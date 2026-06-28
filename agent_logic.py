# agent_logic.py
import joblib
import json
import pandas as pd
import numpy as np
from tensorflow.keras.models import Model
from tensorflow.keras.layers import Input, Dense
from langgraph.graph import StateGraph, END
from typing import TypedDict, Optional, List

# ---- Load all artifacts ----
xgb_model = joblib.load('model_artifacts/xgb_model.pkl')
le = joblib.load('model_artifacts/label_encoder.pkl')
scaler = joblib.load('model_artifacts/scaler.pkl')
scaler_timing2 = joblib.load('model_artifacts/scaler_timing2.pkl')
kmeans2 = joblib.load('model_artifacts/kmeans2.pkl')

with open('model_artifacts/threshold.json') as f:
    best_threshold = json.load(f)['best_threshold']

with open('model_artifacts/clip_caps.json') as f:
    caps = json.load(f)
    cap_flow = caps['cap_flow']
    cap_fwd = caps['cap_fwd']
    cap_bwd = caps['cap_bwd']

with open('model_artifacts/feature_columns.json') as f:
    feature_columns = json.load(f)['columns']

# Rebuild autoencoder
input_dim = len(feature_columns)
input_layer = Input(shape=(input_dim,))
encoded = Dense(32, activation='relu')(input_layer)
encoded = Dense(16, activation='relu')(encoded)
decoded = Dense(32, activation='relu')(encoded)
decoded = Dense(input_dim, activation='linear')(decoded)
autoencoder = Model(inputs=input_layer, outputs=decoded)
autoencoder.load_weights('model_artifacts/autoencoder.weights.h5')


# ---- State schema ----
class SecurityState(TypedDict):
    flow_features: dict
    predicted_class: Optional[str]
    confidence: Optional[float]
    anomaly_score: Optional[float]
    is_anomalous: Optional[bool]
    behavior_cluster: Optional[str]
    severity: Optional[str]
    action: Optional[str]
    reasoning_trace: List[str]


# ---- Nodes ----
def classify_node(state: SecurityState) -> SecurityState:
    flow_df = pd.DataFrame([state['flow_features']])[feature_columns]
    pred_proba = xgb_model.predict_proba(flow_df)[0]
    pred_class_idx = np.argmax(pred_proba)
    confidence = pred_proba[pred_class_idx]
    pred_class = le.inverse_transform([pred_class_idx])[0]

    state['predicted_class'] = pred_class
    state['confidence'] = float(confidence)
    state['reasoning_trace'].append(
        f"Classified as '{pred_class}' with confidence {confidence:.3f}"
    )
    return state


def anomaly_node(state: SecurityState) -> SecurityState:
    flow_df = pd.DataFrame([state['flow_features']])[feature_columns]
    flow_scaled = scaler.transform(flow_df)
    reconstructed = autoencoder.predict(flow_scaled, verbose=0)
    error = np.mean(np.square(flow_scaled - reconstructed))
    is_anomalous = error > best_threshold

    state['anomaly_score'] = float(error)
    state['is_anomalous'] = bool(is_anomalous)
    state['reasoning_trace'].append(
        f"Anomaly score: {error:.5f} (threshold: {best_threshold:.5f}) — "
        f"{'ANOMALOUS' if is_anomalous else 'within normal range'}"
    )
    return state


def fingerprint_node(state: SecurityState) -> SecurityState:
    if state['predicted_class'] != 'Brute_Force':
        state['behavior_cluster'] = 'N/A'
        state['reasoning_trace'].append(
            "Behavioral fingerprinting skipped (only applicable to Brute_Force)"
        )
        return state

    flow_df = pd.DataFrame([state['flow_features']])
    timing_vals = flow_df[['Flow IAT Std', 'Fwd IAT Std', 'Bwd IAT Std']].copy()
    timing_vals['Flow IAT Std'] = timing_vals['Flow IAT Std'].clip(upper=cap_flow)
    timing_vals['Fwd IAT Std'] = timing_vals['Fwd IAT Std'].clip(upper=cap_fwd)
    timing_vals['Bwd IAT Std'] = timing_vals['Bwd IAT Std'].clip(upper=cap_bwd)

    timing_scaled_single = scaler_timing2.transform(timing_vals)
    cluster = kmeans2.predict(timing_scaled_single)[0]
    cluster_label = (
        "Automated/Scripted (regular timing)" if cluster == 1
        else "Irregular/Possibly Coordinated"
    )

    state['behavior_cluster'] = cluster_label
    state['reasoning_trace'].append(f"Behavioral fingerprint: {cluster_label}")
    return state


def severity_node(state: SecurityState) -> SecurityState:
    criticality_map = {
        'Brute_Force': 0.6, 'Port_Scan': 0.4, 'HTTP_DDoS': 0.9,
        'ICMP_Flood': 0.85, 'Web_Crwling': 0.3, 'Normal': 0.0
    }
    base_criticality = criticality_map.get(state['predicted_class'], 0.5)
    confidence_factor = state['confidence']
    anomaly_boost = 0.15 if state['is_anomalous'] else 0
    coordination_boost = 0.2 if state.get('behavior_cluster') == 'Irregular/Possibly Coordinated' else 0

    severity_score = min(1.0, base_criticality * confidence_factor + anomaly_boost + coordination_boost)

    if state['predicted_class'] == 'Normal':
        severity_label = "None"
    elif severity_score >= 0.7:
        severity_label = "High"
    elif severity_score >= 0.4:
        severity_label = "Medium"
    else:
        severity_label = "Low"

    state['severity'] = severity_label
    state['reasoning_trace'].append(
        f"Severity score: {severity_score:.3f} → {severity_label} "
        f"(base={base_criticality}, confidence={confidence_factor:.2f}, "
        f"anomaly_boost={anomaly_boost}, coordination_boost={coordination_boost})"
    )
    return state


def action_node(state: SecurityState) -> SecurityState:
    action_map = {
        "High": "BLOCK source + Alert SOC analyst immediately",
        "Medium": "Alert SOC analyst for review",
        "Low": "Log only, monitor for repeated patterns",
        "None": "No action — traffic classified as normal"
    }
    action = action_map.get(state['severity'], "Flag for manual review")
    state['action'] = action
    state['reasoning_trace'].append(f"Recommended action: {action}")
    return state


def route_after_classify(state: SecurityState) -> str:
    if state['confidence'] < 0.7:
        state['reasoning_trace'].append("Low confidence — routing to deeper investigation path")
    return "anomaly_check"


# ---- Build graph ----
def build_agent_graph():
    workflow = StateGraph(SecurityState)
    workflow.add_node("classify", classify_node)
    workflow.add_node("anomaly_check", anomaly_node)
    workflow.add_node("fingerprint", fingerprint_node)
    workflow.add_node("severity_scoring", severity_node)
    workflow.add_node("action", action_node)

    workflow.set_entry_point("classify")
    workflow.add_conditional_edges(
        "classify", route_after_classify, {"anomaly_check": "anomaly_check"}
    )
    workflow.add_edge("anomaly_check", "fingerprint")
    workflow.add_edge("fingerprint", "severity_scoring")
    workflow.add_edge("severity_scoring", "action")
    workflow.add_edge("action", END)

    return workflow.compile()


agent_app = build_agent_graph()


def run_agent_on_flow(flow_dict: dict) -> dict:
    """Main entry point - call this from the Streamlit app"""
    initial_state = {
        'flow_features': flow_dict,
        'predicted_class': None,
        'confidence': None,
        'anomaly_score': None,
        'is_anomalous': None,
        'behavior_cluster': None,
        'severity': None,
        'action': None,
        'reasoning_trace': []
    }
    return agent_app.invoke(initial_state)

# ---- Global feature importance (fast proxy for explanation, no per-request SHAP) ----
def get_top_features_for_class(class_name, top_n=4):
    importances = xgb_model.feature_importances_
    pairs = list(zip(feature_columns, importances))
    pairs.sort(key=lambda x: x[1], reverse=True)
    return [f[0] for f in pairs[:top_n]]

GLOBAL_TOP_FEATURES = {cls: get_top_features_for_class(cls) for cls in le.classes_}