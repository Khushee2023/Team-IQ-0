# main.py
from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import pandas as pd
from agent_logic import run_agent_on_flow, GLOBAL_TOP_FEATURES

app = FastAPI(title="Cyberattack Detection API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

demo_df = pd.read_csv('model_artifacts/demo_sample.csv')
_results_cache = None
analyst_decisions = {}  # alert_id -> decision string


def process_all_flows():
    global _results_cache
    if _results_cache is not None:
        return _results_cache

    results = []
    for idx, row in demo_df.iterrows():
        flow_dict = row.to_dict()
        true_label = flow_dict.pop('True_Label')
        result = run_agent_on_flow(flow_dict)
        results.append({
            'id': int(idx),
            'true_label': true_label,
            'predicted_class': result['predicted_class'],
            'confidence': round(result['confidence'], 4),
            'is_anomalous': result['is_anomalous'],
            'anomaly_score': round(result['anomaly_score'], 5),
            'behavior_cluster': result['behavior_cluster'],
            'severity': result['severity'],
            'action': result['action'],
            'reasoning_trace': result['reasoning_trace'],
            'top_features': GLOBAL_TOP_FEATURES.get(result['predicted_class'], []),
            'analyst_decision': None
        })
    _results_cache = results
    return results


@app.get("/api/summary")
def get_summary():
    results = process_all_flows()
    total = len(results)
    attacks = sum(1 for r in results if r['predicted_class'] != 'Normal')
    high = sum(1 for r in results if r['severity'] == 'High')
    medium = sum(1 for r in results if r['severity'] == 'Medium')
    low = sum(1 for r in results if r['severity'] == 'Low')
    correct = sum(1 for r in results if r['predicted_class'] == r['true_label'])
    accuracy = round((correct / total) * 100, 2) if total else 0

    breakdown = {}
    for r in results:
        if r['predicted_class'] != 'Normal':
            breakdown[r['predicted_class']] = breakdown.get(r['predicted_class'], 0) + 1

    pending_review = sum(1 for r in results if r['confidence'] < 0.7 and r['predicted_class'] != 'Normal')

    return {
        "total_flows": total,
        "attacks_detected": attacks,
        "high_severity": high,
        "medium_severity": medium,
        "low_severity": low,
        "accuracy": accuracy,
        "attack_breakdown": breakdown,
        "pending_review": pending_review
    }


@app.get("/api/fingerprint-summary")
def fingerprint_summary():
    results = process_all_flows()
    bf = [r for r in results if r['predicted_class'] == 'Brute_Force']
    automated = sum(1 for r in bf if 'Automated' in r['behavior_cluster'])
    coordinated = sum(1 for r in bf if 'Irregular' in r['behavior_cluster'])
    return {
        "total_brute_force": len(bf),
        "automated": automated,
        "coordinated": coordinated,
        "automated_pct": round((automated / len(bf)) * 100, 1) if bf else 0,
        "coordinated_pct": round((coordinated / len(bf)) * 100, 1) if bf else 0
    }


@app.get("/api/alerts")
def get_alerts():
    results = process_all_flows()
    severity_order = {"High": 0, "Medium": 1, "Low": 2, "None": 3}
    alerts = [r for r in results if r['predicted_class'] != 'Normal']
    alerts.sort(key=lambda x: severity_order.get(x['severity'], 4))
    # attach any analyst decisions made
    for a in alerts:
        a['analyst_decision'] = analyst_decisions.get(a['id'])
    return alerts


class Decision(BaseModel):
    decision: str


@app.post("/api/alert/{alert_id}/decide")
def submit_decision(alert_id: int, body: Decision):
    analyst_decisions[alert_id] = body.decision
    return {"status": "ok", "alert_id": alert_id, "decision": body.decision}


app.mount("/", StaticFiles(directory="static", html=True), name="static")