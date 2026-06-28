import joblib
import json
import pandas as pd
import numpy as np
from tensorflow.keras.models import Model
from tensorflow.keras.layers import Input, Dense

# ---- Load non-Keras artifacts ----
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

demo_sample = pd.read_csv('model_artifacts/demo_sample.csv')

# ---- Rebuild autoencoder architecture manually, then load weights ----
input_dim = len(feature_columns)  # should be 66

input_layer = Input(shape=(input_dim,))
encoded = Dense(32, activation='relu')(input_layer)
encoded = Dense(16, activation='relu')(encoded)
decoded = Dense(32, activation='relu')(encoded)
decoded = Dense(input_dim, activation='linear')(decoded)
autoencoder = Model(inputs=input_layer, outputs=decoded)

autoencoder.load_weights('model_artifacts/autoencoder.weights.h5')

print("All artifacts loaded successfully!")
print("Number of features:", len(feature_columns))
print("Demo sample shape:", demo_sample.shape)
print("Classes:", le.classes_)
print("Threshold:", best_threshold)

# ---- Quick test prediction ----
test_row = demo_sample.iloc[0][feature_columns]
test_df = pd.DataFrame([test_row])
pred = xgb_model.predict(test_df)
pred_label = le.inverse_transform(pred)
print("\nTest prediction:", pred_label[0])
print("True label was:", demo_sample.iloc[0]['True_Label'])

# ---- Quick test of autoencoder reconstruction ----
test_scaled = scaler.transform(test_df)
reconstructed = autoencoder.predict(test_scaled, verbose=0)
error = np.mean(np.square(test_scaled - reconstructed))
print("\nAutoencoder reconstruction error:", error)
print("Anomaly threshold:", best_threshold)
print("Flagged as anomalous:", error > best_threshold)