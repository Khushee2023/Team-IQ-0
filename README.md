# Team IQ-0: AI-Powered Cyberattack Detection and SOC Decision Support

Team IQ-0 is a cybersecurity machine learning project focused on detecting, analyzing, and prioritizing network-based cyberattacks. The repository combines multiple ML/DL experiments with a FastAPI-based dashboard and an agentic decision-support pipeline for security alert investigation.

The project does not stop at simple attack classification. It also includes anomaly detection, brute-force behavioral fingerprinting, severity scoring, analyst review support, and recommended SOC-style response actions.

## Project Objective

The objective of this project is to build an intelligent cyberattack detection system that can:

- Classify network traffic into attack categories
- Detect anomalous network behavior
- Identify behavioral patterns in brute-force attacks
- Assign severity levels to alerts
- Recommend SOC-style response actions
- Present results through a web dashboard/API
- Compare multiple machine learning and deep learning approaches

## Repository Contents

```text
Team-IQ-0/
|
|-- model_artifacts/
|   |-- autoencoder.h5
|   |-- autoencoder.keras
|   |-- autoencoder.weights.h5
|   |-- autoencoder_architecture.json
|   |-- clip_caps.json
|   |-- demo_sample.csv
|   |-- feature_columns.json
|   |-- kmeans2.pkl
|   |-- label_encoder.pkl
|   |-- scaler.pkl
|   |-- scaler_timing2.pkl
|   |-- threshold.json
|   `-- xgb_model.pkl
|
|-- static/
|   |-- index.html
|   |-- script.js
|   `-- style.css
|
|-- PCA+MLP.ipynb
|-- Sole MLP.ipynb
|-- lstm_experiment.ipynb
|-- mlp-lstm.ipynb
|-- tcn_experiment.ipynb
|
|-- agent_logic.py
|-- main.py
|-- test_load.py
`-- README.md
```

## Models and Experiments

This repository contains several model experiments for cyberattack detection.

| File | Model / Component | Purpose |
|---|---|---|
| `Sole MLP.ipynb` | MLP | Baseline neural network classifier for attack detection |
| `PCA+MLP.ipynb` | PCA + MLP | Dimensionality reduction followed by MLP classification |
| `lstm_experiment.ipynb` | LSTM | Sequential deep learning model for ordered traffic behavior |
| `mlp-lstm.ipynb` | MLP + LSTM | Hybrid model combining dense and sequential learning |
| `tcn_experiment.ipynb` | TCN | Temporal Convolutional Network for sequence-based classification |
| `agent_logic.py` | Agentic security pipeline | Classification, anomaly detection, fingerprinting, severity scoring, and action recommendation |
| `main.py` | FastAPI app | Backend API and dashboard server |
| `test_load.py` | Artifact validation | Tests whether saved models and preprocessing files load correctly |

## Final Application Pipeline

The deployed application uses saved model artifacts from `model_artifacts/` and processes demo network flows through an agentic pipeline.

The pipeline performs the following steps:

1. Attack Classification

   The system uses the trained classifier artifact `xgb_model.pkl` and converts encoded outputs back to readable class labels using `label_encoder.pkl`.

2. Anomaly Detection

   The system rebuilds an autoencoder architecture, loads trained weights from `autoencoder.weights.h5`, calculates reconstruction error, and compares the error against `threshold.json`.

3. Behavioral Fingerprinting

   For brute-force traffic, timing-based features are analyzed using `scaler_timing2.pkl` and `kmeans2.pkl`. This helps group brute-force behavior into patterns such as regular automated activity or more irregular behavior.

4. Severity Scoring

   The system combines predicted class, confidence, anomaly status, and behavioral fingerprinting to assign a severity level such as High, Medium, Low, or None.

5. Recommended Action

   The application generates SOC-style response guidance, such as blocking a source, alerting an analyst, monitoring traffic, or taking no action for normal traffic.

## Attack Classes

The system is designed around multi-class cyberattack detection. The supported classes include:

```text
Brute_Force
HTTP_DDoS
ICMP_Flood
Normal
Port_Scan
Web_Crwling
```

## API Endpoints

The FastAPI application provides the following endpoints:

| Endpoint | Method | Description |
|---|---|---|
| `/api/summary` | GET | Returns total flows, detected attacks, severity counts, accuracy, attack breakdown, and pending review count |
| `/api/fingerprint-summary` | GET | Summarizes behavioral fingerprinting results for brute-force attacks |
| `/api/alerts` | GET | Returns detected attack alerts sorted by severity |
| `/api/alert/{alert_id}/decide` | POST | Stores analyst decision for a specific alert |
| `/` | GET | Serves the static dashboard from the `static/` folder |

## Dashboard

The `static/` folder contains the frontend dashboard files:

- `index.html`
- `script.js`
- `style.css`

The dashboard is served directly by FastAPI and displays cyberattack detection results, severity levels, analyst review information, and alert details.

## Model Artifacts

The `model_artifacts/` directory stores trained models and preprocessing objects required by the application.

| Artifact | Purpose |
|---|---|
| `xgb_model.pkl` | Main attack classification model |
| `label_encoder.pkl` | Converts encoded model outputs back to class labels |
| `scaler.pkl` | Feature scaler for autoencoder input |
| `scaler_timing2.pkl` | Scaler for timing features used in brute-force fingerprinting |
| `kmeans2.pkl` | KMeans model for brute-force behavioral clustering |
| `autoencoder.weights.h5` | Trained autoencoder weights |
| `threshold.json` | Reconstruction-error threshold for anomaly detection |
| `feature_columns.json` | Ordered list of model input features |
| `clip_caps.json` | Feature clipping values for timing-based analysis |
| `demo_sample.csv` | Sample flows used by the application demo |

## How to Run the Project

### 1. Clone the repository

```bash
git clone https://github.com/Khushee2023/Team-IQ-0.git
cd Team-IQ-0
```

### 2. Create a virtual environment

```bash
python -m venv .venv
```

On Windows:

```bash
.venv\Scripts\activate
```

On macOS/Linux:

```bash
source .venv/bin/activate
```

### 3. Install dependencies

```bash
pip install pandas numpy scikit-learn tensorflow joblib fastapi uvicorn pydantic langgraph xgboost
```

If you also want to run the notebooks:

```bash
pip install notebook jupyter matplotlib seaborn
```

### 4. Test model artifact loading

Before running the dashboard, verify that all saved models and preprocessing files load correctly:

```bash
python test_load.py
```

Expected result:

```text
All artifacts loaded successfully!
```

### 5. Run the FastAPI application

```bash
uvicorn main:app --reload
```

Then open:

```text
http://127.0.0.1:8000
```

## Running the Notebooks

The notebooks can be opened using Jupyter:

```bash
jupyter notebook
```

Then run any of the following:

```text
Sole MLP.ipynb
PCA+MLP.ipynb
lstm_experiment.ipynb
mlp-lstm.ipynb
tcn_experiment.ipynb
```

## Evaluation Metrics

The project compares models using classification and security-relevant metrics such as:

- Accuracy
- Precision
- Recall
- F1-score
- Macro F1-score
- Weighted F1-score
- Confusion matrix
- ROC-AUC where applicable
- Inference behavior and alert quality

Because cyberattack datasets are often imbalanced, macro F1 and class-wise recall are important alongside accuracy.

## Key Features

- Multi-class cyberattack classification
- Saved model artifact loading
- Autoencoder-based anomaly detection
- Brute-force behavioral fingerprinting
- Agentic decision pipeline using LangGraph
- Severity scoring for SOC prioritization
- Recommended response actions
- FastAPI backend
- Static web dashboard
- Notebook-based model experimentation

## Team

**Team Name:** Team IQ-0

This project was developed as a cybersecurity machine learning and deep learning project for network attack detection, alert prioritization, and SOC-style decision support.

## License

This project is licensed under the MIT License. See the `LICENSE` file for details.
