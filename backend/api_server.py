from pathlib import Path

import joblib
import pandas as pd

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware


# =========================================================
# FILE PATHS
# =========================================================

# Directory containing this api_server.py file
BASE_DIR = Path(__file__).resolve().parent

DATA_PATH = (
    BASE_DIR
    / "data"
    / "processed_nvd_data.csv"
)

MODEL_PATH = (
    BASE_DIR
    / "models"
    / "vulnprioritizer_model.joblib"
)


# =========================================================
# FASTAPI APPLICATION
# =========================================================

app = FastAPI(
    title="VulnPrioritizer API",
    description=(
        "REST API for Random Forest-based "
        "vulnerability prioritization."
    ),
    version="1.0.0",
)


app.add_middleware(
    CORSMiddleware,

    # React development server
    allow_origins=[
        "http://localhost:5173",
        "http://127.0.0.1:5173",
    ],

    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# =========================================================
# LOAD THE RANDOM FOREST MODEL ONCE
# =========================================================

if not MODEL_PATH.exists():
    raise RuntimeError(
        f"Model file was not found: {MODEL_PATH}"
    )


model = joblib.load(MODEL_PATH)


# =========================================================
# HELPER: LOAD PROCESSED DATA
# =========================================================

def load_processed_data():
    """
    Load the processed NVD dataset.

    A new DataFrame is returned so API operations do
    not modify the original CSV file.
    """

    if not DATA_PATH.exists():
        raise HTTPException(
            status_code=500,
            detail=(
                "processed_nvd_data.csv was not found."
            ),
        )

    try:
        dataframe = pd.read_csv(DATA_PATH)
    except Exception as error:
        raise HTTPException(
            status_code=500,
            detail=f"Could not read dataset: {error}",
        ) from error

    if dataframe.empty:
        raise HTTPException(
            status_code=500,
            detail="The processed dataset is empty.",
        )

    return dataframe


# =========================================================
# HELPER: CREATE MODEL FEATURES
# =========================================================

def create_model_features(dataframe):
    """
    Recreate the same input features used during model
    training.

    The target-related columns are deliberately excluded:
    - priority
    - priority_score

    Including those columns would leak the correct answer
    into the model.
    """

    feature_columns = [
        "cvss_score",
        "reference_count",
        "weakness_count",
        "has_cisa_kev",
        "vulnerability_age_days",
        "description_length",
        "severity",
        "attack_vector",
        "attack_complexity",
        "privileges_required",
        "user_interaction",
    ]

    missing_columns = [
        column
        for column in feature_columns
        if column not in dataframe.columns
    ]

    if missing_columns:
        raise HTTPException(
            status_code=500,
            detail={
                "message": (
                    "Required model features are missing."
                ),
                "missing_columns": missing_columns,
            },
        )

    features = dataframe[
        feature_columns
    ].copy()

    # Ensure numeric values are valid
    numeric_columns = [
        "cvss_score",
        "reference_count",
        "weakness_count",
        "has_cisa_kev",
        "vulnerability_age_days",
        "description_length",
    ]

    for column in numeric_columns:
        features[column] = pd.to_numeric(
            features[column],
            errors="coerce",
        ).fillna(0)

    # Ensure categorical values are valid text
    categorical_columns = [
        "severity",
        "attack_vector",
        "attack_complexity",
        "privileges_required",
        "user_interaction",
    ]

    for column in categorical_columns:
        features[column] = (
            features[column]
            .fillna("UNKNOWN")
            .astype(str)
        )

    # Convert categorical columns into numeric columns
    features = pd.get_dummies(
        features,
        dtype=int,
    )

    # The saved model remembers the exact feature names
    # and order used during training.
    if not hasattr(model, "feature_names_in_"):
        raise HTTPException(
            status_code=500,
            detail=(
                "The saved model does not contain "
                "feature_names_in_. Retrain the model "
                "using a pandas DataFrame."
            ),
        )

    training_columns = list(
        model.feature_names_in_
    )

    # Add training columns absent from the new dataset
    for column in training_columns:
        if column not in features.columns:
            features[column] = 0

    # Remove unexpected columns and restore training order
    features = features[training_columns]

    return features


# =========================================================
# HELPER: GENERATE RANDOM FOREST PREDICTIONS
# =========================================================

def create_predictions(dataframe):
    """
    Run the trained Random Forest model.

    Returns:
    - predicted priority
    - maximum class probability as confidence
    - weighted probability-based risk score
    """

    features = create_model_features(dataframe)

    predicted_priorities = model.predict(
        features
    )

    probability_matrix = model.predict_proba(
        features
    )

    model_classes = list(model.classes_)

    # Low, Medium and High are mapped onto a 0-100
    # prioritization scale.
    class_risk_weights = {
        "Low": 20,
        "Medium": 60,
        "High": 100,
    }

    confidence_scores = []
    risk_scores = []

    for probability_row in probability_matrix:
        # Confidence is the highest predicted-class
        # probability.
        confidence = (
            max(probability_row) * 100
        )

        confidence_scores.append(
            round(float(confidence), 1)
        )

        # Risk score is a weighted combination of all
        # class probabilities.
        risk_score = 0.0

        for class_name, probability in zip(
            model_classes,
            probability_row,
        ):
            class_weight = (
                class_risk_weights.get(
                    str(class_name),
                    0,
                )
            )

            risk_score += (
                float(probability)
                * class_weight
            )

        risk_scores.append(
            round(
                min(
                    max(risk_score, 0),
                    100,
                )
            )
        )

    result = dataframe.copy()

    result["predicted_priority"] = (
        predicted_priorities
    )

    result["model_confidence"] = (
        confidence_scores
    )

    result["ml_risk_score"] = risk_scores

    return result


# =========================================================
# HELPER: CONVERT ONE ROW TO FRONTEND JSON
# =========================================================

def row_to_vulnerability(row):
    """
    Convert a pandas row into the field names expected
    by the React frontend.
    """

    published_date = str(
        row.get("published_date", "")
    )

    return {
        "cveId": str(
            row.get("cve_id", "Unknown")
        ),

        "description": str(
            row.get(
                "description",
                "No description is available.",
            )
        ),

        "cvss": float(
            row.get("cvss_score", 0)
        ),

        "severity": str(
            row.get("severity", "UNKNOWN")
        ),

        # Live model output
        "priority": str(
            row.get(
                "predicted_priority",
                "Unknown",
            )
        ),

        # Live probability-based risk score
        "riskScore": int(
            row.get("ml_risk_score", 0)
        ),

        # Live highest class probability
        "confidence": float(
            row.get("model_confidence", 0)
        ),

        "attackVector": str(
            row.get(
                "attack_vector",
                "UNKNOWN",
            )
        ),

        "attackComplexity": str(
            row.get(
                "attack_complexity",
                "UNKNOWN",
            )
        ),

        "privilegesRequired": str(
            row.get(
                "privileges_required",
                "UNKNOWN",
            )
        ),

        "userInteraction": str(
            row.get(
                "user_interaction",
                "UNKNOWN",
            )
        ),

        "referenceCount": int(
            row.get("reference_count", 0)
        ),

        "weaknessCount": int(
            row.get("weakness_count", 0)
        ),

        "hasCisaKev": bool(
            row.get("has_cisa_kev", 0)
        ),

        "published": (
            published_date[:10]
            if published_date
            else "Unknown"
        ),
    }


# =========================================================
# ROOT ENDPOINT
# =========================================================

@app.get("/")
def root():
    return {
        "application": "VulnPrioritizer",
        "status": "online",
        "model": "Random Forest Classifier",
        "model_loaded": True,
    }


# =========================================================
# HEALTH ENDPOINT
# =========================================================

@app.get("/health")
def health():
    return {
        "status": "healthy",
        "dataset_exists": DATA_PATH.exists(),
        "model_exists": MODEL_PATH.exists(),
        "model_classes": [
            str(class_name)
            for class_name in model.classes_
        ],
    }


# =========================================================
# DASHBOARD ENDPOINT
# =========================================================

@app.get("/dashboard")
def dashboard():
    dataframe = load_processed_data()

    prediction_data = create_predictions(
        dataframe
    )

    predictions = prediction_data[
        "predicted_priority"
    ]

    total = len(prediction_data)

    high = int(
        (predictions == "High").sum()
    )

    medium = int(
        (predictions == "Medium").sum()
    )

    low = int(
        (predictions == "Low").sum()
    )

    average_risk = round(
        prediction_data[
            "ml_risk_score"
        ].mean()
    )

    average_confidence = round(
        prediction_data[
            "model_confidence"
        ].mean(),
        1,
    )

    return {
        "total_vulnerabilities": total,
        "high_priority": high,
        "medium_priority": medium,
        "low_priority": low,
        "average_risk": average_risk,
        "average_confidence": (
            average_confidence
        ),
        "model": (
            "Random Forest Classifier"
        ),
    }


# =========================================================
# ALL VULNERABILITIES ENDPOINT
# =========================================================

@app.get("/vulnerabilities")
def vulnerabilities():
    dataframe = load_processed_data()

    prediction_data = create_predictions(
        dataframe
    )

    # Highest-risk records appear first.
    prediction_data = (
        prediction_data
        .sort_values(
            by=[
                "ml_risk_score",
                "cvss_score",
            ],
            ascending=False,
        )
        .reset_index(drop=True)
    )

    return [
        row_to_vulnerability(row)
        for _, row in prediction_data.iterrows()
    ]


# =========================================================
# SINGLE VULNERABILITY ENDPOINT
# =========================================================

@app.get(
    "/vulnerabilities/{cve_id}"
)
def vulnerability_details(cve_id: str):
    dataframe = load_processed_data()

    matching_rows = dataframe[
        dataframe["cve_id"]
        .astype(str)
        .str.upper()
        == cve_id.upper()
    ]

    if matching_rows.empty:
        raise HTTPException(
            status_code=404,
            detail=(
                f"Vulnerability {cve_id} "
                "was not found."
            ),
        )

    prediction_data = create_predictions(
        matching_rows.copy()
    )

    row = prediction_data.iloc[0]

    return row_to_vulnerability(row)


# =========================================================
# MODEL INFORMATION ENDPOINT
# =========================================================

@app.get("/model-info")
def model_info():
    feature_names = [
        str(feature)
        for feature in model.feature_names_in_
    ]

    feature_importances = [
        float(value)
        for value in model.feature_importances_
    ]

    importance_rows = [
        {
            "feature": feature,
            "importance": round(
                importance,
                6,
            ),
        }
        for feature, importance in zip(
            feature_names,
            feature_importances,
        )
    ]

    importance_rows.sort(
        key=lambda item:
            item["importance"],
        reverse=True,
    )

    return {
        "algorithm": (
            "Random Forest Classifier"
        ),

        "model_classes": [
            str(class_name)
            for class_name in model.classes_
        ],

        "number_of_trees": len(
            model.estimators_
        ),

        "number_of_features": len(
            feature_names
        ),

        "feature_importance": (
            importance_rows
        ),
    }