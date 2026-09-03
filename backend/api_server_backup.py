from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
import pandas as pd

app = FastAPI(
    title="VulnPrioritizer API"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

DATA_PATH = "data/processed_nvd_data.csv"


@app.get("/")
def root():
    return {
        "status": "online"
    }


@app.get("/dashboard")
def dashboard():
    df = pd.read_csv(DATA_PATH)

    total = len(df)

    high = int(
        (df["priority"] == "High").sum()
    )

    medium = int(
        (df["priority"] == "Medium").sum()
    )

    low = int(
        (df["priority"] == "Low").sum()
    )

    risk_scores = (
        df["priority_score"]
        .clip(lower=0, upper=10)
        * 10
    )

    average_risk = round(
        risk_scores.mean()
    )

    return {
        "total_vulnerabilities": total,
        "high_priority": high,
        "medium_priority": medium,
        "low_priority": low,
        "average_risk": average_risk,
    }


@app.get("/vulnerabilities")
def vulnerabilities():
    df = pd.read_csv(DATA_PATH)

    results = []

    for _, row in df.iterrows():
        risk_score = min(
            int(row["priority_score"] * 10),
            100
        )

        results.append(
            {
                "cveId": str(row["cve_id"]),
                "description": str(row["description"]),
                "cvss": float(row["cvss_score"]),
                "severity": str(row["severity"]),
                "priority": str(row["priority"]),
                "riskScore": risk_score,

                # Temporary until model probability is integrated
                "confidence": None,

                "attackVector": str(
                    row["attack_vector"]
                ),
                "attackComplexity": str(
                    row["attack_complexity"]
                ),
                "privilegesRequired": str(
                    row["privileges_required"]
                ),
                "userInteraction": str(
                    row["user_interaction"]
                ),
                "referenceCount": int(
                    row["reference_count"]
                ),
                "weaknessCount": int(
                    row["weakness_count"]
                ),
                "hasCisaKev": bool(
                    row["has_cisa_kev"]
                ),
                "published": str(
                    row["published_date"]
                )[:10],
            }
        )

    return results