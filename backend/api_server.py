from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

app = FastAPI(
    title="VulnPrioritizer API"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/")
def root():
    return {
        "message": "VulnPrioritizer API Running"
    }


@app.get("/dashboard")
def dashboard():

    return {
        "total_vulnerabilities": 1000,
        "high_priority": 80,
        "medium_priority": 413,
        "low_priority": 525,
        "average_risk": 62
    }