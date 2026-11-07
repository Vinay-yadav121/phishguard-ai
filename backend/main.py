import sqlite3
from datetime import datetime
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from pathlib import Path
from urllib.parse import urlparse
import joblib
import re

app = FastAPI(
    title="PhishGuard AI",
    version="2.0",
    description="ML-powered phishing URL detection"
)

# Frontend connection
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "https://phishguard-ai-roan.vercel.app",
        "https://phishguard-ai-roan.vercel.app",
        "http://localhost:5173"
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# Load trained ML model
MODEL_PATH = Path(__file__).parent / "phishing_model.pkl"
model = joblib.load(MODEL_PATH)


class URLRequest(BaseModel):
    url: str = Field(min_length=1, max_length=2048)


def get_phishing_class():
    classes = model.classes_

    for label in classes:
        name = str(label).lower()

        if any(word in name for word in [
            "phishing", "malicious", "unsafe", "bad"
        ]):
            return label

    # Numeric labels: 1 represents phishing
    if 1 in classes:
        return 1

    raise RuntimeError(
        f"Cannot identify phishing class: {classes}"
    )


PHISHING_CLASS = get_phishing_class()
# SQLite database
DB_PATH = Path(__file__).parent / "phishguard.db"


def init_db():
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                url TEXT NOT NULL,
                result TEXT NOT NULL,
                risk_score REAL NOT NULL,
                confidence REAL NOT NULL,
                scanned_at TEXT NOT NULL
            )
        """)


init_db()


@app.get("/")
def home():
    return {
        "message": "PhishGuard AI Backend Running",
        "status": "success",
        "ml_model": "loaded"
    }


@app.get("/health")
def health():
    return {
        "status": "healthy",
        "model_loaded": model is not None
    }


@app.post("/analyze")
def analyze_url(request: URLRequest):
    url = request.url.strip()

    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    parsed = urlparse(url)

    if not parsed.hostname:
        raise HTTPException(
            status_code=400,
            detail="Please enter a valid URL"
        )

    # ML prediction
    prediction = model.predict([url])[0]
    probabilities = model.predict_proba([url])[0]

    classes = list(model.classes_)
    phishing_index = classes.index(PHISHING_CLASS)

    phishing_probability = float(
        probabilities[phishing_index]
    )

    risk_score = round(phishing_probability * 100, 2)

    # URL security indicators
    hostname = parsed.hostname.lower()
    reasons = []

    if parsed.scheme != "https":
        reasons.append("URL does not use HTTPS")

    # Detect IPv4 address
    if re.match(
        r"^\d{1,3}(?:\.\d{1,3}){3}$",
        hostname
    ):
        reasons.append("Website uses an IP address")

    if "@" in url:
        reasons.append("URL contains @ symbol")

    if len(url) > 75:
        reasons.append("URL is unusually long")

    if hostname.count(".") >= 3:
        reasons.append("URL contains multiple subdomains")

    suspicious_words = [
        "login", "verify", "update", "secure",
        "account", "password", "bank", "free",
        "confirm", "signin"
    ]

    for word in suspicious_words:
        if word in hostname:
            reasons.append(f"Suspicious keyword: {word}")

    # Final classification based on ML probability
    if risk_score >= 70:
        result = "Phishing"
    elif risk_score >= 40:
        result = "Suspicious"
    else:
        result = "Likely Safe"

        
    # Save scan to SQLite database
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute(
            """
            INSERT INTO scans
            (url, result, risk_score, confidence, scanned_at)
            VALUES (?, ?, ?, ?, ?)
            """,
            (
                url,
                result,
                risk_score,
                round(max(probabilities) * 100, 2),
                datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            )
        )


    return {
        "url": url,
        "result": result,
        "risk_score": risk_score,
        "confidence": round(
            max(probabilities) * 100, 2
        ),
        "ml_prediction": str(prediction),
        "detection_method": "TF-IDF + Logistic Regression",
        "reasons": reasons,
        "status": "success"
    }

@app.get("/history")
def get_history():
    with sqlite3.connect(DB_PATH) as conn:
        conn.row_factory = sqlite3.Row
        rows = conn.execute(
            "SELECT * FROM scans ORDER BY id DESC LIMIT 100"
        ).fetchall()

    return [dict(row) for row in rows]


@app.delete("/history")
def clear_history():
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute("DELETE FROM scans")

    return {"message": "Scan history cleared"}
