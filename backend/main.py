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
        "http://localhost:5173",
        "http://127.0.0.1:5173"
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
    """Find the class representing phishing."""
    classes = model.classes_

    for label in classes:
        name = str(label).lower()

        if any(word in name for word in [
            "phishing", "malicious", "unsafe", "bad"
        ]):
            return label

    # For binary numeric labels, conventionally 1 = phishing
    if 1 in classes:
        return 1

    # If labels are safe/legitimate and phishing is not identifiable,
    # the model cannot safely determine the phishing class.
    raise RuntimeError(
        f"Cannot identify phishing class from labels: {classes}"
    )


PHISHING_CLASS = get_phishing_class()


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

    if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", hostname):
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
