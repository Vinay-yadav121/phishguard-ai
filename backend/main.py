
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from urllib.parse import urlparse
import re

app = FastAPI(title="PhishGuard AI", version="1.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


class URLRequest(BaseModel):
    url: str


@app.get("/")
def home():
    return {
        "message": "PhishGuard AI Backend Running",
        "status": "success"
    }


@app.post("/analyze")
def analyze_url(request: URLRequest):
    url = request.url.strip()

    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    parsed = urlparse(url)
    hostname = parsed.hostname or ""
    score = 0
    reasons = []

    # Check HTTPS
    if parsed.scheme != "https":
        score += 20
        reasons.append("URL does not use HTTPS")

    # Check IP address instead of domain
    if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", hostname):
        score += 25
        reasons.append("Website uses an IP address")

    # Check suspicious symbols
    if "@" in url:
        score += 25
        reasons.append("URL contains @ symbol")

    # Check unusually long URL
    if len(url) > 75:
        score += 15
        reasons.append("URL is unusually long")

    # Check excessive subdomains
    if hostname.count(".") >= 3:
        score += 15
        reasons.append("URL contains multiple subdomains")

    # Check suspicious keywords
    suspicious_words = [
        "login", "verify", "update", "secure",
        "account", "password", "bank", "free",
        "confirm", "signin"
    ]

    for word in suspicious_words:
        if word in hostname.lower():
            score += 10
            reasons.append(f"Suspicious keyword: {word}")
            break

    score = min(score, 100)

    if score >= 50:
        result = "Phishing"
    elif score >= 25:
        result = "Suspicious"
    else:
        result = "Likely Safe"

    return {
        "url": url,
        "risk_score": score,
        "result": result,
        "reasons": reasons,
        "status": "success"
    }
