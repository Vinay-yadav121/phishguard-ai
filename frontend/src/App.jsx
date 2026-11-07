
import { useState } from "react";
import "./App.css";

function App() {
  const [url, setUrl] = useState("");
  const [result, setResult] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");

  async function scanURL(e) {
    e.preventDefault();

    if (!url.trim()) {
      setError("Please enter a URL");
      return;
    }

    setLoading(true);
    setError("");
    setResult(null);

    try {
      const response = await fetch("http://127.0.0.1:8000/analyze", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({ url }),
      });

      const data = await response.json();

      if (!response.ok) {
        throw new Error(data.detail || "Scanning failed");
      }

      setResult(data);
    } catch (err) {
      setError(
        "Backend connection failed. Make sure FastAPI is running on port 8000."
      );
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="app">
      <nav className="navbar">
        <h2>🛡️ PhishGuard AI</h2>
        <span className="status">● AI Protection Active</span>
      </nav>

      <main className="container">
        <section className="hero">
          <span className="tag">AI-POWERED CYBERSECURITY</span>
          <h1>
            Detect phishing.
            <br />
            <span>Browse safely.</span>
          </h1>
          <p>
            Analyze suspicious URLs using machine learning
            and identify potential phishing threats.
          </p>
        </section>

        <section className="scanner">
          <h2>🔍 URL Security Scanner</h2>
          <p>Enter a website URL to analyze its security risk.</p>

          <form onSubmit={scanURL}>
            <input
              type="text"
              placeholder="https://example.com"
              value={url}
              onChange={(e) => setUrl(e.target.value)}
            />
            <button type="submit" disabled={loading}>
              {loading ? "Scanning..." : "Scan URL"}
            </button>
          </form>

          {error && <p className="error">{error}</p>}

          {result && (
            <div className="result">
              <h2>{result.result}</h2>

              <div className="risk">
                <span>Risk Score</span>
                <strong>{result.risk_score}%</strong>
              </div>

              <p>
                <strong>Confidence:</strong> {result.confidence}%
              </p>

              <p>
                <strong>Detection:</strong> {result.detection_method}
              </p>

              <p>
                <strong>URL:</strong> {result.url}
              </p>

              <h3>Detection Indicators</h3>

              {result.reasons.length === 0 ? (
                <p>No suspicious URL indicators detected.</p>
              ) : (
                <ul>
                  {result.reasons.map((reason, index) => (
                    <li key={index}>⚠️ {reason}</li>
                  ))}
                </ul>
              )}
            </div>
          )}
        </section>

        <section className="features">
          <div className="feature">
            <h3>🤖 ML Detection</h3>
            <p>TF-IDF and Logistic Regression classification.</p>
          </div>

          <div className="feature">
            <h3>📊 Risk Analysis</h3>
            <p>Risk score and confidence-based analysis.</p>
          </div>

          <div className="feature">
            <h3>🔐 Security Awareness</h3>
            <p>Identify suspicious URLs before opening them.</p>
          </div>
        </section>

        <footer>
          PhishGuard AI | AI-Powered Phishing Detection Platform
        </footer>
      </main>
    </div>
  );
}

export default App;
