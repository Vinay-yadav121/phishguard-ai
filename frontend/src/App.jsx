
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

      if (!response.ok) {
        throw new Error("Backend request failed");
      }

      const data = await response.json();
      setResult(data);
    } catch (err) {
      setError("Unable to connect to backend. Check if FastAPI is running.");
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="app">
      <nav className="navbar">
        <div className="brand">
          <span className="brand-icon">🛡️</span>
          PhishGuard <span className="ai">AI</span>
        </div>
        <span className="nav-status">● System Online</span>
      </nav>

      <main className="main">
        <div className="hero">
          <div className="tag">AI-POWERED CYBERSECURITY</div>
          <h1>
            Detect Phishing.
            <br />
            <span>Stay Protected.</span>
          </h1>
          <p>
            Analyze suspicious URLs with PhishGuard AI and identify
            potential phishing threats before they reach you.
          </p>
        </div>

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
              {loading ? "Scanning..." : "Scan URL →"}
            </button>
          </form>

          {error && <div className="error">{error}</div>}

          {result && (
            <div className="result">
              <h3>Scan Results</h3>
              <div className="result-url">{result.url}</div>

              <div className="score">
                <span>{result.risk_score}</span>
                <small>/100 Risk Score</small>
              </div>

              <div
                className={`status ${
                  result.result === "Phishing"
                    ? "danger"
                    : result.result === "Suspicious"
                    ? "warning"
                    : "safe"
                }`}
              >
                {result.result === "Phishing"
                  ? "🚨 Phishing Detected"
                  : result.result === "Suspicious"
                  ? "⚠️ Suspicious URL"
                  : "✅ Likely Safe"}
              </div>

              <h4>Detection Reasons</h4>
              {result.reasons.length > 0 ? (
                <ul>
                  {result.reasons.map((reason, index) => (
                    <li key={index}>{reason}</li>
                  ))}
                </ul>
              ) : (
                <p>No suspicious URL patterns detected.</p>
              )}
            </div>
          )}
        </section>

        <div className="features">
          <div className="feature">
            <span>🔎</span>
            <h3>URL Analysis</h3>
            <p>Examine suspicious URL patterns.</p>
          </div>
          <div className="feature">
            <span>🧠</span>
            <h3>Risk Detection</h3>
            <p>Identify potential phishing indicators.</p>
          </div>
          <div className="feature">
            <span>⚡</span>
            <h3>Instant Results</h3>
            <p>Get a risk score within seconds.</p>
          </div>
        </div>

        <footer>
          PhishGuard AI | Educational Cybersecurity Project
          <br />
          Always verify websites independently before sharing sensitive information.
        </footer>
      </main>
    </div>
  );
}

export default App;
