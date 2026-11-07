
import { useState } from "react";
import "./App.css";

function App() {
  const [url, setUrl] = useState("");
  const [result, setResult] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");

  async function analyzeURL(e) {
    e.preventDefault();

    setLoading(true);
    setResult(null);
    setError("");

    try {
     const response = await fetch(`${import.meta.env.VITE_API_URL}/analyze`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({ url }),
      });

      const data = await response.json();

      if (!response.ok) {
        throw new Error(data.detail || "Analysis failed");
      }

      setResult(data);
    } catch (err) {
      setError(err.message || "Backend connection failed");
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="app">
      <header className="header">
        <h1>🛡️ PhishGuard AI</h1>
        <p>AI-Powered Phishing URL Detection</p>
      </header>

      <main className="container">
        <section className="scanner">
          <h2>URL Security Scanner</h2>
          <p>Enter a website URL to analyze its security risk.</p>

          <form onSubmit={analyzeURL}>
            <input
              type="text"
              placeholder="https://example.com"
              value={url}
              onChange={(e) => setUrl(e.target.value)}
              required
            />

            <button type="submit" disabled={loading}>
              {loading ? "Scanning..." : "Scan URL"}
            </button>
          </form>

          {error && <p className="error">{error}</p>}

          {result && (
            <div className="result">
              <h2>{result.result}</h2>

              <p>
                <strong>Risk Score:</strong> {result.risk_score}%
              </p>

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

              {result.reasons.length > 0 ? (
                <ul>
                  {result.reasons.map((reason, index) => (
                    <li key={index}>{reason}</li>
                  ))}
                </ul>
              ) : (
                <p>No suspicious URL indicators detected.</p>
              )}
            </div>
          )}
        </section>
      </main>

      <footer>
        PhishGuard AI | Machine Learning Security Project
      </footer>
    </div>
  );
}

export default App;
