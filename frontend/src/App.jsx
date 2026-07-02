import { useState } from "react";
import "./App.css";

const API_BASE = "http://localhost:8000";
const SEVERITY_ORDER = { critical: 0, high: 1, medium: 2, low: 3 };
const AGENT_META = {
  security: "🔒 security",
  quality: "📐 quality",
  performance: "⚡ performance",
  documentation: "📝 documentation",
  architecture: "🏛️ architecture",
};

export default function App() {
  const [target, setTarget] = useState("");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [result, setResult] = useState(null);
  const [tierFilter, setTierFilter] = useState("all");
  const [sevFilter, setSevFilter] = useState("all");
  const [agentFilter, setAgentFilter] = useState("all");

  async function runReview(e) {
    e.preventDefault();
    setError("");
    setResult(null);
    setLoading(true);
    try {
      const res = await fetch(`${API_BASE}/review`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ target }),
      });
      if (!res.ok) {
        const body = await res.json().catch(() => ({}));
        throw new Error(body.detail || `Request failed (${res.status})`);
      }
      setResult(await res.json());
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  }

  const agentsPresent = [...new Set((result?.findings || []).map((f) => f.agent))].sort();

  const findings = (result?.findings || [])
    .filter((f) => tierFilter === "all" || f.tier === tierFilter)
    .filter((f) => sevFilter === "all" || f.severity === sevFilter)
    .filter((f) => agentFilter === "all" || f.agent === agentFilter)
    .sort((a, b) => SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity]);

  return (
    <div className="app">
      <header>
        <h1>🔍 Agentic Code Review</h1>
        <p className="tagline">
          Deterministic tools + a fenced LLM — <b className="v">Verified</b> facts vs{" "}
          <b className="s">Suggested</b> hints.
        </p>
      </header>

      <form className="search" onSubmit={runReview}>
        <input
          value={target}
          onChange={(e) => setTarget(e.target.value)}
          placeholder="GitHub repo URL or pull-request URL"
        />
        <button disabled={loading || !target}>{loading ? "Reviewing…" : "Review"}</button>
      </form>

      {loading && <p className="muted">Running the agents… this can take a bit.</p>}
      {error && <div className="error">⚠️ {error}</div>}

      {result && (
        <section className="results">
          <h2>{result.title}</h2>

          <div className="summary">
            <span className="chip">Total {result.summary.total}</span>
            <span className="chip verified">✅ Verified {result.summary.verified}</span>
            <span className="chip suggested">🤖 Suggested {result.summary.suggested}</span>
            {Object.entries(result.summary.by_severity).map(([s, n]) => (
              <span key={s} className={`chip sev-${s}`}>
                {s} {n}
              </span>
            ))}
          </div>

          <div className="filters">
            <label>
              Tier{" "}
              <select value={tierFilter} onChange={(e) => setTierFilter(e.target.value)}>
                <option value="all">All</option>
                <option value="verified">Verified</option>
                <option value="suggested">Suggested</option>
              </select>
            </label>
            <label>
              Severity{" "}
              <select value={sevFilter} onChange={(e) => setSevFilter(e.target.value)}>
                <option value="all">All</option>
                <option value="critical">Critical</option>
                <option value="high">High</option>
                <option value="medium">Medium</option>
                <option value="low">Low</option>
              </select>
            </label>
            <label>
              Agent{" "}
              <select value={agentFilter} onChange={(e) => setAgentFilter(e.target.value)}>
                <option value="all">All</option>
                {agentsPresent.map((a) => (
                  <option key={a} value={a}>
                    {a}
                  </option>
                ))}
              </select>
            </label>
            <span className="muted">{findings.length} shown</span>
          </div>

          <ul className="findings">
            {findings.map((f, i) => (
              <li key={i} className={`finding sev-border-${f.severity}`}>
                <div className="finding-head">
                  <span className={`badge sev-${f.severity}`}>{f.severity.toUpperCase()}</span>
                  <span className={`badge agent agent-${f.agent}`}>
                    {AGENT_META[f.agent] || f.agent}
                  </span>
                  <span className={`badge tier-${f.tier}`}>
                    {f.tier === "verified" ? "✅ Verified" : "🤖 Suggested"}
                  </span>
                  <span className="loc">
                    {f.filename ? `${f.filename}:` : ""}
                    {f.line_number ? `L${f.line_number}` : ""}
                  </span>
                  {f.rule_id && <span className="rule">{f.rule_id}</span>}
                  {f.corroborated_by?.length > 0 && (
                    <span className="corro">✓ {f.corroborated_by.join(", ")}</span>
                  )}
                </div>
                <div className="cat">{f.category}</div>
                <div className="desc">{f.description}</div>
                {f.evidence && (
                  <div className="evidence">
                    cites: <code>{f.evidence}</code>
                  </div>
                )}
                <div className="fix">💡 {f.suggestion}</div>
              </li>
            ))}
          </ul>
        </section>
      )}
    </div>
  );
}
