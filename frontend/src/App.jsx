import { useState } from "react"
import RuleCard from "./components/RuleCard"
import AnalysisPanel from "./components/AnalysisPanel"
import "./App.css"

export default function App() {
  const [rules, setRules] = useState([])
  const [analysis, setAnalysis] = useState("")
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState("")
  const [query, setQuery] = useState("")
  const [intelligence, setIntelligence] = useState(null)

  const handleSearch = async () => {
    if (!query.trim()) return
    setLoading(true)
    setError("")
    setRules([])
    setAnalysis("")

    try {
      const response = await fetch("http://localhost:8000/api/search", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ input: query })
      })
      if (!response.ok) throw new Error(`${response.status}`)
      const data = await response.json()
      setRules(data.rules)
      setAnalysis(data.analysis)
      setIntelligence(data.intelligence)
    } catch (err) {
      setError(`CONNECTION FAILED — ${err.message}`)
    } finally {
      setLoading(false)
    }
  }

  const handleKey = (e) => {
    if (e.key === "Enter") handleSearch()
  }

  return (
    <div className="app">
      <div className="topbar">
        <div className="topbar-left">
          <div className="topbar-logo">
            <div className="logo-mark" />
            <span className="topbar-title">Threat Intelligence Platform</span>
          </div>
          <div className="topbar-divider" />
          <span className="topbar-sub">MITRE ATT&CK · Blue Team</span>
        </div>
        <div className="topbar-right">
          <div className="status-indicator">
            <div className="status-dot" />
            <span>System Operational</span>
          </div>
        </div>
      </div>

      <div className="command-bar">
        <div className="command-label">Query / Threat Scenario or ATT&CK Technique ID</div>
        <div className="command-input-row">
          <div className="command-input-wrapper">
            <span className="command-prompt">&gt;_</span>
            <input
              type="text"
              value={query}
              onChange={e => setQuery(e.target.value)}
              onKeyDown={handleKey}
              placeholder="lateral movement SMB · credential dumping · T1059 · APT..."
              disabled={loading}
              autoFocus
            />
          </div>
          <button
            className="command-execute"
            onClick={handleSearch}
            disabled={loading || !query.trim()}
          >
            {loading ? "Analyzing..." : "Execute"}
          </button>
        </div>
      </div>

      <div className="content">
        <div className="rules-panel">
          <div className="panel-header">
            <span className="panel-label">Detection Rules</span>
            {rules.length > 0 && (
              <span className="panel-count">{rules.length} matched</span>
            )}
          </div>
          {error && <div className="error-bar">{error}</div>}
          {rules.length === 0 && !loading && (
            <div className="empty-state">
              <div className="empty-state-icon">⬡</div>
              <p>No rules loaded</p>
              <p>Execute a query to surface detection rules</p>
            </div>
          )}
          {rules.map(rule => (
            <RuleCard key={rule.id} rule={rule} />
          ))}
        </div>

        <AnalysisPanel analysis={analysis} loading={loading} intelligence={intelligence}/>
      </div>
    </div>
  )
}