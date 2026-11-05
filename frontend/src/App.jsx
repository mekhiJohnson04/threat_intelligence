import { useState } from "react"
import RuleCard from "./components/RuleCard"
import AnalysisPanel from "./components/AnalysisPanel"
import "./App.css"
import logo from "./IMG_4837.png"

export default function App() {
  const [rules, setRules] = useState([])
  const [analysis, setAnalysis] = useState("")
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState("")
  const [query, setQuery] = useState("")
  const [intelligence, setIntelligence] = useState(null)
  const [cve_intelligence, setCVE] = useState(null)

  const handleSearch = async () => {
    if (!query.trim()) return
    setLoading(true)
    setError("")
    setRules([])
    setAnalysis("")
    setIntelligence(null)
    setCVE(null)

    try {
      const response = await fetch("http://localhost:8000/api/search", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ input: query })
      })
      
      if (!response.ok) throw new Error(`${response.status}`)
      if (!response.body) throw new Error("ReadableStream not supported by response.")

      // 1. Pipe the byte stream directly into a text decoder stream
      const stream = response.body.pipeThrough(new TextDecoderStream())
      const reader = stream.getReader()
      
      let buffer = ""

      while (true) {
        const { value, done } = await reader.read()
        if (done) break

        buffer += value
        
        // 2. Split chunk buffer by line endings
        const lines = buffer.split("\n")
        
        // Pop the trailing partial line to append to the next network packet read
        buffer = lines.pop() || ""

        // 3. Process completed line pieces safely
        for (const line of lines) {
          if (!line.trim()) continue
          
          try {
            const parsedData = JSON.parse(line)

            // Capture initial metadata configuration block
            if (parsedData.event === "metadata") {
              setRules(parsedData.rules || [])
              setIntelligence(parsedData.intelligence || null)
              setCVE(parsedData.cve_intelligence || null)
            } 
            // Capture incremental analytical string chunks
            else if (parsedData.event === "analysis") {
              setAnalysis((prev) => prev + parsedData.text)
            }
          } catch (err) {
            console.error("Failed to parse chunk line:", err)
          }
        }
      }
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
            <img src={logo} alt="TIP logo" className="logo-img" />
            <span className="topbar-title">Arkhived Intelligence</span>
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

        <AnalysisPanel
         analysis={analysis} 
         loading={loading} 
         intelligence={intelligence}
         cveIntelligence={cve_intelligence}
         />
      </div>
    </div>
  )
}
