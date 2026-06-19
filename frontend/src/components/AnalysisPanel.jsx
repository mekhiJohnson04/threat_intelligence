import { useState, useEffect, useRef } from "react"

function CVEChip({ tag, cveData }) {
  const [hovered, setHovered] = useState(false)
  const [typed, setTyped] = useState("")
  const intervalRef = useRef(null)

  const fullText = cveData
    ? `${cveData.vulnerability_name}\n\n${cveData.vendor_project} · ${cveData.product}\n\n${cveData.description}\n\nREQUIRED ACTION\n${cveData.required_action}`
    : ""

  useEffect(() => {
    if (hovered && fullText) {
      setTyped("")
      let i = 0
      intervalRef.current = setInterval(() => {
        i++
        setTyped(fullText.slice(0, i))
        if (i >= fullText.length) clearInterval(intervalRef.current)
      }, 8)
    } else {
      clearInterval(intervalRef.current)
      setTyped("")
    }
    return () => clearInterval(intervalRef.current)
  }, [hovered])

  return (
    <span
      className="chip-cve-wrapper"
      onMouseEnter={() => setHovered(true)}
      onMouseLeave={() => setHovered(false)}
    >
      <span className={`chip ${cveData ? "chip-yellow chip-interactive" : "chip-yellow"}`}>
        {tag}
      </span>

      {hovered && cveData && (
        <div className="cve-tooltip">
          <div className="cve-tooltip-content">
            {typed.split("\n").map((line, i) => (
              <p key={i}>{line}</p>
            ))}
            <span className="cve-cursor">▌</span>
          </div>
        </div>
      )}
    </span>
  )
}

export default function AnalysisPanel({ analysis, loading, intelligence, cveIntelligence }) {
  const [activeTab, setActiveTab] = useState("assessment")

  const cveLookup = {}
  cveIntelligence?.forEach(cve => {
    cveLookup[cve.cve_id.toLowerCase()] = cve
  })

  return (
    <div className="analysis-panel">
      <div className="analysis-header">
        <div className="tab-group">
          <button
            className={`tab-btn ${activeTab === "assessment" ? "active" : ""}`}
            onClick={() => setActiveTab("assessment")}
          >
            Assessment
          </button>
          <button
            className={`tab-btn ${activeTab === "intelligence" ? "active" : ""}`}
            onClick={() => setActiveTab("intelligence")}
          >
            Intelligence
            {intelligence?.pulse_count > 0 && (
              <span className="tab-count">{intelligence.pulse_count}</span>
            )}
          </button>
        </div>
      </div>

      {/* ── ASSESSMENT TAB ── */}
      {activeTab === "assessment" && (
        <>
          {loading && (
            <div className="loading-block">
              <div className="loading-line" style={{ width: "78%" }} />
              <div className="loading-line" />
              <div className="loading-line" />
              <div className="loading-line" />
              <div className="loading-line" />
            </div>
          )}
          {!loading && !analysis && (
            <div className="analysis-empty">
              <p>Execute a query to receive<br />operational threat analysis<br />mapped to MITRE ATT&CK</p>
            </div>
          )}
          {!loading && analysis && (
            <div className="analysis-content">
              {analysis.split("\n").map((line, i) => (
                <p key={i}>{line}</p>
              ))}
            </div>
          )}
        </>
      )}

      {/* ── INTELLIGENCE TAB ── */}
      {activeTab === "intelligence" && (
        <div className="intel-content">
          {!intelligence || intelligence.pulse_count === 0 ? (
            <div className="analysis-empty">
              <p>Execute a query to surface<br />threat intelligence data</p>
            </div>
          ) : (
            <>
              <div className="intel-stat">
                <span className="intel-stat-number">{intelligence.pulse_count}</span>
                <span className="intel-stat-label">Threat Campaigns Matched</span>
              </div>

              {intelligence.malware_families?.length > 0 && (
                <div className="intel-section">
                  <div className="intel-section-label">
                    Malware Families
                    <span className="intel-section-count">{intelligence.malware_families.length}</span>
                  </div>
                  <div className="chip-group">
                    {intelligence.malware_families.slice(0, 8).map((f, i) => (
                      <span key={i} className="chip chip-red">{f}</span>
                    ))}
                    {intelligence.malware_families.length > 8 && (
                      <span className="chip chip-dim">+{intelligence.malware_families.length - 8} more</span>
                    )}
                  </div>
                </div>
              )}

              {intelligence.industries?.length > 0 && (
                <div className="intel-section">
                  <div className="intel-section-label">
                    Targeted Industries
                    <span className="intel-section-count">{intelligence.industries.length}</span>
                  </div>
                  <div className="chip-group">
                    {intelligence.industries.filter(i => i !== "Unknown").map((ind, i) => (
                      <span key={i} className="chip chip-blue">{ind}</span>
                    ))}
                  </div>
                </div>
              )}

              {intelligence.countries?.length > 0 && (
                <div className="intel-section">
                  <div className="intel-section-label">
                    Targeted Countries
                    <span className="intel-section-count">{intelligence.countries.length}</span>
                  </div>
                  <div className="chip-group">
                    {intelligence.countries.map((c, i) => (
                      <span key={i} className="chip chip-dim">{c}</span>
                    ))}
                  </div>
                </div>
              )}

              {intelligence.tags?.length > 0 && (
                <div className="intel-section">
                  <div className="intel-section-label">
                    Indicators & CVEs
                    <span className="intel-section-count">{intelligence.tags.length}</span>
                  </div>
                  <div className="chip-group">
                    {intelligence.tags.map((t, i) => {
                      const isCve = t.toLowerCase().startsWith("cve")
                      const cveData = isCve ? cveLookup[t.toLowerCase()] : null
                      if (isCve && !cveData) return null  // drop unmatched CVEs
                      return isCve
                        ? <CVEChip key={i} tag={t} cveData={cveData} />
                        : <span key={i} className="chip chip-purple">{t}</span>
                    })}
                  </div>
                </div>
              )}
            </>
          )}
        </div>
      )}
    </div>
  )
}