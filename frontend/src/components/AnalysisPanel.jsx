import { useState } from "react"

export default function AnalysisPanel({ analysis, loading, intelligence }) {
  const [activeTab, setActiveTab] = useState("assessment")

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
              {/* Stat */}
              <div className="intel-stat">
                <span className="intel-stat-number">{intelligence.pulse_count}</span>
                <span className="intel-stat-label">Threat Campaigns Matched</span>
              </div>

              {/* Malware Families */}
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

              {/* Industries */}
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

              {/* Countries */}
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

              {/* Tags */}
              {intelligence.tags?.length > 0 && (
                <div className="intel-section">
                  <div className="intel-section-label">
                    Indicators & CVEs
                    <span className="intel-section-count">{intelligence.tags.length}</span>
                  </div>
                  <div className="chip-group">
                    {intelligence.tags.map((t, i) => (
                      <span key={i} className={`chip ${t.toLowerCase().startsWith("cve") ? "chip-yellow" : "chip-purple"}`}>
                        {t}
                      </span>
                    ))}
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