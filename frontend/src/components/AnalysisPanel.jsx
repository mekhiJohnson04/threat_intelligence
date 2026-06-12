export default function AnalysisPanel({ analysis, loading }) {
  return (
    <div className="analysis-panel">
      <div className="analysis-header">
        <span className="panel-label">Analyst Assessment</span>
        {analysis && <span className="panel-count">Arkhived · Intelligence</span>}
      </div>

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
          <p>
            Execute a query to receive<br />
            operational threat analysis<br />
            mapped to MITRE ATT&CK
          </p>
        </div>
      )}

      {!loading && analysis && (
        <div className="analysis-content">
          {analysis.split("\n").map((line, i) => (
            <p key={i}>{line}</p>
          ))}
        </div>
      )}
    </div>
  )
}