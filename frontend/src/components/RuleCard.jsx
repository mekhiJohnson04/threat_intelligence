export default function RuleCard({ rule }) {
  const badgeClass = {
    Sigma: "badge-sigma",
    YARA: "badge-yara",
    Suricata: "badge-suricata"
  }[rule.rule_type] || "badge-sigma"

  return (
    <div className="rule-card">
      <div className="rule-card-top">
        <span className="rule-threat">{rule.threat}</span>
        <span className={`rule-badge ${badgeClass}`}>{rule.rule_type}</span>
      </div>
      <div className="rule-meta">
        <span className="rule-technique">{rule.mapped_technique}</span>
        <span className="rule-meta-divider">·</span>
        <span className="rule-tool">{rule.tool}</span>
        <span className="rule-meta-divider">.</span>
        <span className="rule_tool">{rule.tactic}</span>
      </div>
      <div className="rule-signature">{rule.signature}</div>
    </div>
  )
}