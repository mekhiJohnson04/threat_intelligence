Place your blue_team_clean.json file here.

This is where rule_engine.py loads the dataset from:
  backend/data/blue_team_clean.json

The file expects a JSON array of objects with this shape:
{
  "id": "01",
  "threat": "PowerShell Abuse",
  "rule_type": "Sigma",
  "signature": "selection: CommandLine contains 'Invoke-Expression'",
  "tool": "Sigma",
  "mapped_technique": "T1059.001"
}
