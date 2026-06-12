import json
from collections import Counter

def _extract_technique_id():
    with open('backend/data/blue_team_clean.json') as f:
        data = json.load(f)

    # Strip sub-techniques and get unique base IDs
    base_techniques = set()
    for rule in data:
        technique = rule['mapped_technique'].split('.')[0]
        base_techniques.add(technique)

    print(f"\nTotal unique base techniques: {len(base_techniques)}")
    return sorted(base_techniques)


TECHNIQUE_TO_TACTIC = {
    # Credential Access
    "T1003": "Credential Access",
    "T1040": "Credential Access",
    "T1056": "Credential Access",
    "T1110": "Credential Access",
    "T1134": "Credential Access",
    "T1550": "Credential Access",
    "T1552": "Credential Access",
    "T1558": "Credential Access",

    # Discovery
    "T1007": "Discovery",
    "T1012": "Discovery",
    "T1016": "Discovery",
    "T1018": "Discovery",
    "T1033": "Discovery",
    "T1046": "Discovery",
    "T1049": "Discovery",
    "T1057": "Discovery",
    "T1069": "Discovery",
    "T1082": "Discovery",
    "T1083": "Discovery",
    "T1087": "Discovery",
    "T1135": "Discovery",
    "T1518": "Discovery",
    "T1526": "Discovery",

    # Defense Evasion
    "T1014": "Defense Evasion",
    "T1027": "Defense Evasion",
    "T1055": "Defense Evasion",
    "T1070": "Defense Evasion",
    "T1078": "Defense Evasion",
    "T1176": "Defense Evasion",
    "T1218": "Defense Evasion",
    "T1484": "Defense Evasion",
    "T1548": "Defense Evasion",
    "T1553": "Defense Evasion",
    "T1562": "Defense Evasion",
    "T1564": "Defense Evasion",
    "T1574": "Defense Evasion",

    # Execution
    "T1047": "Execution",
    "T1053": "Execution",
    "T1059": "Execution",
    "T1203": "Execution",
    "T1204": "Execution",
    "T1610": "Execution",

    # Persistence
    "T1505": "Persistence",
    "T1543": "Persistence",
    "T1546": "Persistence",
    "T1547": "Persistence",
    "T1588": "Persistence",

    # Privilege Escalation
    "T1068": "Privilege Escalation",
    "T1611": "Privilege Escalation",

    # Lateral Movement
    "T1021": "Lateral Movement",
    "T1563": "Lateral Movement",
    "T1570": "Lateral Movement",

    # Command and Control
    "T1071": "Command and Control",
    "T1090": "Command and Control",
    "T1102": "Command and Control",
    "T1105": "Command and Control",
    "T1573": "Command and Control",

    # Exfiltration
    "T1041": "Exfiltration",
    "T1537": "Exfiltration",

    # Collection
    "T1056": "Collection",
    "T1113": "Collection",

    # Initial Access
    "T1189": "Initial Access",
    "T1190": "Initial Access",
    "T1195": "Initial Access",
    "T1566": "Initial Access",

    # Resource Development
    "T1584": "Resource Development",

    # Impact
    "T1485": "Impact",
    "T1486": "Impact",
    "T1489": "Impact",
    "T1490": "Impact",
    "T1496": "Impact",
    "T1498": "Impact",
    "T1529": "Impact",

    # Discovery (cloud/container)
    "T1613": "Discovery",
}

def get_tactic(technique_id: str) -> str:
    """
    Takes a full technique ID like T1059.001,
    strips the sub-technique, returns the tactic name.
    Returns 'Unknown' if not in the mapping.
    """
    base = technique_id.split(".")[0]
    return TECHNIQUE_TO_TACTIC.get(base, "Unknown")


def enrich_rules_with_tactic(rules: list) -> list:
    """
    Takes a list of rules and attaches a tactic field to each one.
    Call this in rule_engine.py before returning results.
    """
    for rule in rules:
        rule["tactic"] = get_tactic(rule["mapped_technique"])
    return rules


def group_rules_by_tactic(rules: list) -> dict:
    """
    Groups a list of rules by their tactic phase.
    Returns a dict like:
    {
        "Lateral Movement": [...rules],
        "Credential Access": [...rules],
    }
    """
    enriched = enrich_rules_with_tactic(rules)
    grouped = {}
    for rule in enriched:
        tactic = rule["tactic"]
        if tactic not in grouped:
            grouped[tactic] = []
        grouped[tactic].append(rule)
    return grouped