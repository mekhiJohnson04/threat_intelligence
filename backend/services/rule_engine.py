import json
from pathlib import Path
from collections import Counter
from services.technique_mapper import enrich_rules_with_tactic

# Load the dataset once when the server starts
# This is intentional — no need to re-read the file on every request
BLUE_TEAM_PATH = Path(__file__).parent.parent / "data" / "blue_team_clean.json"
THREAT_INTEL_PATH = Path(__file__).parent.parent / "data" / "threat_intel.json"

with open(BLUE_TEAM_PATH) as f:
    RULES = json.load(f)

with open(THREAT_INTEL_PATH) as f:
    THREATS = json.load(f)


def search_rules(query: str) -> list:
    """
    Search rules by threat name or ATT&CK technique ID.
    This is where YOUR filtering logic lives — write this yourself,
    extend it, break it, rebuild it. This is the hands-on work.
    """
    query = query.lower()
    matches = []

    for rule in RULES:
        threat_match = query in rule["threat"].lower()
        technique_match = query in rule["mapped_technique"].lower()
        rule_type_match = query in rule["rule_type"].lower()

        if threat_match or technique_match or rule_type_match:
            matches.append(rule)

    return enrich_rules_with_tactic(matches)


def get_coverage_gaps() -> dict:
    """
    Returns a count of how many detection rules exist per ATT&CK technique.
    Techniques with low counts = gaps in your detection coverage.
    This is a real metric security teams use.
    """
    technique_counts = Counter(r["mapped_technique"] for r in RULES)
    return {
        "total_rules": len(RULES),
        "techniques_covered": len(technique_counts),
        "coverage": dict(technique_counts.most_common())
    }


def filter_by_rule_type(rule_type: str) -> list:
    """
    Returns all rules of a specific type: Sigma, YARA, or Suricata.
    Each type serves a different detection purpose — understand the difference.
    """
    return [r for r in RULES if r["rule_type"].lower() == rule_type.lower()]


def get_all_threats() -> list:
    """
    Returns a deduplicated list of all threat names in the dataset.
    Useful for autocomplete or browsing.
    """
    return list(set(r["threat"] for r in RULES))


def get_rules_by_technique(technique_id: str) -> list:
    """
    Returns all rules mapped to a specific ATT&CK technique ID.
    e.g. get_rules_by_technique("T1059") returns all command execution rules.
    """
    return [r for r in RULES if r["mapped_technique"].startswith(technique_id)]

def get_threat_ids():

    ids = set()

    for threat in THREATS:
        ids.add(threat["Attack_IDs"])