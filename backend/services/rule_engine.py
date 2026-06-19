import json
from pathlib import Path
from collections import Counter
from services.technique_mapper import enrich_rules_with_tactic, is_high_signal
# Load the dataset once when the server starts
# This is intentional — no need to re-read the file on every request
BLUE_TEAM_PATH = Path(__file__).parent.parent / "data" / "blue_team_clean.json"
THREAT_INTEL_PATH = Path(__file__).parent.parent / "data" / "threat_intel.json"
CVE_VULNERABILITIES_PATH = Path(__file__).parent.parent / "data" / "cve_vulnerabilities.json"

with open(BLUE_TEAM_PATH) as f:
    RULES = json.load(f)

with open(THREAT_INTEL_PATH) as f:
    THREAT_INTEL = json.load(f)

with open(CVE_VULNERABILITIES_PATH) as f:
    CVE_VULNERABILITIES = json.load(f)


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

def get_related_threat_intel(technique_id: str) -> list:
    base = technique_id.split(".")[0] # the actual part of the id we need (e.g. "T1059".001 )
    matches = []

    for pulse in THREAT_INTEL:
        attack_ids = set(
            t.strip() for t in str(pulse.get("Attack_IDs", "")).split(",")
        )

        if base in attack_ids:
            matches.append(pulse)

    return matches

def get_intelligence(matched_pulses: list) -> dict:
    malware_families = set()
    industries = set()
    countries = set()
    tags = set()

    for pulse in matched_pulses:
        malware_families.update(x.strip() for x in str(pulse.get("Malware_Families", "")).split(","))
        industries.update(y.strip() for y in str(pulse.get("Industries", "")).split(","))
        countries.update(parse_countries(pulse.get("Countries", "")))
        tags.update(
        t.strip() for t in str(pulse.get("Tags", "")).split(",")
            if t.strip() and is_high_signal(t.strip())
        )

    
    return { # None is python's null value, so when converted to json, None gets serialized to null
        "malware_families": list(malware_families) or None,
        "industries": list(industries) or None,
        "countries": list(countries) or None,
        "tags": list(tags) or None,
        "pulse_count": len(matched_pulses)
    }

def get_pulse_context(matched_pulses: list) -> list:

    return [ 
        {
            "title": p.get("Title", ""),
            "description": p.get("Description", ""),
            "malware_families": p.get("Malware_Families", ""),
            "attack_ids": p.get("Attack_IDs", "")
        }
        for p in matched_pulses
    ]


MULTIPART_SUFFIXES = (
    "Islamic Republic of",
    "U.S.",
    "Republic of",
    "Democratic People's Republic of",
)

def parse_countries(raw: str) -> set:
    if not raw or raw.strip() == "Unknown":
        return set()
    
    parts = [p.strip() for p in raw.split(",")]
    
    countries = set()
    i = 0
    while i < len(parts):
        if i + 2 < len(parts) and f"{parts[i + 1]}, {parts[i + 2]}" == "Democratic People's Republic of":
            countries.add(f"{parts[i]}, Democratic People's Republic of")
            i += 3
        elif i + 1 < len(parts) and parts[i + 1] in MULTIPART_SUFFIXES:
            countries.add(f"{parts[i]}, {parts[i + 1]}")
            i += 2
        else:
            if parts[i]:
                countries.add(parts[i])
            i += 1
    
    return countries

CVE_LOOKUP = {cve["cveID"].lower(): cve for cve in CVE_VULNERABILITIES}

def get_cve_intelligence(tags: list):
    """
        Returns all cveIDs from the dataset that are found in the high signal tags.
    """
    matches = []
    seen_cve_id = set()

    for tag in tags:
        if tag.lower() in CVE_LOOKUP and tag.lower() not in seen_cve_id:
            cve = CVE_LOOKUP.get(tag.lower())
            matches.append(
                {
                    "cve_id": cve.get("cveID", ""),
                    "vendor_project": cve.get("vendorProject", ""),
                    "product": cve.get("product", ""),
                    "vulnerability_name": cve.get("vulnerabilityName", "") ,
                    "description": cve.get("shortDescription", ""),
                    "required_action": cve.get("requiredAction", "")
                }
            )

            seen_cve_id.add(tag.lower())

    return matches

            