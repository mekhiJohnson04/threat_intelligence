"""
Loads backend/data/*.json into PostgreSQL (tables from db/schema.sql).

Run from the backend/ folder so the `services` and `db` imports resolve:
    python -m db.load_data

Every insert is an upsert (INSERT ... ON CONFLICT ...), so running this twice
updates rows instead of duplicating them or crashing.
"""
import json
import psycopg
from psycopg import sql
from pathlib import Path

from db.connection import get_connection
from db import transforms
from services.rule_engine import parse_countries
from services.technique_mapper import TECHNIQUE_TO_TACTIC

DATA_DIR = Path(__file__).resolve().parent.parent / "data"

# Reference data: ATT&CK tactic IDs -> names (not in your JSON files).
# Enterprise names match the values in TECHNIQUE_TO_TACTIC.
# TA0027 / TA0031 are Mobile ATT&CK tactics that appear in the pulse data; they're
# suffixed because attack_tactics.name is UNIQUE and would clash with the Enterprise ones.
TACTIC_NAMES = {
    "TA0001": "Initial Access",
    "TA0002": "Execution",
    "TA0003": "Persistence",
    "TA0004": "Privilege Escalation",
    "TA0005": "Defense Evasion",
    "TA0006": "Credential Access",
    "TA0007": "Discovery",
    "TA0008": "Lateral Movement",
    "TA0009": "Collection",
    "TA0010": "Exfiltration",
    "TA0011": "Command and Control",
    "TA0040": "Impact",
    "TA0042": "Resource Development",
    "TA0043": "Reconnaissance",
    "TA0027": "Initial Access (Mobile)",
    "TA0031": "Credential Access (Mobile)",
}


# ---------------------------------------------------------------------------
# File reading
# ---------------------------------------------------------------------------

def load_json(filename: str) -> list[dict]:
    """
    Reads DATA_DIR / filename and returns the parsed list of records.
    """
    with open(DATA_DIR / filename) as f:
        return json.load(f)


# ---------------------------------------------------------------------------
# Shared entities
# ---------------------------------------------------------------------------

def upsert_tactics(cur: psycopg.Cursor) -> None:
    """
    Inserts every entry of TACTIC_NAMES into attack_tactics (tactic_id, name).
    Hint: cur.executemany(...) with ON CONFLICT (tactic_id) DO UPDATE SET name = EXCLUDED.name
    """
    query = """
        INSERT INTO attack_tactics (tactic_id, name)
        VALUES (%s, %s)
        ON CONFLICT (tactic_id) DO UPDATE SET name = EXCLUDED.name
    """
    # .items() gives (tactic_id, name) pairs — the same order as the %s placeholders
    cur.executemany(query, list(TACTIC_NAMES.items()))


def upsert_technique(cur: psycopg.Cursor, technique_id: str) -> None:
    """
    Inserts one technique into attack_techniques — and its parent first if it's a
    sub-technique, because parent_technique_id is a foreign key.
      "T1059.001" -> insert "T1059" (parent None), then "T1059.001" (parent "T1059")
    Use transforms.parent_technique() and ON CONFLICT (technique_id) DO NOTHING.
    """
    query = """
        INSERT INTO attack_techniques (technique_id, parent_technique_id)
        VALUES (%s, %s)
        ON CONFLICT (technique_id) DO NOTHING
    """
    parent = transforms.parent_technique(technique_id)

    if parent is not None:
        cur.execute(query,(parent, None))
    
    cur.execute(query, (technique_id, parent))

def load_technique_tactics(cur: psycopg.Cursor) -> None:
    """
    Fills technique_tactics from TECHNIQUE_TO_TACTIC (technique -> tactic *name*).
    You need the tactic *ID*, so build a reverse lookup of TACTIC_NAMES (name -> id).
    Make sure each technique exists first (upsert_technique) — it's a foreign key.
    """
    raise NotImplementedError


def get_or_create_entity(cur: psycopg.Cursor, table: str, id_column: str, name: str) -> int:
    """
    Returns the id of `name` in a name-based entity table, inserting it if new.
    Works for malware_families, industries and countries:
        get_or_create_entity(cur, "malware_families", "malware_family_id", "AsyncRAT")

    Steps:
      1. INSERT INTO <table> (name) VALUES (%s) ON CONFLICT (lower(name)) DO NOTHING
      2. SELECT <id_column> FROM <table> WHERE lower(name) = lower(%s)
      3. return that id

    Table/column names can't be passed as %s parameters — build them with
    sql.SQL(...).format(sql.Identifier(table), sql.Identifier(id_column)).
    Never use an f-string for SQL.
    """
    raise NotImplementedError


# ---------------------------------------------------------------------------
# Records
# ---------------------------------------------------------------------------

def load_detection_rules(cur: psycopg.Cursor, rules: list[dict]) -> None:
    """
    blue_team_clean.json -> detection_rules (expect 350 rows).
    For each rule: upsert_technique(rule["mapped_technique"]) first (foreign key),
    then upsert the rule on id.
    """
    raise NotImplementedError


def load_threat_pulses(cur: psycopg.Cursor, pulses: list[dict]) -> None:
    """
    threat_intel.json -> threat_pulses (expect 2,340 rows — 25 Pulse_IDs are duplicated).
    For each pulse: upsert the pulse row, then call load_pulse_relationships().
    Dates: transforms.iso_to_datetime. Tags: transforms.split_list (it's a TEXT[] column;
    psycopg turns a Python list into a Postgres array for you).
    """
    raise NotImplementedError


def load_pulse_relationships(cur: psycopg.Cursor, pulse: dict) -> None:
    """
    Fills the five join tables for one pulse. Use ON CONFLICT DO NOTHING on each.

      Attack_IDs       -> split_list, then for each ID:
                            tactic ID    -> pulse_tactics (skip IDs not in TACTIC_NAMES)
                            technique ID -> upsert_technique, then pulse_techniques
      Malware_Families -> split_list -> get_or_create_entity -> pulse_malware_families
      Industries       -> split_list -> get_or_create_entity -> pulse_industries
      Countries        -> parse_countries (NOT split_list) -> get_or_create_entity -> pulse_countries
    """
    raise NotImplementedError


def load_kev(cur: psycopg.Cursor, vulnerabilities: list[dict]) -> None:
    """
    cve_vulnerabilities.json -> kev_vulnerabilities (expect 1,766 rows), upsert on cve_id.
    dateAdded / dueDate are "YYYY-MM-DD" strings — Postgres casts those to DATE itself.
    forensicTriage -> transforms.to_bool. cwes is already a list.
    """
    raise NotImplementedError


def load_domains(cur: psycopg.Cursor, domains: list[dict]) -> None:
    """
    malicious_domains.json -> malicious_domains (expect 162 rows), upsert on domain.
    Skip the columns the schema dropped (Domain_Length, Has_Numbers, Has_Hyphen,
    Total_Engines, Data_Source).
    Dates: transforms.epoch_to_datetime. Categories: transforms.parse_categories.
    Popularity_Rank: transforms.to_int.
    """
    raise NotImplementedError


def load_ips(cur: psycopg.Cursor, ips: list[dict]) -> None:
    """
    malicious_ips.json -> malicious_ips (expect 200 rows), upsert on ip.
    Skip Total_Reports and Times_Submitted (dropped from the schema).
    ASN: transforms.to_int. TOR_Node: transforms.to_bool. Country/Network: transforms.clean.
    psycopg accepts IP and CIDR strings for INET / CIDR columns as-is.
    """
    raise NotImplementedError


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main() -> None:
    """
    Runs every loader in foreign-key order inside one transaction, so a failure
    anywhere rolls the whole load back.

      with get_connection() as conn:
          with conn.cursor() as cur:
              1. upsert_tactics
              2. load_technique_tactics
              3. load_detection_rules     (blue_team_clean.json)
              4. load_threat_pulses       (threat_intel.json)
              5. load_kev                 (cve_vulnerabilities.json)
              6. load_domains             (malicious_domains.json)
              7. load_ips                 (malicious_ips.json)

    Print a line after each step (e.g. "detection_rules: 350") so you can see progress.
    """
    raise NotImplementedError


if __name__ == "__main__":
    main()
