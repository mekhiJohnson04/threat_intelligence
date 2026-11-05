-- Threat Explorer — PostgreSQL schema (ontology layout)
--
-- Entities (the "things"):
--   attack_tactics, attack_techniques, malware_families, industries, countries   <- shared concepts
--   detection_rules, threat_pulses, kev_vulnerabilities                           <- records from backend/data/
--   malicious_domains, malicious_ips                                              <- standalone for now (no shared key yet)
--
-- Relationships (the edges):
--   detection_rules.mapped_technique  -> attack_techniques     rule DETECTS technique
--   attack_techniques.parent          -> attack_techniques     sub-technique OF technique
--   technique_tactics                    technique ACHIEVES tactic
--   pulse_techniques                     pulse USES technique
--   pulse_tactics                        pulse USES tactic
--   pulse_malware_families               pulse MENTIONS malware family
--   pulse_industries                     pulse TARGETS industry
--   pulse_countries                      pulse TARGETS country
--
-- Conventions the loader must follow when inserting from the JSON files:
--   * "Unknown" / "" / null           -> NULL (or no join row)
--   * "Yes" / "No"                    -> TRUE / FALSE
--   * Unix epoch strings ("1777636885.0") -> to_timestamp(...)   (TIMESTAMPTZ)
--   * Insert entity tables first, then records, then join tables.
--
-- Wrapped in a transaction: if any table already exists, nothing is created.

BEGIN;

-- ===========================================================================
-- Shared entities
-- ===========================================================================

-- MITRE ATT&CK tactics. Pulses reference these directly by ID (e.g. "TA0007").
-- technique_mapper.TECHNIQUE_TO_TACTIC uses names, so the loader needs the
-- standard ID <-> name mapping to fill both columns.
CREATE TABLE attack_tactics (
    tactic_id TEXT PRIMARY KEY CHECK (tactic_id ~ '^TA[0-9]{4}$'),
    name      TEXT UNIQUE                              -- e.g. 'Credential Access'
);

-- MITRE ATT&CK techniques and sub-techniques.
-- Insert a base technique ("T1059") before its sub-techniques ("T1059.001").
CREATE TABLE attack_techniques (
    technique_id        TEXT PRIMARY KEY CHECK (technique_id ~ '^T[0-9]{4}(\.[0-9]{3})?$'),
    parent_technique_id TEXT REFERENCES attack_techniques (technique_id),
    name                TEXT,                          -- not in the current data; fill later if you add ATT&CK names
    -- sub-techniques must point at their base ID, base techniques have no parent
    CHECK (
        (technique_id LIKE '%.%' AND parent_technique_id = split_part(technique_id, '.', 1))
        OR (technique_id NOT LIKE '%.%' AND parent_technique_id IS NULL)
    )
);

CREATE INDEX idx_attack_techniques_parent ON attack_techniques (parent_technique_id);

-- Many-to-many: in ATT&CK a technique can belong to more than one tactic.
CREATE TABLE technique_tactics (
    technique_id TEXT REFERENCES attack_techniques (technique_id) ON DELETE CASCADE,
    tactic_id    TEXT REFERENCES attack_tactics (tactic_id) ON DELETE CASCADE,
    PRIMARY KEY (technique_id, tactic_id)
);

CREATE INDEX idx_technique_tactics_tactic ON technique_tactics (tactic_id);

-- Name-based entities. The unique index on lower(name) merges case variants
-- like "ValleyRat" / "ValleyRAT"; the first spelling inserted is kept.
-- Loader: INSERT ... ON CONFLICT (lower(name)) DO NOTHING, then look up the id.
CREATE TABLE malware_families (
    malware_family_id INTEGER GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    name              TEXT NOT NULL
);
CREATE UNIQUE INDEX uq_malware_families_name ON malware_families (lower(name));

CREATE TABLE industries (
    industry_id INTEGER GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    name        TEXT NOT NULL
);
CREATE UNIQUE INDEX uq_industries_name ON industries (lower(name));

-- Split pulse country strings with rule_engine.parse_countries(), not a naive
-- comma split, so names like "Korea, Republic of" stay whole.
CREATE TABLE countries (
    country_id INTEGER GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    name       TEXT NOT NULL
);
CREATE UNIQUE INDEX uq_countries_name ON countries (lower(name));


-- ===========================================================================
-- Records
-- ===========================================================================

-- blue_team_clean.json (350 rows) — detection rules mapped to ATT&CK
CREATE TABLE detection_rules (
    id               TEXT PRIMARY KEY,                 -- "01", "02", ... kept as text to preserve zero padding
    threat           TEXT NOT NULL,
    rule_type        TEXT NOT NULL CHECK (rule_type IN ('Sigma', 'YARA', 'Suricata')),
    signature        TEXT NOT NULL,
    tool             TEXT NOT NULL,                    -- currently always equal to rule_type
    mapped_technique TEXT NOT NULL REFERENCES attack_techniques (technique_id),
    ingested_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- text_pattern_ops serves both joins and the prefix match in get_rules_by_technique()
CREATE INDEX idx_detection_rules_technique ON detection_rules (mapped_technique text_pattern_ops);
CREATE INDEX idx_detection_rules_rule_type ON detection_rules (rule_type);


-- threat_intel.json (2,365 rows) — AlienVault OTX pulses
-- NOTE: 25 Pulse_IDs appear twice with slightly different descriptions.
--       Load with INSERT ... ON CONFLICT (pulse_id) DO UPDATE (or DO NOTHING).
CREATE TABLE threat_pulses (
    pulse_id    TEXT PRIMARY KEY,                      -- 24-char hex OTX id
    title       TEXT NOT NULL,
    description TEXT,
    created_at  TIMESTAMPTZ NOT NULL,                  -- OTX timestamps are UTC
    modified_at TIMESTAMPTZ,
    tlp         TEXT CHECK (tlp IN ('white', 'green', 'amber', 'red', 'clear')),
    tags        TEXT[] NOT NULL DEFAULT '{}',          -- free-form keywords, kept as a list rather than an entity
    ingested_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_threat_pulses_created_at ON threat_pulses (created_at DESC);

-- Pulse relationships. Attack_IDs holds both technique IDs (T....) and tactic
-- IDs (TA....); the loader routes each ID to the matching table.
CREATE TABLE pulse_techniques (
    pulse_id     TEXT REFERENCES threat_pulses (pulse_id) ON DELETE CASCADE,
    technique_id TEXT REFERENCES attack_techniques (technique_id) ON DELETE CASCADE,
    PRIMARY KEY (pulse_id, technique_id)
);
CREATE INDEX idx_pulse_techniques_technique ON pulse_techniques (technique_id);

CREATE TABLE pulse_tactics (
    pulse_id  TEXT REFERENCES threat_pulses (pulse_id) ON DELETE CASCADE,
    tactic_id TEXT REFERENCES attack_tactics (tactic_id) ON DELETE CASCADE,
    PRIMARY KEY (pulse_id, tactic_id)
);
CREATE INDEX idx_pulse_tactics_tactic ON pulse_tactics (tactic_id);

CREATE TABLE pulse_malware_families (
    pulse_id          TEXT REFERENCES threat_pulses (pulse_id) ON DELETE CASCADE,
    malware_family_id INTEGER REFERENCES malware_families (malware_family_id) ON DELETE CASCADE,
    PRIMARY KEY (pulse_id, malware_family_id)
);
CREATE INDEX idx_pulse_malware_families_family ON pulse_malware_families (malware_family_id);

CREATE TABLE pulse_industries (
    pulse_id    TEXT REFERENCES threat_pulses (pulse_id) ON DELETE CASCADE,
    industry_id INTEGER REFERENCES industries (industry_id) ON DELETE CASCADE,
    PRIMARY KEY (pulse_id, industry_id)
);
CREATE INDEX idx_pulse_industries_industry ON pulse_industries (industry_id);

CREATE TABLE pulse_countries (
    pulse_id   TEXT REFERENCES threat_pulses (pulse_id) ON DELETE CASCADE,
    country_id INTEGER REFERENCES countries (country_id) ON DELETE CASCADE,
    PRIMARY KEY (pulse_id, country_id)
);
CREATE INDEX idx_pulse_countries_country ON pulse_countries (country_id);


-- cve_vulnerabilities.json (1,766 rows) — CISA Known Exploited Vulnerabilities
-- Refreshed every 24h by sync_service.update_cve_data(); upsert on cve_id.
CREATE TABLE kev_vulnerabilities (
    cve_id                        TEXT PRIMARY KEY CHECK (cve_id ~ '^CVE-[0-9]{4}-[0-9]{4,}$'),
    vendor_project                TEXT NOT NULL,
    product                       TEXT NOT NULL,
    vulnerability_name            TEXT NOT NULL,
    date_added                    DATE NOT NULL,
    short_description             TEXT NOT NULL,
    required_action               TEXT NOT NULL,
    due_date                      DATE,
    known_ransomware_campaign_use TEXT NOT NULL CHECK (known_ransomware_campaign_use IN ('Known', 'Unknown')),
    forensic_triage               BOOLEAN,             -- newer KEV field; nullable in case older records lack it
    notes                         TEXT,
    cwes                          TEXT[] NOT NULL DEFAULT '{}',   -- e.g. {CWE-78,CWE-20}
    ingested_at                   TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- CVE_LOOKUP is keyed on lowercase cve_id
CREATE INDEX idx_kev_cve_id_lower   ON kev_vulnerabilities (lower(cve_id));
CREATE INDEX idx_kev_vendor_project ON kev_vulnerabilities (vendor_project);
CREATE INDEX idx_kev_date_added     ON kev_vulnerabilities (date_added DESC);
CREATE INDEX idx_kev_cwes           ON kev_vulnerabilities USING GIN (cwes);


-- malicious_domains.json (162 rows) — VirusTotal domain reports
-- Length / has-numbers / has-hyphen are derivable from domain, e.g.
--   length(domain), domain ~ '[0-9]', position('-' in domain) > 0
CREATE TABLE malicious_domains (
    domain             TEXT PRIMARY KEY,
    tld                TEXT NOT NULL,
    registrar          TEXT,
    creation_date      TIMESTAMPTZ,
    last_update_date   TIMESTAMPTZ,
    reputation         INTEGER NOT NULL DEFAULT 0,
    malicious_votes    INTEGER NOT NULL DEFAULT 0,
    suspicious_votes   INTEGER NOT NULL DEFAULT 0,
    harmless_votes     INTEGER NOT NULL DEFAULT 0,
    undetected_votes   INTEGER NOT NULL DEFAULT 0,
    threat_severity    TEXT NOT NULL CHECK (threat_severity IN ('Low', 'Medium', 'High')),
    categories         JSONB NOT NULL DEFAULT '{}',    -- source is a Python dict repr; parse with ast.literal_eval
    popularity_rank    INTEGER,
    last_analysis_date TIMESTAMPTZ,
    whois_summary      TEXT,
    ingested_at        TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_malicious_domains_severity ON malicious_domains (threat_severity);
CREATE INDEX idx_malicious_domains_tld      ON malicious_domains (tld);


-- malicious_ips.json (200 rows) — VirusTotal IP reports
CREATE TABLE malicious_ips (
    ip                 INET PRIMARY KEY,
    country            VARCHAR(2),                     -- ISO 3166 alpha-2
    continent          VARCHAR(2),
    asn                BIGINT,                         -- source is "51395.0"; cast to int
    owner              TEXT,
    network            CIDR,
    malicious_votes    INTEGER NOT NULL DEFAULT 0,
    suspicious_votes   INTEGER NOT NULL DEFAULT 0,
    harmless_votes     INTEGER NOT NULL DEFAULT 0,
    undetected_votes   INTEGER NOT NULL DEFAULT 0,
    reputation_score   INTEGER NOT NULL DEFAULT 0,
    threat_label       TEXT,                           -- unrated / clean / malware (VT may add more)
    threat_category    TEXT,
    regional_registry  TEXT,
    whois_summary      TEXT,
    tor_node           BOOLEAN NOT NULL DEFAULT FALSE,
    last_analysis_date TIMESTAMPTZ,
    threat_severity    TEXT NOT NULL CHECK (threat_severity IN ('Low', 'Medium', 'High')),
    ingested_at        TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_malicious_ips_asn      ON malicious_ips (asn);
CREATE INDEX idx_malicious_ips_country  ON malicious_ips (country);
CREATE INDEX idx_malicious_ips_severity ON malicious_ips (threat_severity);
-- Lets you ask "which known IPs fall inside this range?":  WHERE ip << '185.220.101.0/24'
CREATE INDEX idx_malicious_ips_ip_gist  ON malicious_ips USING GIST (ip inet_ops);

COMMIT;


-- ===========================================================================
-- Example: rule_engine.get_related_threat_intel() as a join
-- (reference only — commented out so it doesn't run with the schema)
-- ===========================================================================
-- SELECT DISTINCT p.*
-- FROM threat_pulses p
-- JOIN pulse_techniques pt ON pt.pulse_id = p.pulse_id
-- WHERE pt.technique_id = split_part('T1059.001', '.', 1);   -- base ID, same as the Python version


SELECT count(*) FROM information_schema.tables WHERE table_schema = 'public';