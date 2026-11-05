import ast
import json
import re
from datetime import datetime, timezone

# Small, pure functions that turn raw JSON values into what the schema expects.
# No database code in here — that makes them easy to test on their own:
#   python -c "from db.transforms import to_bool; print(to_bool('Yes'))"

MISSING_VALUES = {"", "Unknown", "N/A"}


def clean(value):
    """
    "Unknown" / "" / "N/A" / None -> None. Anything else comes back unchanged.
    Most of the other helpers should call this first.
    """
    if value is None or value in MISSING_VALUES:
        return None
    
    return value


def to_bool(value: str | None) -> bool | None:
    """
    "Yes" -> True, "No" -> False, missing -> None.
    """
    if value == "Yes":
        return True
    elif value == "No":
        return False

    return None

def to_int(value) -> int | None:
    """
    Handles numbers stored as float strings, e.g. ASN "51395.0" -> 51395,
    Popularity_Rank "38402.0" -> 38402. Missing -> None.
    Hint: int("51395.0") fails — go through float first.
    """
    if clean(value) is None:
        return None
    
    float_val = float(value)
    return int(float_val)


def epoch_to_datetime(value) -> datetime | None:
    """
    Unix timestamps -> timezone-aware datetime (UTC).
    Inputs look like "1777636885.0" (domains, as a string) or 1777589108 (IPs, as an int).
    Missing -> None.
    Hint: datetime.fromtimestamp(..., tz=timezone.utc)
    """
    if value is None or value in MISSING_VALUES: #satisfy missing lines
        return None
    
    if type(value) is str:
        int_val = to_int(value)
        return datetime.fromtimestamp(int_val, tz=timezone.utc)
    
    return datetime.fromtimestamp(value, tz=timezone.utc)


def iso_to_datetime(value: str | None) -> datetime | None:
    """
    OTX timestamps like "2026-04-29T10:49:26.327000" -> datetime marked as UTC.
    They have no timezone in the string, so attach timezone.utc yourself.
    Hint: datetime.fromisoformat(...) then .replace(tzinfo=...)
    """
    if clean(value) is None:
        return None
    return datetime.fromisoformat(value).replace(tzinfo=timezone.utc)


def split_list(value: str | None) -> list[str]:
    """
    "T1059, T1105, T1071" -> ["T1059", "T1105", "T1071"]
    Strip whitespace, drop empty items, and return [] for missing values.
    (Countries are the exception — use rule_engine.parse_countries for those.)
    """
    attack_id_set = []
    if clean(value) is None:
        return []
    
    for item in value.split(","):
        t = item.strip()
        if t in MISSING_VALUES:
            continue
        attack_id_set.append(t)

    return attack_id_set


def parse_categories(value: str | None) -> str:
    """
    Domain Categories are a Python dict written as text with single quotes:
        "{'BitDefender': 'computersandsoftware'}"
    That isn't valid JSON, so json.loads will fail on it.
    Return a JSON string ready for the JSONB column ("{}" when empty/missing).
    Hint: ast.literal_eval to read it, json.dumps to write it.
    """
    if clean(value) is None:
        return "{}"

    # literal_eval only evaluates plain Python literals (dicts, strings, numbers),
    # so unlike eval() it can't run code hidden in the data
    try:
        categories = ast.literal_eval(value)
    except (ValueError, SyntaxError):
        # 10 rows were cut off at 150 chars when the dataset was built, so they end
        # mid-string. Keep the complete 'engine': 'category' pairs before the cut.
        categories = dict(re.findall(r"'([^']*)': '([^']*)'", value))

    return json.dumps(categories)


def is_tactic_id(attack_id: str) -> bool:
    """
    "TA0007" -> True, "T1059" / "T1059.001" -> False.
    Pulse Attack_IDs mix both kinds, so this decides which table an ID goes to.
    """
    return attack_id.startswith("TA")


def base_technique(technique_id: str) -> str:
    """
    "T1059.001" -> "T1059", "T1059" -> "T1059".
    """
    # split always returns at least one item, so [0] works with or without a "."
    return technique_id.split(".")[0]


def parent_technique(technique_id: str) -> str | None:
    """
    Value for attack_techniques.parent_technique_id:
    "T1059.001" -> "T1059", "T1059" -> None (base techniques have no parent).
    The schema has a CHECK constraint that enforces exactly this.
    """
    if "." not in technique_id:
        return None

    return base_technique(technique_id)
