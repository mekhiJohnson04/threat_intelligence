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

import json 

with open('backend/data/threat_intel.json') as f:
    data = json.load(f)

for pulse in data:
    result = parse_countries(pulse.get('Countries', ''))
    if 'Republic of' in result:
        print(repr(pulse.get('Countries', '')))