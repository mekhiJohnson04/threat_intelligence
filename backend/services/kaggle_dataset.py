import json

with open('data/threat_intel.json') as f:
    data = json.load(f)

# Print every field of first record
print(json.dumps(data[0], indent=2))

for pulse in data:
    for key, value in pulse.items():
        if isinstance(value, str) and 'cve' in value.lower():
            print(f"Field: {key}")
            print(repr(value[:200]))
            print()
            break