import json
import pandas as pd

df = pd.read_csv('data/4_malicious_ips.csv')
data = df.to_dict(orient='records')

with open('malicious_ips.json', 'w') as f:
    json.dump(data, f, indent=2)

print(f"Done - {len(data)} records")
print(df.columns.tolist())