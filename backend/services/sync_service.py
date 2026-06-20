import httpx
from services import rule_engine
import json
async def fetch_cisa_kev() -> dict:
    async with httpx.AsyncClient() as client: # opens the client
        response = await client.get("https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json") # makes request without blocking
        return response.json()
    
async def update_cve_data():
    new_data = await fetch_cisa_kev()

    new_count = new_data.get("count", "")
    current_count = len(rule_engine.CVE_VULNERABILITIES)

    if new_count > current_count:
        vulnerabilities = new_data["vulnerabilities"]

        #update disk
        with open(rule_engine.CVE_VULNERABILITIES_PATH, "w") as f:
            json.dump(vulnerabilities, f, indent=2)
            
        # update in-memory lookup
        rule_engine.CVE_VULNERABILITIES = vulnerabilities
        rule_engine.CVE_LOOKUP = {cve["cveID"].lower(): cve for cve in vulnerabilities}

        print(f"CVE dataset updated — {current_count} → {new_count} records")
    else:
        print(f"CVE dataset current — {current_count} records")

