import httpx
from services import rule_engine
async def fetch_cisa_kev() -> dict:
    async with httpx.AsyncClient() as client: # opens the client
        response = await client.get("https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json") # makes request without blocking
        return response.json()
    
async def update_json(cve_dict: dict):
    new_data = await fetch_cisa_kev()

    new_data_length = new_data.get("count", "")

    if new_data_length > len(cve_dict):
        rule_engine.CVE_LOOKUP = {cve["cveID"].lower(): cve for cve in new_data["vulnerabilities"]}

        with open(rule_engine.CVE_VULNERABILITIES_PATH) as f:
            


    
