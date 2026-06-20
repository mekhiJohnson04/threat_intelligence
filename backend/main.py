from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from services.rule_engine import search_rules, get_intelligence, get_related_threat_intel, get_pulse_context, get_cve_intelligence
from services.claude_service import analyze_threat


from contextlib import asynccontextmanager
from apscheduler.schedulers.asyncio import AsyncIOScheduler
from services.sync_service import update_cve_data

scheduler = AsyncIOScheduler()


@asynccontextmanager
async def lifespan(app):
    scheduler.add_job(update_cve_data, "interval", hours=24)
    scheduler.start()
    await update_cve_data()
    yield
    scheduler.shutdown()

app = FastAPI(lifespan=lifespan)

# CORS — allows your frontend (localhost:5173) to talk to
# this backend (localhost:8000). Without this the browser blocks it.
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173"],
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/")
def root():
    return {"status": "Threat Explorer API is running"}


@app.post("/api/search")
async def search(query: dict):
    # 1. Extract user input from request body
    user_input = query.get("input", "")

    if not user_input:
        return {"error": "No input provided"}

    # 2. Search the dataset — YOUR logic in rule_engine.py
    matching_rules = search_rules(user_input)

    mapped_techniques = set()

    for rule in matching_rules:
        mapped_techniques.add(rule["mapped_technique"])
    
    matched_pulses = []
    for technique in mapped_techniques:
        matched_pulses.extend(get_related_threat_intel(technique_id=technique))

    
    pulse_context = get_pulse_context(matched_pulses=matched_pulses)

    intelligence = get_intelligence(matched_pulses=matched_pulses)

    cve_intelligence = get_cve_intelligence(intelligence["tags"])




    # 3. Send rules + query to Claude for operational analysis
    analysis = await analyze_threat(user_input, matching_rules, pulse_context)

    # 4. Return everything to the frontend as JSON
    return {
        "rules": matching_rules,
        "analysis": analysis,
        "intelligence": intelligence,
        "cve_intelligence": cve_intelligence
    }


@app.get("/api/coverage")
def coverage():
    # Returns technique coverage counts — useful for dashboard
    from services.rule_engine import get_coverage_gaps
    return get_coverage_gaps()


@app.get("/api/rules/{rule_type}")
def rules_by_type(rule_type: str):
    # Filter rules by Sigma, YARA, or Suricata
    from services.rule_engine import filter_by_rule_type
    return filter_by_rule_type(rule_type)


