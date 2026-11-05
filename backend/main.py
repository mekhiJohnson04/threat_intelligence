from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from services.rule_engine import search_rules, get_intelligence, get_related_threat_intel, get_pulse_context, get_cve_intelligence
from services.claude_service import analyze_threat
import json
from fastapi.responses import StreamingResponse

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
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/")
def root():
    return {"status": "Threat Explorer API is running"}
#Not Done!!! -------------
@app.route("/api/login", methods=["GET", "POST"])
def login():
    pass
# -------------------------

@app.post("/api/search")
async def search(query: dict):
    # Extract user input from request body
    user_input = query.get("input", "")

    if not user_input:
        return {"error": "No input provided"}

    # 1. Fetch all your structured data synchronously/asynchronously first
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

    # Internal generator to orchestrate the stream pipeline
    async def response_generator():
        # First event: Send all the compiled metadata to the frontend immediately
        metadata = {
            "event": "metadata",
            "rules": matching_rules,
            "intelligence": intelligence,
            "cve_intelligence": cve_intelligence
        }
        # yield as a single line json string followed by a newline separator
        yield json.dumps(metadata) + "\n"

        # Subsequent events: Stream the analysis tokens from Kimi as they hit the server
        async for analysis_chunk in analyze_threat(user_input=user_input, rules=matching_rules, pulse=pulse_context):
            chunk_data = {
                "event": "analysis",
                "text": analysis_chunk
            }
            yield json.dumps(chunk_data) + "\n"

    # Return the StreamingResponse using the generator
    return StreamingResponse(
        response_generator(),
        media_type="application/x-ndjson" # Line-delimited JSON format
    )

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


