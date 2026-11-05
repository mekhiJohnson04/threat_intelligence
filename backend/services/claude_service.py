import json
import os
import anthropic
from dotenv import load_dotenv
from pathlib import Path
from typing import AsyncGenerator

load_dotenv(Path(__file__).resolve().parents[2] / ".env", override=True)

# Async client so streaming doesn't block the FastAPI event loop
client = anthropic.AsyncAnthropic(api_key=os.environ.get("API_KEY"))

MODEL = "claude-sonnet-5-5"

# Matched rules/pulses for a broad query can number in the hundreds — cap what
# gets sent for analysis so the prompt stays focused on the most relevant items.
MAX_CONTEXT_ITEMS = 15

async def analyze_threat(user_input: str, rules: list, pulse: list) -> AsyncGenerator[str, None]:
    """
    Sends the user query + matching rules to Claude for operational analysis.
    Streams chunks back to the caller as they arrive.
    """

    if not rules:
        rules_context = "No matching rules found in the dataset for this query."
    else:
        truncated_rules = rules[:MAX_CONTEXT_ITEMS]
        rules_context = json.dumps(truncated_rules, indent=2)
        if len(rules) > MAX_CONTEXT_ITEMS:
            rules_context += f"\n(...and {len(rules) - MAX_CONTEXT_ITEMS} more matching rules omitted for brevity)"

    if not pulse:
        pulse_context = "No matching intelligence found in the dataset for this query."
    else:
        truncated_pulse = pulse[:MAX_CONTEXT_ITEMS]
        pulse_context = json.dumps(truncated_pulse, indent=2)
        if len(pulse) > MAX_CONTEXT_ITEMS:
            pulse_context += f"\n(...and {len(pulse) - MAX_CONTEXT_ITEMS} more matching pulses omitted for brevity)"

    system_prompt = """You are a SOC (Security Operations Center) analyst assistant
with deep expertise in MITRE ATT&CK and threat detection... (rest of your prompt)"""

    user_message = f"""Analyst query: {user_input}

Matching detection rules from dataset:
{rules_context}

Matching threat intelligence pulses from dataset:
{pulse_context}

Provide your operational analysis."""

    # Sonnet 5.5 thinks before answering by default; effort controls how much (default is high).
    # fallbacks="default" re-runs the request on another Claude model server-side if a
    # safety classifier declines it — security content like this can trip the cyber classifier.
    try:
        async with client.beta.messages.stream(
            model=MODEL,
            max_tokens=16000,  # ceiling, not a target — thinking + answer both count toward it
            system=system_prompt,
            messages=[{"role": "user", "content": user_message}],
            output_config={"effort": "medium"},
            betas=["server-side-fallback-2026-07-01"],
            fallbacks="default",
        ) as stream:
            # text_stream yields only the visible answer, not thinking blocks
            async for text in stream.text_stream:
                yield text

            final = await stream.get_final_message()
            if final.stop_reason == "refusal":
                yield "\n[Analysis unavailable — the model declined this request.]"
            elif final.stop_reason == "max_tokens":
                yield "\n[Analysis truncated — hit the max_tokens limit.]"
    except anthropic.RateLimitError:
        yield "\n[Analysis unavailable — rate limited by the Claude API, try again shortly.]"
    except anthropic.APIStatusError as e:
        yield f"\n[Analysis unavailable — the Claude API rejected the request ({e.status_code}): {e.message}]"
    except anthropic.APIConnectionError:
        yield "\n[Analysis unavailable — could not reach the Claude API.]"
