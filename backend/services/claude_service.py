import json
import anthropic
import os
from dotenv import load_dotenv

load_dotenv()

client = anthropic.Anthropic(api_key=os.getenv("ANTHROPIC_API_KEY"))


async def analyze_threat(user_input: str, rules: list) -> str:
    """
    Sends the user query + matching rules to Claude for operational analysis.
    This is the orchestration layer — Claude brings the context the dataset lacks.
    """

    # If no rules matched, still give useful guidance
    if not rules:
        rules_context = "No matching rules found in the dataset for this query."
    else:
        rules_context = json.dumps(rules, indent=2)

    system_prompt = """You are a SOC (Security Operations Center) analyst assistant 
with deep expertise in MITRE ATT&CK and threat detection.

You will be given a threat description or query from an analyst, along with 
matching detection rules from a blue team dataset.

Your job is to:
1. Identify what ATT&CK tactic phase this threat belongs to
2. Explain what the threat means operationally in plain English
3. Explain what each detection rule is looking for and which tool runs it
4. Tell the analyst what to investigate next if this fires
5. Note any gaps — what this dataset does NOT cover for this threat

Be direct, operational, and concise. You are talking to a technical analyst, 
not an executive. No fluff, no filler.

Formatting rules: never use markdown headers or hashtags. Use plain text only. 
For section headings use ALL CAPS instead. Keep everything readable as plain text."""

    user_message = f"""Analyst query: {user_input}

Matching detection rules from dataset:
{rules_context}

Provide your operational analysis."""

    response = client.messages.create(
        model="claude-sonnet-4-6",
        max_tokens=1000,
        system=system_prompt,
        messages=[
            {"role": "user", "content": user_message}
        ]
    )

    return response.content[0].text
