# Threat Detection Rule Explorer

A full stack tool for querying blue team detection rules mapped to MITRE ATT&CK techniques,
with Claude-powered operational analysis.

## Architecture

```
frontend/   React + Vite — the UI
backend/    FastAPI + Python — data layer + Claude API
```

## Setup

### 1. Add your dataset
Copy your `blue_team_clean.json` into:
```
backend/data/blue_team_clean.json
```

### 2. Backend
```bash
cd backend

# Create virtual environment
python -m venv venv
source venv/bin/activate      # Mac/Linux
venv\Scripts\activate         # Windows

# Install dependencies
pip install -r requirements.txt

# Set your Anthropic API key
cp .env.example .env
# Edit .env and add your ANTHROPIC_API_KEY

# Run the server
uvicorn main:app --reload
# Backend runs at http://localhost:8000
```

### 3. Frontend
```bash
cd frontend

# Install dependencies
npm install

# Run the dev server
npm run dev
# Frontend runs at http://localhost:5173
```

## API Routes

| Method | Route | What it does |
|--------|-------|--------------|
| POST | /api/search | Main search — takes user input, returns rules + Claude analysis |
| GET | /api/coverage | Returns ATT&CK technique coverage counts |
| GET | /api/rules/{type} | Filter rules by Sigma, YARA, or Suricata |
