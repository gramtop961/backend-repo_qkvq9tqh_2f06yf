# AI-powered Email Security Prototype

A demo showcasing a hybrid email phishing detector with a FastAPI backend and a React (Vite + Tailwind) frontend.

Security & privacy checklist (non-negotiable)
- Never send real user emails to a public demo. Use sanitized or synthetic examples.
- Use HTTPS when deploying publicly.
- If you ever connect to mail servers, validate credentials; do not log full email bodies in plain text in production.
- Rate-limit the classify endpoint to avoid abuse.

## Architecture
- Backend: FastAPI + uvicorn; hybrid detector (TF-IDF + Logistic Regression) + rule engine; SQLite logging.
- Frontend: Vite + React SPA demo that posts to /api/v1/classify.
- Docker: Backend container and an optional static Nginx server for built frontend.

## Run locally

Backend
```
# 1) Create a virtualenv (recommended)
python -m venv .venv && source .venv/bin/activate

# 2) Install deps
pip install -r backend/requirements.txt

# 3) (Optional) Train model
python backend/model_train.py

# 4) Run API
uvicorn backend.app:app --reload --port 8000
```

Frontend
```
# from project root
npm install
# Set BASE_URL for the frontend
VITE_BACKEND_URL=http://localhost:8000 npm run dev
```

## Docker
Build and run with docker-compose:
```
docker compose up --build
```
- Backend: http://localhost:8000
- FastAPI docs: http://localhost:8000/docs
- Frontend (if you build it): run `npm run build` then Nginx serves dist at http://localhost:3000

## API
POST /api/v1/classify
- Body: { "subject": "...", "body": "...", "headers": "optional" }
- Returns: { verdict, probability_malicious, reasons, top_tokens }

GET /api/v1/logs
- Returns recent logs (hashed subject/body).

POST /api/v1/feedback
- Body: { log_id?, human_label: "safe|malicious|borderline", notes? }

### curl
```
curl -s -X POST \
  "http://localhost:8000/api/v1/classify" \
  -H "Content-Type: application/json" \
  -d '{"subject":"Verify your account","body":"Click http://phish.me now","headers":"From: security@bank.com"}'
```

### fetch()
```js
fetch(`${import.meta.env.VITE_BACKEND_URL}/api/v1/classify`, {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({ subject: 'Hello', body: 'world', headers: '' })
}).then(r => r.json()).then(console.log)
```

## Testing
```
pip install -r backend/requirements.txt
pytest -q
```

## Sample emails
See sample_emails/ for sanitized examples.

## LinkedIn screenshots (suggested)
- Malicious verdict with reasons and top tokens
- Safe verdict
- FastAPI docs at /docs
