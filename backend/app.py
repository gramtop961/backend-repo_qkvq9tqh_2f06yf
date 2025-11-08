import hashlib
import json
import os
import re
import sqlite3
import time
from collections import defaultdict, deque
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

import joblib
from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

# ----------------------
# App and CORS
# ----------------------
app = FastAPI(title="Email Security API", version="1.0.0")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ----------------------
# Data models
# ----------------------
class ClassifyIn(BaseModel):
    subject: str = Field(..., max_length=500)
    body: str = Field(..., max_length=50000)
    headers: Optional[str] = Field(None, max_length=50000)

class TokenScore(BaseModel):
    token: str
    score: float

class ClassifyOut(BaseModel):
    verdict: str
    probability_malicious: float
    reasons: List[str]
    top_tokens: List[TokenScore]
    explain: Optional[Dict[str, Any]] = None

class FeedbackIn(BaseModel):
    log_id: Optional[int] = None
    human_label: str = Field(..., pattern=r"^(safe|malicious|borderline)$")
    notes: Optional[str] = None

# ----------------------
# Paths and constants
# ----------------------
BASE_DIR = Path(__file__).parent
MODEL_PATH = BASE_DIR / "model.pkl"
VECTORIZER_PATH = BASE_DIR / "vectorizer.pkl"
DB_PATH = BASE_DIR / "logs.db"

RATE_LIMIT_MAX = int(os.getenv("RATE_LIMIT_MAX", "30"))
RATE_LIMIT_WINDOW_SEC = int(os.getenv("RATE_LIMIT_WINDOW_SEC", "300"))  # 5 minutes

# ----------------------
# Simple rate limiter (per-IP, sliding window)
# ----------------------
_rate_buckets: Dict[str, deque] = defaultdict(deque)

def check_rate_limit(ip: str) -> None:
    now = time.time()
    dq = _rate_buckets[ip]
    while dq and now - dq[0] > RATE_LIMIT_WINDOW_SEC:
        dq.popleft()
    if len(dq) >= RATE_LIMIT_MAX:
        raise HTTPException(status_code=429, detail="Rate limit exceeded. Please try again later.")
    dq.append(now)

# ----------------------
# SQLite helpers
# ----------------------
def init_db():
    with sqlite3.connect(DB_PATH) as con:
        cur = con.cursor()
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ts TEXT NOT NULL,
                subj_hash TEXT,
                body_hash TEXT,
                verdict TEXT,
                prob REAL,
                reasons_json TEXT
            )
            """
        )
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS feedback (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ts TEXT NOT NULL,
                log_id INTEGER,
                human_label TEXT,
                notes TEXT,
                FOREIGN KEY(log_id) REFERENCES logs(id)
            )
            """
        )
        con.commit()

init_db()

# ----------------------
# Hybrid detector components
# ----------------------
SUSPICIOUS_KEYWORDS = {
    "verify", "reset", "urgent", "password", "bank", "update", "login", "account", "suspend",
}
URL_REGEX = re.compile(r"https?://[\w\-\.\:]+(/[\w\-\./\?\=\&%#]*)?", re.I)
EMAIL_REGEX = re.compile(r"[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}", re.I)


def rule_engine(subject: str, body: str, headers: Optional[str]) -> List[str]:
    reasons: List[str] = []

    # URLs
    urls = URL_REGEX.findall(subject + "\n" + body)
    if urls:
        reasons.append(f"Found {len(urls)} URL(s)")

    # Suspicious keywords
    text = f"{subject}\n{body}".lower()
    hits = [kw for kw in SUSPICIOUS_KEYWORDS if kw in text]
    if hits:
        reasons.append("Suspicious keywords: " + ", ".join(sorted(hits)))

    # Domain heuristics (mismatch display vs. reply-to)
    if headers:
        froms = re.findall(r"^From:\s*(.*)$", headers, flags=re.I | re.M)
        reply_to = re.findall(r"^Reply-To:\s*(.*)$", headers, flags=re.I | re.M)
        if froms and reply_to:
            from_dom = extract_domain(froms[0])
            rt_dom = extract_domain(reply_to[0])
            if from_dom and rt_dom and from_dom != rt_dom:
                reasons.append(f"Header mismatch: From domain {from_dom} vs Reply-To {rt_dom}")
        # Very naive auth checks
        if re.search(r"spf=fail|dkim=fail|dmarc=fail", headers, re.I):
            reasons.append("Header auth failed (SPF/DKIM/DMARC)")

    # Urgency heuristic
    if re.search(r"!{2,}|asap|immediately|within\s+\d+\s+(hours?|minutes?)", text, re.I):
        reasons.append("Urgency language detected")

    return reasons


def extract_domain(addr: str) -> Optional[str]:
    m = EMAIL_REGEX.search(addr)
    if not m:
        return None
    return m.group(0).split("@")[-1].lower()


_model = None
_vectorizer = None


def load_model():
    global _model, _vectorizer
    if _model is not None and _vectorizer is not None:
        return _model, _vectorizer
    if MODEL_PATH.exists() and VECTORIZER_PATH.exists():
        _model = joblib.load(MODEL_PATH)
        _vectorizer = joblib.load(VECTORIZER_PATH)
    return _model, _vectorizer


def classify_ml(subject: str, body: str) -> Dict[str, Any]:
    model, vec = load_model()
    if model is None or vec is None:
        return {
            "proba": 0.0,
            "top_tokens": [],
            "explain": {"note": "ML model not available; only rules used"},
        }
    text = subject + "\n" + body
    X = vec.transform([text])
    proba = float(model.predict_proba(X)[0, 1])

    # Top contributing tokens: tfidf_value * coef
    try:
        import numpy as np
        coefs = model.coef_[0]
        feature_names = vec.get_feature_names_out()
        x = X.toarray()[0]
        contrib = x * coefs
        top_idx = np.argsort(contrib)[::-1][:5]
        top_tokens = [
            {"token": str(feature_names[i]), "score": float(contrib[i])}
            for i in top_idx if abs(contrib[i]) > 0
        ]
    except Exception:
        top_tokens = []

    return {"proba": proba, "top_tokens": top_tokens, "explain": None}


# ----------------------
# Routes
# ----------------------
@app.post("/api/v1/classify", response_model=ClassifyOut)
async def classify(request: Request, payload: ClassifyIn):
    # Rate limit
    ip = request.client.host if request.client else "unknown"
    check_rate_limit(ip)

    # Rule engine
    reasons = rule_engine(payload.subject, payload.body, payload.headers)

    # ML score
    ml = classify_ml(payload.subject, payload.body)
    proba = ml["proba"]

    # Combine: if strong rule indicators, boost probability
    rule_boost = 0.0
    if any(r.startswith("Found ") for r in reasons):
        rule_boost += 0.15
    if any(r.startswith("Suspicious keywords") for r in reasons):
        rule_boost += 0.2
    if any("Header auth failed" in r or "Header mismatch" in r for r in reasons):
        rule_boost += 0.25
    proba = min(1.0, proba + rule_boost)

    # Verdict thresholds
    if proba >= 0.7:
        verdict = "malicious"
    elif proba >= 0.4:
        verdict = "borderline"
    else:
        verdict = "safe"

    # Logging (hashed content)
    subj_hash = hashlib.sha256(payload.subject.encode("utf-8")).hexdigest()
    body_hash = hashlib.sha256(payload.body.encode("utf-8")).hexdigest()
    ts = datetime.utcnow().isoformat() + "Z"
    reasons_json = json.dumps(reasons, ensure_ascii=False)

    with sqlite3.connect(DB_PATH) as con:
        cur = con.cursor()
        cur.execute(
            "INSERT INTO logs (ts, subj_hash, body_hash, verdict, prob, reasons_json) VALUES (?, ?, ?, ?, ?, ?)",
            (ts, subj_hash, body_hash, verdict, float(proba), reasons_json),
        )
        con.commit()

    return ClassifyOut(
        verdict=verdict,
        probability_malicious=float(proba),
        reasons=reasons,
        top_tokens=[TokenScore(**t) for t in ml.get("top_tokens", [])][:5],
        explain=ml.get("explain"),
    )


@app.get("/api/v1/logs")
async def get_logs():
    with sqlite3.connect(DB_PATH) as con:
        con.row_factory = sqlite3.Row
        cur = con.cursor()
        cur.execute("SELECT id, ts, subj_hash, body_hash, verdict, prob, reasons_json FROM logs ORDER BY id DESC LIMIT 200")
        rows = cur.fetchall()
        out = []
        for r in rows:
            out.append({
                "id": r["id"],
                "ts": r["ts"],
                "subj_hash": r["subj_hash"],
                "body_hash": r["body_hash"],
                "verdict": r["verdict"],
                "prob": r["prob"],
                "reasons": json.loads(r["reasons_json"]) if r["reasons_json"] else [],
            })
        return out


@app.post("/api/v1/feedback")
async def feedback(payload: FeedbackIn):
    ts = datetime.utcnow().isoformat() + "Z"
    with sqlite3.connect(DB_PATH) as con:
        cur = con.cursor()
        cur.execute(
            "INSERT INTO feedback (ts, log_id, human_label, notes) VALUES (?, ?, ?, ?)",
            (ts, payload.log_id, payload.human_label, payload.notes),
        )
        con.commit()
    return {"status": "ok"}


@app.get("/")
async def root():
    return {"status": "ok", "message": "Email Security API"}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=int(os.getenv("PORT", 8000)))
