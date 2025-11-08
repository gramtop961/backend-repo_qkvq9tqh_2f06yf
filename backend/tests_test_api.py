import json
from fastapi.testclient import TestClient
from app import app

client = TestClient(app)


def test_classify_contract():
  payload = {"subject":"Hello","body":"Team lunch tomorrow","headers":"From: a@b.com"}
  r = client.post("/api/v1/classify", json=payload)
  assert r.status_code == 200
  data = r.json()
  assert set(["verdict","probability_malicious","reasons","top_tokens"]).issubset(data.keys())


def test_rule_engine_phishing_signal():
  payload = {"subject":"URGENT verify password","body":"click http://bad.example.com now","headers":"From: x@y.com"}
  r = client.post("/api/v1/classify", json=payload)
  assert r.status_code == 200
  data = r.json()
  assert data["probability_malicious"] >= 0.4
