import json
import os
from pathlib import Path

import joblib
import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import classification_report, roc_auc_score
from sklearn.model_selection import train_test_split

# Note: For demo purposes, we include very small synthetic subsets.
# Replace this with real subsets of SpamAssassin + Enron when available.

def load_synthetic():
    phishing = [
        "urgent verify your password http://bad.example.com",
        "reset your bank login immediately",
        "confirm account now click http://phish.me",
        "update password within 24 hours",
    ]
    safe = [
        "lunch meeting tomorrow at noon",
        "weekly report attached please review",
        "team outing next friday details inside",
        "invoice paid thank you",
    ]
    X = phishing + safe
    y = [1] * len(phishing) + [0] * len(safe)
    return X, np.array(y)


def main():
    X, y = load_synthetic()
    vec = TfidfVectorizer(lowercase=True, ngram_range=(1, 2), min_df=1, max_df=1.0)
    Xv = vec.fit_transform(X)

    Xtr, Xte, ytr, yte = train_test_split(Xv, y, test_size=0.33, random_state=42, stratify=y)

    clf = LogisticRegression(max_iter=200, solver="liblinear")
    clf.fit(Xtr, ytr)

    ypred = clf.predict(Xte)
    yproba = clf.predict_proba(Xte)[:, 1]

    report = classification_report(yte, ypred, output_dict=True)
    auc = roc_auc_score(yte, yproba)

    print("Classification report:\n", json.dumps(report, indent=2))
    print("ROC AUC:", float(auc))

    out_dir = Path(__file__).parent
    joblib.dump(clf, out_dir / "model.pkl")
    joblib.dump(vec, out_dir / "vectorizer.pkl")

    artifacts = {"classification_report": report, "roc_auc": float(auc)}
    (out_dir / "artifacts").mkdir(exist_ok=True)
    with open(out_dir / "artifacts" / "metrics.json", "w") as f:
        json.dump(artifacts, f, indent=2)

    print("Saved model.pkl, vectorizer.pkl, and artifacts/metrics.json")


if __name__ == "__main__":
    main()
