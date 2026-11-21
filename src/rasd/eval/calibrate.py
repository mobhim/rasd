"""Re-estimate policy weights from labelled data with an interpretable model:
logistic regression over the SAME evidence ids the analyst sees. The output is
a new versioned Policy — the decision remains a transparent additive sum and
the decision guards still apply."""
from __future__ import annotations

from ..analysis import Analyzer, Policy
from ..models import Message


def evidence_ids(analyzer: Analyzer, corpus: list[dict]) -> list[set[str]]:
    return [{e.id for e in analyzer.analyze(Message(m["text"], sender=m.get("sender"))).evidence} for m in corpus]


def fit_policy(train: list[dict], version: str, c: float = 1.0) -> Policy:
    from sklearn.linear_model import LogisticRegression
    base = Analyzer()
    feats = evidence_ids(base, train)
    vocab = sorted(set().union(*feats))
    x = [[1.0 if v in f else 0.0 for v in vocab] for f in feats]
    lr = LogisticRegression(C=c, max_iter=2000).fit(x, [m["label"] for m in train])
    return Policy(version=version, bias=round(float(lr.intercept_[0]), 4),
                  weights={v: round(float(w), 4) for v, w in zip(vocab, lr.coef_[0])})
