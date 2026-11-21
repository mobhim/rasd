"""Reproducible baselines representing the classes of existing approaches.

Commercial products cannot be run here, so we do not report numbers for them.
These baselines stand for the *techniques* the literature and typical tooling
use: keyword blocklists, a supervised TF-IDF text classifier (the dominant
approach in Arabic smishing papers), text-similarity campaign clustering and
exact-string IOC matching."""
from __future__ import annotations

import re

KEYWORDS = ["عاجل", "مبروك", "ربحت", "جائزة", "تحديث بياناتك", "اضغط", "الرابط", "تم إيقاف", "تم ايقاف", "حسابك",
            "بطاقتك", "رمز التحقق", "فوراً", "فورا", "مجاناً", "تعليق", "تجميد", "رسوم", "واتساب", "تليجرام"]
_IOC = re.compile(r"(?:https?://|www\.)\S+|\+?\d{9,14}")


def keyword_predict(texts: list[str], min_hits: int = 2) -> list[int]:
    return [int(sum(k in t for k in KEYWORDS) >= min_hits) for t in texts]


def tfidf_lr(train_x: list[str], train_y: list[int]):
    from sklearn.feature_extraction.text import TfidfVectorizer
    from sklearn.linear_model import LogisticRegression
    from sklearn.pipeline import make_pipeline
    model = make_pipeline(TfidfVectorizer(analyzer="char_wb", ngram_range=(2, 5), sublinear_tf=True, min_df=2),
                          LogisticRegression(C=10, max_iter=2000, class_weight="balanced"))
    return model.fit(train_x, train_y)


def _components(n: int, pairs) -> list[int]:
    parent = list(range(n))

    def find(x):
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x
    for a, b in pairs:
        parent[find(a)] = find(b)
    return [find(i) for i in range(n)]


def text_similarity_clusters(texts: list[str], threshold: float) -> list[int]:
    from sklearn.feature_extraction.text import TfidfVectorizer
    x = TfidfVectorizer(analyzer="char_wb", ngram_range=(2, 5), sublinear_tf=True).fit_transform(texts)
    sim = (x @ x.T).toarray()
    n = len(texts)
    return _components(n, ((i, j) for i in range(n) for j in range(i + 1, n) if sim[i, j] >= threshold))


def exact_ioc_clusters(texts: list[str]) -> list[int]:
    seen: dict[str, int] = {}
    pairs = []
    for i, t in enumerate(texts):
        for tok in _IOC.findall(t):
            tok = tok.rstrip(".,،")
            if tok in seen:
                pairs.append((seen[tok], i))
            seen.setdefault(tok, i)
    return _components(len(texts), pairs)
