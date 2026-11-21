"""Detection and clustering metrics (no third-party dependencies)."""
from __future__ import annotations

import random
from collections import Counter
from math import comb


def prf(y_true: list[int], y_pred: list[int]) -> dict:
    tp = sum(1 for t, p in zip(y_true, y_pred) if t and p)
    fp = sum(1 for t, p in zip(y_true, y_pred) if not t and p)
    fn = sum(1 for t, p in zip(y_true, y_pred) if t and not p)
    tn = len(y_true) - tp - fp - fn
    pr = tp / (tp + fp) if tp + fp else 0.0
    rc = tp / (tp + fn) if tp + fn else 0.0
    return {"n": len(y_true), "tp": tp, "fp": fp, "fn": fn, "tn": tn, "precision": round(pr, 4), "recall": round(rc, 4),
            "f1": round(2 * pr * rc / (pr + rc), 4) if pr + rc else 0.0, "fpr": round(fp / (fp + tn), 4) if fp + tn else 0.0}


def bootstrap_f1(y_true: list[int], y_pred: list[int], n: int = 1000, seed: int = 0) -> tuple[float, float]:
    rng, idx, vals = random.Random(seed), range(len(y_true)), []
    for _ in range(n):
        s = [rng.choice(idx) for _ in idx]
        vals.append(prf([y_true[i] for i in s], [y_pred[i] for i in s])["f1"])
    vals.sort()
    return round(vals[int(0.025 * n)], 4), round(vals[int(0.975 * n)], 4)


def clustering(truth: list, pred: list) -> dict:
    """Pairwise P/R/F1, Adjusted Rand Index and B-cubed F1 for two labelings."""
    n = len(truth)
    ct, cp, cj = Counter(truth), Counter(pred), Counter(zip(truth, pred))
    same_both = sum(comb(v, 2) for v in cj.values())
    same_t, same_p, total = sum(comb(v, 2) for v in ct.values()), sum(comb(v, 2) for v in cp.values()), comb(n, 2)
    pr = same_both / same_p if same_p else 1.0
    rc = same_both / same_t if same_t else 1.0
    exp = same_t * same_p / total if total else 0.0
    mx = (same_t + same_p) / 2
    ari = (same_both - exp) / (mx - exp) if mx != exp else 1.0
    bp = sum(cj[(t, p)] / cp[p] for t, p in zip(truth, pred)) / n
    br = sum(cj[(t, p)] / ct[t] for t, p in zip(truth, pred)) / n
    f = lambda a, b: round(2 * a * b / (a + b), 4) if a + b else 0.0      # noqa: E731
    return {"n": n, "true_clusters": len(ct), "pred_clusters": len(cp), "pair_precision": round(pr, 4),
            "pair_recall": round(rc, 4), "pair_f1": f(pr, rc), "ari": round(ari, 4),
            "bcubed_precision": round(bp, 4), "bcubed_recall": round(br, 4), "bcubed_f1": f(bp, br)}
