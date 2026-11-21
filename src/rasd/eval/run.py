"""Evaluation harness. Everything printed here is measured by this run; the
report records the seed, corpus sizes and policy versions used."""
from __future__ import annotations

import csv
import json
import random
import time
from collections import Counter, defaultdict

from ..analysis import Analyzer, Policy
from ..graph import CampaignGraph, GraphConfig, MsgNode
from ..graph import engine as graph_engine
from ..models import Message
from . import baselines
from .calibrate import fit_policy
from .generator import generate
from .metrics import bootstrap_f1, clustering, prf


def _analyze_all(an: Analyzer, corpus: list[dict]) -> list[dict]:
    return [an.analyze(Message(m["text"], id=m.get("id"), sender=m.get("sender"), received_at=m.get("received_at"))).to_dict()
            for m in corpus]


def _det(y, p) -> dict:
    d = prf(y, p)
    d["f1_ci95"] = bootstrap_f1(y, p)
    return d


def detection(corpus: list[dict], seed: int) -> dict:
    fams = sorted({m["family"] for m in corpus})
    random.Random(seed).shuffle(fams)
    train_f = set(fams[: len(fams) // 2])
    train = [m for m in corpus if m["family"] in train_f]
    test = [m for m in corpus if m["family"] not in train_f]
    y = [m["label"] for m in test]
    res: dict = {"split": {"type": "template-family-disjoint (test templates never seen in training)",
                           "train": len(train), "test": len(test), "test_positive": sum(y)}}
    prior = _analyze_all(Analyzer(), test)
    flagged = [int(a["verdict"] != "benign") for a in prior]
    res["rasd_prior_flagged"] = _det(y, flagged)
    res["rasd_prior_malicious_only"] = _det(y, [int(a["verdict"] == "malicious") for a in prior])
    cal_policy = fit_policy(train, f"calibrated-seed{seed}")
    cal = _analyze_all(Analyzer(policy=cal_policy), test)
    res["rasd_calibrated_flagged"] = _det(y, [int(a["verdict"] != "benign") for a in cal])
    res["baseline_keywords"] = _det(y, baselines.keyword_predict([m["text"] for m in test]))
    model = baselines.tfidf_lr([m["text"] for m in train], [m["label"] for m in train])
    res["baseline_tfidf_lr_unseen_templates"] = _det(y, [int(v) for v in model.predict([m["text"] for m in test])])
    # same classifier under the split most papers use (random): shows template leakage
    idx = list(range(len(corpus)))
    random.Random(seed).shuffle(idx)
    cut = len(idx) // 2
    tr, te = [corpus[i] for i in idx[:cut]], [corpus[i] for i in idx[cut:]]
    m2 = baselines.tfidf_lr([m["text"] for m in tr], [m["label"] for m in tr])
    res["baseline_tfidf_lr_random_split"] = _det([m["label"] for m in te], [int(v) for v in m2.predict([m["text"] for m in te])])

    # slices (RASD prior vs TF-IDF on the family-disjoint test set)
    tf_pred = [int(v) for v in model.predict([m["text"] for m in test])]
    slices: dict = {}
    for name, sel in [("obfuscated_malicious", lambda m: m["label"] == 1 and m["obfuscation"]),
                      ("clean_malicious", lambda m: m["label"] == 1 and not m["obfuscation"])] + \
                     [(f"malicious_{d}", (lambda d: lambda m: m["label"] == 1 and m["dialect"] == d)(d))
                      for d in sorted({m["dialect"] for m in test})]:
        ix = [i for i, m in enumerate(test) if sel(m)]
        if ix:
            slices[name] = {"n": len(ix), "rasd_recall": round(sum(flagged[i] for i in ix) / len(ix), 4),
                            "tfidf_recall": round(sum(tf_pred[i] for i in ix) / len(ix), 4)}
    fp_kinds = Counter(test[i]["kind"] for i in range(len(test)) if flagged[i] and not y[i])
    res["slices"] = slices
    res["rasd_false_positive_kinds"] = dict(fp_kinds)
    res["rasd_missed_kinds"] = dict(Counter(test[i]["kind"] for i in range(len(test)) if not flagged[i] and y[i]))
    res["calibrated_policy_top_weights"] = dict(sorted(cal_policy.weights.items(), key=lambda kv: -abs(kv[1]))[:12])
    return res


def campaigns(corpus: list[dict]) -> dict:
    an = Analyzer()
    analyses = _analyze_all(an, corpus)
    mal_ix = [i for i, m in enumerate(corpus) if m["label"] == 1]
    truth = [corpus[i]["campaign"] or f"single-{corpus[i]['id']}" for i in mal_ix]
    texts = [corpus[i]["text"] for i in mal_ix]

    def rasd_labels(cfg: GraphConfig, weak_override: dict | None = None, oracle: bool = False) -> tuple[list, CampaignGraph]:
        saved = dict(graph_engine.WEAK)
        if weak_override:
            graph_engine.WEAK.update(weak_override)
        try:
            nodes = []
            for a, m in zip(analyses, corpus):
                n = MsgNode.from_analysis(a, m["received_at"])
                if oracle:
                    n.verdict = "malicious" if m["label"] else "benign"
                nodes.append(n)
            g = CampaignGraph(nodes, cfg)
        finally:
            graph_engine.WEAK.clear(); graph_engine.WEAK.update(saved)
        return [g.msg_campaign.get(corpus[i]["id"], f"s-{i}") for i in mal_ix], g

    out: dict = {"n_malicious": len(mal_ix), "true_campaigns": len({m["campaign"] for m in corpus if m["campaign"]}),
                 "note": "clusters scored over all truly malicious messages; a message the detector missed counts as an unlinked singleton"}
    labels, g = rasd_labels(GraphConfig())
    out["rasd_end_to_end"] = clustering(truth, labels)
    out["rasd_confidence_levels"] = dict(Counter(c["confidence"] for c in g.campaigns))
    benign_ids = {m["id"] for m in corpus if m["label"] == 0}
    out["rasd_campaigns_containing_benign"] = sum(1 for c in g.campaigns if benign_ids & set(c["message_ids"]))
    out["rasd_benign_messages_in_campaigns"] = sum(len(benign_ids & set(c["message_ids"])) for c in g.campaigns)
    out["rasd_oracle_detection"] = clustering(truth, rasd_labels(GraphConfig(), oracle=True)[0])
    out["rasd_hard_evidence_only"] = clustering(truth, rasd_labels(GraphConfig(corroboration_threshold=1.1))[0])
    # ablation: let text similarity alone merge messages (what the design forbids)
    out["ablation_template_alone_links"] = clustering(truth, _template_merge(analyses, corpus, mal_ix, labels))
    out["baseline_exact_ioc_match"] = clustering(truth, baselines.exact_ioc_clusters(texts))
    sweep = {t: clustering(truth, baselines.text_similarity_clusters(texts, t)) for t in (0.5, 0.6, 0.7, 0.8, 0.9)}
    out["baseline_text_similarity_sweep"] = {str(t): {k: v[k] for k in ("pair_precision", "pair_recall", "pair_f1", "ari", "bcubed_f1", "pred_clusters")}
                                             for t, v in sweep.items()}
    best = max(sweep, key=lambda t: sweep[t]["pair_f1"])
    out["baseline_text_similarity_best"] = {"threshold": best, "tuned_on_test_labels": True, **sweep[best]}
    return out


def _template_merge(analyses, corpus, mal_ix, rasd_labels) -> list:
    """RASD clusters, additionally merged whenever two messages share a template fingerprint."""
    parent: dict = {}

    def find(x):
        parent.setdefault(x, x)
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x
    by_fp = defaultdict(list)
    for lab, i in zip(rasd_labels, mal_ix):
        by_fp[analyses[i]["fingerprint"]].append(lab)
    for labs in by_fp.values():
        for other in labs[1:]:
            parent[find(other)] = find(labs[0])
    return [find(lab) for lab in rasd_labels]


def external(path: str, seed: int, annotations: str = "data/annotations/alsantali_test_fraud_labels.json") -> dict:
    """Real public data: Alsantali Arabic-SMS-Spam (GPL-3.0). Its labels are
    spam/ham, NOT fraud/benign: most 'spam' is ordinary retail marketing, which
    is outside RASD's scope. So we report (a) against the original label and
    (b) against a fraud annotation of the held-out half made after the engine
    was frozen. Lexicon work only ever looked at the DEV half."""
    import os
    from .external_split import load
    data = load(path)
    an = Analyzer()
    analyses = {m["id"]: a for m, a in zip(data, _analyze_all(an, data))}
    flag = {k: int(a["verdict"] != "benign") for k, a in analyses.items()}
    dev, test = [m for m in data if m["part"] == "dev"], [m for m in data if m["part"] == "test"]
    res: dict = {"source": "github.com/KhalidAlsantali/Arabic-SMS-Spam-Data (GPL-3.0)", "n_unique": len(data),
                 "dev": {"n": len(dev), "spam": sum(m["label"] for m in dev)},
                 "test": {"n": len(test), "spam": sum(m["label"] for m in test)},
                 "protocol": "lexicon tuned on DEV only; TEST untouched until frozen"}
    yt = [m["label"] for m in test]
    res["test_vs_spam_label"] = {"rasd_prior_zero_shot": _det(yt, [flag[m["id"]] for m in test]),
                                 "baseline_keywords": _det(yt, baselines.keyword_predict([m["text"] for m in test]))}
    model = baselines.tfidf_lr([m["text"] for m in dev], [m["label"] for m in dev])
    tf = {m["id"]: int(v) for m, v in zip(test, model.predict([m["text"] for m in test]))}
    res["test_vs_spam_label"]["baseline_tfidf_lr_trained_on_dev"] = _det(yt, [tf[m["id"]] for m in test])
    res["dev_vs_spam_label_rasd"] = prf([m["label"] for m in dev], [flag[m["id"]] for m in dev])
    if os.path.exists(annotations):
        with open(annotations, encoding="utf8") as fh:
            ann = json.load(fh)
        clear, prob, amb = set(ann["fraud_clear"]), set(ann["fraud_probable"]), set(ann["ambiguous"])
        spam_test = [m["id"] for m in test if m["label"]]
        marketing = [i for i in spam_test if i not in clear | prob | amb]
        ham = [m["id"] for m in test if not m["label"]]
        rate = lambda ids, f: {"n": len(ids), "flagged": sum(f[i] for i in ids), "rate": round(sum(f[i] for i in ids) / max(1, len(ids)), 4)}   # noqa: E731
        kw = {m["id"]: v for m, v in zip(test, baselines.keyword_predict([m["text"] for m in test]))}
        res["test_fraud_annotation"] = {
            "annotation": "single annotator, post-freeze, blind to verdicts — see data/annotations/",
            "rasd": {"fraud_clear_recall": rate(sorted(clear), flag), "fraud_probable_recall": rate(sorted(prob), flag),
                     "marketing_flag_rate": rate(marketing, flag), "ham_flag_rate": rate(ham, flag),
                     "malicious_verdict_on_fraud_clear": sum(1 for i in clear if analyses[i]["verdict"] == "malicious")},
            "baseline_keywords": {"fraud_clear_recall": rate(sorted(clear), kw), "fraud_probable_recall": rate(sorted(prob), kw),
                                  "marketing_flag_rate": rate(marketing, kw), "ham_flag_rate": rate(ham, kw)},
            "baseline_tfidf_lr_spam_classifier": {"fraud_clear_recall": rate(sorted(clear), tf), "fraud_probable_recall": rate(sorted(prob), tf),
                                                  "marketing_flag_rate": rate(marketing, tf), "ham_flag_rate": rate(ham, tf),
                                                  "note": "trained to detect spam, so flagging marketing is its intended behaviour; shown to make the task difference explicit"},
            "rasd_missed_fraud_ids": sorted(i for i in clear | prob if not flag[i]),
        }
    var = Counter((m["label"], analyses[m["id"]]["variety"]["label"].replace("msa_mixed_", "mixed:")) for m in data)
    res["variety_by_label_all"] = {f"{'spam' if k[0] else 'ham'}|{k[1]}": v for k, v in sorted(var.items(), key=lambda kv: -kv[1])}
    obf = Counter(e["id"] for m in data if m["label"] for e in analyses[m["id"]]["evidence"] if e["id"].startswith("obfuscation."))
    res["obfuscation_evidence_in_spam_all"] = dict(obf)
    # unsupervised structure (no campaign ground truth exists for this dataset)
    g = CampaignGraph([MsgNode.from_analysis(analyses[m["id"]]) for m in data])
    lab = {m["id"]: m["label"] for m in data}
    res["campaign_structure_no_ground_truth"] = {
        "campaigns": len(g.campaigns), "messages_in_campaigns": len(g.msg_campaign),
        "campaigns_containing_ham": sum(1 for c in g.campaigns if any(not lab[i] for i in c["message_ids"])),
        "template_families": [{"size": f["size"], "distinct_hard_indicators": f["distinct_hard_indicators"],
                               "in_campaigns": len(f["campaign_ids"]), "unlinked_messages": f["unlinked_messages"]}
                              for f in g.template_families],
        "detail": [{"size": c["size"], "confidence": c["confidence"],
                    "shared": [f"{d['type']}×{d['messages']}" for d in c["indicators"] if d["messages"] >= 2]} for c in g.campaigns[:8]]}
    return res


def throughput(corpus: list[dict]) -> dict:
    an = Analyzer()
    t = time.perf_counter()
    for m in corpus:
        an.analyze(Message(m["text"], sender=m.get("sender")))
    dt = time.perf_counter() - t
    nodes = [MsgNode.from_analysis(a, m["received_at"]) for a, m in zip(_analyze_all(an, corpus), corpus)]
    t = time.perf_counter()
    CampaignGraph(nodes)
    return {"messages": len(corpus), "analyze_msgs_per_sec_single_core": round(len(corpus) / dt, 1),
            "graph_build_seconds": round(time.perf_counter() - t, 3)}


def main(seed: int = 7, out: str | None = None, external_path: str | None = None, **kw) -> int:
    external_path = external_path or kw.get("external")
    corpus = generate(seed=seed)
    report = {"seed": seed, "corpus": {"type": "synthetic (rasd.eval.generator)", "messages": len(corpus),
                                       "malicious": sum(m["label"] for m in corpus),
                                       "campaigns": len({m["campaign"] for m in corpus if m["campaign"]})},
              "prior_policy": Policy().version,
              "detection": detection(corpus, seed), "campaigns": campaigns(corpus), "throughput": throughput(corpus)}
    if external_path:
        report["external_real_data"] = external(external_path, seed)
    js = json.dumps(report, ensure_ascii=False, indent=2)
    if out:
        with open(out, "w", encoding="utf8") as fh:
            fh.write(js)
    print(js)
    return 0
