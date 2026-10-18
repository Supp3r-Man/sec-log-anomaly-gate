"""Metrics, dev-split tuning, and the printed report. Tuning sees the dev split only."""
import math
from itertools import product

from .detect import RULES, run_rule
from .gen import TYPES


def evaluate(events, labels, alerts):
    """An alert is a TP for its type if it contains an event of an attack instance of that type,
    'x' (cross-type) if it only touches other attack types, FP if it touches no attack event."""
    attack = {}
    for k, lab in enumerate(labels):
        for i in lab["events"]:
            attack.setdefault(i, set()).add(k)
    per = {}
    for ty in TYPES:
        ks = {k for k, lab in enumerate(labels) if lab["type"] == ty}
        hit, tp, xt, fp, n = set(), 0, 0, 0, 0
        for a in alerts:
            if a.type != ty:
                continue
            n += 1
            hits = {k for i in a.ids for k in attack.get(i, ())}
            if hits & ks:
                tp += 1
                hit |= hits & ks
            elif hits:
                xt += 1
            else:
                fp += 1
        var = {}
        for v in ("fast", "slow"):
            tot = [k for k in ks if labels[k]["variant"] == v]
            var[v] = (sum(k in hit for k in tot), len(tot))
        per[ty] = dict(alerts=n, tp=tp, xt=xt, fp=fp, detected=len(hit), total=len(ks), variant=var,
                       missed=sorted(ks - hit))
    benign = len(events) - len(attack)
    fp_all = sum(p["fp"] for p in per.values())
    return dict(per=per, benign=benign, false_alerts=fp_all, fa_per_1000=1000 * fp_all / max(benign, 1),
                alerts=len(alerts))


def tune(events, labels, budget=0.5):
    """Per rule, grid search on the dev split: among settings whose false alerts stay within
    `budget` per 1000 benign events, maximise detected attack instances of the rule's type;
    ties go to fewer false alerts, then fewer alerts. Returns (config, per-rule dev report)."""
    attack_ids = {i for lab in labels for i in lab["events"]}
    allowed = math.floor(budget * (len(events) - len(attack_ids)) / 1000)
    cfg, rep = {}, {}
    for name, spec in RULES.items():
        keys, best = list(spec["grid"]), None
        for combo in product(*spec["grid"].values()):
            p = dict(zip(keys, combo))
            al = run_rule(name, events, p)
            r = evaluate(events, labels, al)["per"][spec["type"]]
            ok = r["fp"] <= allowed
            key = (ok, r["detected"] if ok else 0, -r["xt"], -r["fp"], -len(al))
            if best is None or key > best[0]:
                best = (key, p, r)
        cfg[name] = best[1]
        rep[name] = dict(params=best[1], detected=best[2]["detected"], total=best[2]["total"], fp=best[2]["fp"],
                         allowed=allowed)
    return cfg, rep


def format_table(title, res, n_events, n_inst):
    L = [f"{title}: {n_events} events ({res['benign']} benign), {n_inst} attack instances",
         f"{'attack type':22s} {'fast':>7s} {'slow':>7s} {'prec':>5s} {'any-atk':>7s}  alerts (tp/cross/fp)"]
    for ty, p in res["per"].items():
        f, s = p["variant"]["fast"], p["variant"]["slow"]
        prec = f"{p['tp'] / p['alerts']:.2f}" if p["alerts"] else "n/a"
        anyp = f"{(p['tp'] + p['xt']) / p['alerts']:.2f}" if p["alerts"] else "n/a"
        L.append(f"{ty:22s} {f'{f[0]}/{f[1]}':>7s} {f'{s[0]}/{s[1]}':>7s} {prec:>5s} {anyp:>7s}  "
                 f"{p['alerts']} ({p['tp']}/{p['xt']}/{p['fp']})")
    d = sum(p["detected"] for p in res["per"].values())
    L.append(f"overall recall {d}/{n_inst}; false alerts per 1000 benign events: "
             f"{res['fa_per_1000']:.2f} ({res['false_alerts']} alerts touching no attack event)")
    return L
