"""CLI. scan exit codes: 0 clean, 1 alerts at or above --fail-on, 2 could not judge."""
import argparse
import json
import sys

from .config import DEV_SEED, TEST_SEED, ConfigError, load_config
from .detect import RULES, detect_all, run_rule
from .events import SEV_NAME, SEVERITY, LogUnreadable, load_events, parse_events
from .gen import generate, write_jsonl
from .tune import evaluate, format_table, tune


def _nonneg(s):
    v = int(s)
    if v < 0:
        raise argparse.ArgumentTypeError("must be >= 0")
    return v


def cmd_scan(a):
    try:
        cfg = load_config(a.config)
        loaded = load_events(a.logfile)
    except (LogUnreadable, ConfigError) as e:
        print(f"CANNOT JUDGE: {e}", file=sys.stderr)
        return 2
    alerts = detect_all(loaded.events, cfg) if loaded.events else []
    gate = SEVERITY[a.fail_on]
    firing = [x for x in alerts if x.severity >= gate]
    reason = None
    if not loaded.events:
        reason = "no parseable events in the file"
    elif len(loaded.bad) > a.max_bad:
        reason = f"{len(loaded.bad)} unparseable lines exceeds limit {a.max_bad} (first: {loaded.bad[:5]})"
    verdict = "cannot_judge" if reason else ("alerts" if firing else "clean")
    if a.json:
        print(json.dumps(dict(verdict=verdict, reason=reason, events=len(loaded.events), bad_lines=len(loaded.bad),
                              bad_line_numbers=loaded.bad[:20], alerts=[x.to_dict() for x in alerts])))
    else:
        for x in alerts:
            ids = ",".join(map(str, x.ids[:8])) + (f",+{len(x.ids) - 8} more" if len(x.ids) > 8 else "")
            print(f"[{SEV_NAME[x.severity].upper()}] {x.type} subject={x.subject} rules={'+'.join(x.rules)} "
                  f"events=[{ids}]\n    why: {' | '.join(x.whys)}")
        print(f"summary: events={len(loaded.events)} bad_lines={len(loaded.bad)} alerts={len(alerts)} "
              f"at_or_above_{a.fail_on}={len(firing)} verdict={verdict}")
        if reason:
            print(f"CANNOT JUDGE: {reason}", file=sys.stderr)
    return 2 if reason else (1 if firing else 0)


def cmd_gen(a):
    ev, lab = generate(a.seed, a.users, a.days, a.per_cell)
    write_jsonl(a.out, ev)
    if a.labels:
        with open(a.labels, "w", encoding="utf-8", newline="\n") as f:
            json.dump(lab, f)
    print(f"wrote {len(ev)} events, {len(lab)} attack instances")
    return 0


def cmd_tune(a):
    ev, lab = generate(a.dev_seed)
    cfg, rep = tune(parse_events(ev), lab, a.budget)
    with open(a.out, "w", encoding="utf-8", newline="\n") as f:
        json.dump(cfg, f, indent=1, sort_keys=True)
        f.write("\n")
    print(f"tuned on dev seed {a.dev_seed}; wrote {a.out}")
    return 0


def cmd_demo(a):
    size = dict(n_users=20, days=7, per_cell=2) if a.small else {}
    dev_raw, dev_lab = generate(DEV_SEED, **size)
    test_raw, test_lab = generate(TEST_SEED, **size)
    dev, test = parse_events(dev_raw), parse_events(test_raw)
    cfg, rep = tune(dev, dev_lab)
    print(f"Thresholds tuned on DEV only (seed {DEV_SEED}); false-alert budget "
          f"<= {next(iter(rep.values()))['allowed']} per rule on dev")
    for name, r in rep.items():
        print(f"  {name:18s} {json.dumps(r['params'])}  dev detected {r['detected']}/{r['total']}, dev false alerts {r['fp']}")
    print()
    for title, ev, lab in ((f"DEV (in-sample, optimistic; seed {DEV_SEED})", dev, dev_lab),
                           (f"TEST (held out, never tuned on; seed {TEST_SEED})", test, test_lab)):
        res = evaluate(ev, lab, detect_all(ev, cfg))
        print("\n".join(format_table(title, res, len(ev), len(lab))))
        if ev is test:
            print("Evasions that got through on TEST (missed instances):")
            for ty, p in res["per"].items():
                for k in p["missed"]:
                    print(f"  {ty}/{lab[k]['variant']}: {lab[k]['desc']}")
            print("Per rule on TEST (raw alerts before merging):")
            for name, params in cfg.items():
                r = evaluate(ev, lab, run_rule(name, ev, params))["per"][RULES[name]["type"]]
                v = r["variant"]
                print(f"  {name:18s} detected {r['detected']}/{r['total']} (fast {v['fast'][0]}/{v['fast'][1]}, "
                      f"slow {v['slow'][0]}/{v['slow'][1]}), alerts {r['alerts']}, false {r['fp']}")
        print()
    return 0


def main(argv=None):
    p = argparse.ArgumentParser(prog="seclog", description="Detect attacks in synthetic auth/audit logs.")
    sub = p.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("scan", help="scan a JSONL log; exit 0 clean, 1 alerts, 2 could not judge")
    s.add_argument("logfile")
    s.add_argument("--config", help="JSON config (default: tuned default_config.json)")
    s.add_argument("--fail-on", choices=list(SEVERITY), default="medium")
    s.add_argument("--max-bad", type=_nonneg, default=5, help="max unparseable lines before exit 2")
    s.add_argument("--json", action="store_true")
    s.set_defaults(fn=cmd_scan)
    g = sub.add_parser("gen", help="generate a synthetic log")
    g.add_argument("--seed", type=int, default=1)
    g.add_argument("--out", required=True)
    g.add_argument("--labels")
    g.add_argument("--users", type=int, default=60)
    g.add_argument("--days", type=int, default=14)
    g.add_argument("--per-cell", type=int, default=8)
    g.set_defaults(fn=cmd_gen)
    t = sub.add_parser("tune", help="tune thresholds on a dev split and write a config")
    t.add_argument("--dev-seed", type=int, default=DEV_SEED)
    t.add_argument("--budget", type=float, default=0.5, help="false alerts per 1000 benign events, per rule")
    t.add_argument("--out", required=True)
    t.set_defaults(fn=cmd_tune)
    d = sub.add_parser("demo", help="tune on dev, report on held-out test")
    d.add_argument("--small", action="store_true", help="tiny dataset (smoke test)")
    d.set_defaults(fn=cmd_demo)
    a = p.parse_args(argv)
    try:
        return a.fn(a)
    except Exception as e:  # never let a crash look like exit 1 (alerts) or 0 (clean)
        print(f"CANNOT JUDGE: internal error: {type(e).__name__}: {e}", file=sys.stderr)
        return 2
