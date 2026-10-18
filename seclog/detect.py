"""Detectors. Every alert says which rule fired, on which events, and why.

Sliding-window rules: brute_fast, brute_slow, stuffing_fast, spray_slow, impossible_travel,
privesc_seq, offhours_rule. Statistical per-user baselines: stat_fail_spike (EWMA of hourly failures)
and offhours_z (running mean/std of the hour an admin acts). Baselines use winsorized updates: an
anomalous value is clipped to mean + z*sd before it is learned, so a sustained change is eventually
absorbed but one burst cannot drag the baseline far.
"""
import math
from collections import Counter, defaultdict, deque
from dataclasses import dataclass, field, replace

from .events import CITIES, SEV_NAME, iso, km

PRIV_ROLES = {"admin", "secops", "dba"}


@dataclass
class Alert:
    rule: str
    type: str
    severity: int
    subject: str
    t0: float
    t1: float
    ids: list
    why: str
    rules: list = field(default_factory=list)
    whys: list = field(default_factory=list)

    def __post_init__(self):
        if not self.rules:
            self.rules = [self.rule]
        if not self.whys:
            self.whys = [self.why]

    def to_dict(self):
        return dict(type=self.type, severity=SEV_NAME[self.severity], subject=self.subject,
                    start=iso(self.t0), end=iso(self.t1), rules=self.rules,
                    event_ids=self.ids, why=" | ".join(self.whys))


def burst_triggers(ts, w, k):
    """ts sorted. Trigger at i when >= k items lie in [ts[i]-w, ts[i]]; after a trigger the next one
    needs ts > last_trigger_ts + w. Returns (left, i) index pairs."""
    out, left, last = [], 0, -math.inf
    for i, t in enumerate(ts):
        while ts[left] < t - w:
            left += 1
        if i - left + 1 >= k and t > last + w:
            out.append((left, i))
            last = t
    return out


def many_users_windows(items, w, k, ratio):
    """items (t, user, failed, id) sorted by t. Trigger when >= k distinct users failed in the window
    and failures are >= ratio of all attempts in it. Same cooldown as burst_triggers."""
    out, dq, cnt, nf, last = [], deque(), Counter(), 0, -math.inf
    for it in items:
        t, u, f, _ = it
        dq.append(it)
        if f:
            cnt[u] += 1
            nf += 1
        while dq[0][0] < t - w:
            o = dq.popleft()
            if o[2]:
                cnt[o[1]] -= 1
                nf -= 1
                if cnt[o[1]] == 0:
                    del cnt[o[1]]
        if len(cnt) >= k and nf >= ratio * len(dq) and t > last + w:
            out.append(list(dq))
            last = t
    return out


def _group(events, keyf, pred):
    d = defaultdict(list)
    for e in events:
        if pred(e):
            d[keyf(e)].append(e)
    return d


def _is_fail(e):
    return e["action"] == "login" and e["result"] == "failure"


def rule_brute(events, n, w):
    out = []
    for user, es in _group(events, lambda e: e["user"], _is_fail).items():
        ts = [e["t"] for e in es]
        for lo, i in burst_triggers(ts, w, n):
            win = es[lo:i + 1]
            srcs = sorted({e["src_ip"] for e in win})
            out.append((user, ts[lo], ts[i], [e["id"] for e in win],
                        f"{len(win)} failed logins for {user} within {int(ts[i] - ts[lo])}s "
                        f"(limit {n} per {int(w)}s) from {len(srcs)} source(s), e.g. {srcs[0]}"))
    return out


def rule_many_users(events, k, w, ratio):
    out = []
    for src, es in _group(events, lambda e: e["src_ip"], lambda e: e["action"] == "login").items():
        items = [(e["t"], e["user"], e["result"] == "failure", e["id"]) for e in es]
        for win in many_users_windows(items, w, k, ratio):
            fu = {x[1] for x in win if x[2]}
            nf = sum(x[2] for x in win)
            out.append((src, win[0][0], win[-1][0], [x[3] for x in win],
                        f"{len(fu)} distinct users failed from {src} in {int(win[-1][0] - win[0][0])}s; "
                        f"{nf}/{len(win)} attempts failed (needs >= {k} users per {int(w)}s, "
                        f">= {ratio:.0%} failing)"))
    return out


def rule_travel(events, v, min_km, seen_ok):
    out, prev, seen = [], {}, defaultdict(Counter)
    for e in events:
        if e["action"] != "login" or e["result"] != "success" or e.get("geo") not in CITIES:
            continue
        u, c, p = e["user"], e["geo"], prev.get(e["user"])
        if p is not None and p["geo"] != c:
            d = km(p["geo"], c)
            sp = d / (max(e["t"] - p["t"], 1) / 3600)
            if d >= min_km and sp > v and seen[u][c] < seen_ok:
                out.append((u, p["t"], e["t"], [p["id"], e["id"]],
                            f"{u} logged in from {p['geo']} ({p['src_ip']}) then {c} ({e['src_ip']}) "
                            f"{int(e['t'] - p['t'])}s later: {d:.0f} km = {sp:.0f} km/h > {v} km/h; "
                            f"{c} seen {seen[u][c]}x before for this user"))
        seen[u][c] += 1
        prev[u] = e
    return out


def rule_privesc(events, w):
    """Privileged role granted to a user who has never done a sensitive action, then their first
    sensitive action within w seconds. Blind spot: users who already have sensitive history."""
    out, had, pend = [], set(), {}
    for e in events:
        u = e["user"]
        if e["action"] == "role_grant" and e["role"] in PRIV_ROLES and u not in had:
            pend[u] = e
        elif e["action"] == "admin_action":
            g = pend.pop(u, None)
            if g is not None and e["t"] - g["t"] <= w:
                out.append((u, g["t"], e["t"], [g["id"], e["id"]],
                            f"{u} was granted {g['role']} by {g.get('actor', '?')} and {int(e['t'] - g['t'])}s "
                            f"later did first-ever sensitive action {e['op']} (limit {int(w)}s)"))
            had.add(u)
    return out


def _cool(out, idx, e, why):
    """One alert per user per burst: ops within an hour of the previous alert extend it."""
    i = idx.get(e["user"])
    if i is not None and e["t"] - out[i][2] <= 3600:
        out[i][2] = e["t"]
        out[i][3].append(e["id"])
    else:
        idx[e["user"]] = len(out)
        out.append([e["user"], e["t"], e["t"], [e["id"]], why])


def _hour(e):
    return (e["t"] % 86400) / 3600


def rule_offhours(events, start, end):
    out, idx = [], {}
    for e in events:
        if e["action"] == "admin_action" and (_hour(e) < start or _hour(e) >= end):
            _cool(out, idx, e, f"{e['user']} ran sensitive action {e['op']} at {_hour(e):.2f}h UTC, "
                               f"outside business hours [{start}, {end})")
    return out


def rule_hour_z(events, z, min_hist):
    out, idx, st = [], {}, {}
    for e in events:
        if e["action"] != "admin_action":
            continue
        h, s = _hour(e), st.setdefault(e["user"], [0, 0.0, 0.0])
        n, m, m2 = s
        x = h
        if n >= min_hist:
            sd = max(math.sqrt(m2 / n), 1.0)
            if abs(h - m) / sd > z:
                _cool(out, idx, e, f"{e['user']} ran {e['op']} at {h:.2f}h UTC; own history mean {m:.1f}h "
                                   f"sd {sd:.1f}h over {n} actions: z={abs(h - m) / sd:.1f} > {z}")
                x = m + math.copysign(z * sd, h - m)
        s[0] += 1
        d = x - m
        s[1] += d / s[0]
        s[2] += d * (x - s[1])
    return out


def rule_spike(events, z, min_count, alpha=0.1):
    fails, span = defaultdict(lambda: defaultdict(list)), {}
    for e in events:
        u, b = e["user"], int(e["t"] // 3600)
        lo, hi = span.get(u, (b, b))
        span[u] = (min(lo, b), max(hi, b))
        if _is_fail(e):
            fails[u][b].append(e["id"])
    out = []
    for u, (lo, hi) in span.items():
        mean = var = 0.0
        for b in range(lo, hi + 1):
            ids = fails[u].get(b, ())
            c, sd = len(ids), max(math.sqrt(var), 1.0)
            x = c
            if c >= min_count and c - mean > z * sd:
                out.append((u, b * 3600, b * 3600 + 3600, list(ids),
                            f"{c} failed logins for {u} in the hour of {iso(b * 3600)}; EWMA baseline "
                            f"{mean:.2f} (sd {sd:.2f}), z={(c - mean) / sd:.1f} > {z}, min count {min_count}"))
                x = min(c, mean + z * sd)
            d = x - mean
            mean += alpha * d
            var = (1 - alpha) * (var + alpha * d * d)
    return out


RULES = {
    "brute_fast": dict(fn=rule_brute, type="brute_force", sev=3, grid=dict(n=[5, 8, 10, 15, 20, 30], w=[120, 300, 600])),
    "brute_slow": dict(fn=rule_brute, type="brute_force", sev=3, grid=dict(n=[6, 8, 12, 20, 30, 50], w=[3600, 21600, 86400])),
    "stat_fail_spike": dict(fn=rule_spike, type="brute_force", sev=2, grid=dict(z=[2, 3, 4, 6, 8], min_count=[3, 5, 8])),
    "stuffing_fast": dict(fn=rule_many_users, type="credential_stuffing", sev=3, grid=dict(k=[8, 10, 15, 20, 30], w=[300, 600, 1800], ratio=[0.5, 0.8])),
    "spray_slow": dict(fn=rule_many_users, type="password_spraying", sev=3, grid=dict(k=[10, 15, 20, 30], w=[3600, 14400, 43200], ratio=[0.5, 0.8])),
    "impossible_travel": dict(fn=rule_travel, type="impossible_travel", sev=3, grid=dict(v=[400, 600, 800, 1000, 1200], min_km=[300, 1000], seen_ok=[1, 2, 3])),
    "privesc_seq": dict(fn=rule_privesc, type="privilege_escalation", sev=3, grid=dict(w=[600, 1800, 3600, 7200, 21600, 86400])),
    "offhours_rule": dict(fn=rule_offhours, type="offhours_admin", sev=2, grid=dict(start=[6, 7, 8], end=[17, 18, 19, 20])),
    "offhours_z": dict(fn=rule_hour_z, type="offhours_admin", sev=2, grid=dict(z=[2, 3, 4, 5], min_hist=[3, 5, 10])),
}


def run_rule(name, events, params):
    spec = RULES[name]
    return [Alert(name, spec["type"], spec["sev"], s, t0, t1, ids, why)
            for s, t0, t1, ids, why in spec["fn"](events, **params)]


def merge(alerts, gap=3600):
    """Merge alerts with the same type and subject whose spans touch (within gap seconds)."""
    out, cur = [], {}
    for a in sorted(alerts, key=lambda a: (a.type, a.subject, a.t0)):
        c = cur.get((a.type, a.subject))
        if c is not None and a.t0 <= c.t1 + gap:
            c.t1 = max(c.t1, a.t1)
            c.ids = sorted(set(c.ids) | set(a.ids))
            c.severity = max(c.severity, a.severity)
            c.rules = sorted(set(c.rules) | set(a.rules))
            c.whys = c.whys + a.whys
        else:
            c = replace(a, ids=list(a.ids), rules=list(a.rules), whys=list(a.whys))
            cur[(a.type, a.subject)] = c
            out.append(c)
    return sorted(out, key=lambda a: (a.t0, a.type, a.subject))


def detect_all(events, cfg):
    raw = []
    for name, params in cfg.items():
        raw += run_rule(name, events, params)
    return merge(raw)
