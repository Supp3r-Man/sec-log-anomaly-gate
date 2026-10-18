"""Seeded synthetic auth/audit log generator.

Everything is fictional: users usr001.., admins adm00.., hosts *.example.test, cities invented.
IPs come only from the documentation ranges: 198.51.100.0/24 (home), 192.0.2.0/24 (office NAT,
VPN exit, travel, service accounts), 203.0.113.0/24 (attackers).
The log file carries no labels; labels (which line ids belong to which attack) are returned apart.
"""
import json
import random
from collections import defaultdict
from datetime import datetime, timezone

from .events import CITIES, iso, km

TYPES = ["brute_force", "credential_stuffing", "password_spraying",
         "impossible_travel", "privilege_escalation", "offhours_admin"]
HOSTS = [f"{n}.example.test" for n in ("app01", "app02", "db01", "wiki01", "git01", "vpn01")]
IDP = "idp.example.test"
OPS = ["export_all_records", "disable_audit_log", "create_api_key", "delete_backups", "change_idp_config"]
T0 = int(datetime(2026, 3, 2, tzinfo=timezone.utc).timestamp())  # a Monday


def generate(seed, n_users=60, days=14, per_cell=8):
    """Returns (events, labels). per_cell = attack instances per (type, fast|slow)."""
    r = random.Random(seed)
    E, inst = [], []
    cities = list(CITIES)

    def emit(t, d, k=-1):
        t = int(t)
        d["ts"] = iso(t)
        E.append((t, len(E), d, k))

    def ev(user, action, ip, geo, host, result="success", **kw):
        return dict(ts=None, user=user, action=action, result=result, src_ip=ip, host=host, geo=geo, **kw)

    def login(user, ip, geo, ok, host=IDP):
        return ev(user, "login", ip, geo, host, "success" if ok else "failure")

    users = []
    for i in range(n_users):
        u = dict(i=i, name=f"adm{i:02d}" if i < 6 else f"usr{i:03d}", admin=i < 6, oncall=i < 3,
                 home=r.choice(cities), ip=f"198.51.100.{i + 1}", office=i >= 6 and r.random() < 0.25,
                 vpn=i >= 6 and i % 12 == 7, start=r.randint(7, 10), length=r.randint(8, 9),
                 fail_p=r.choice([0.01, 0.03, 0.03, 0.08]), hosts=r.sample(HOSTS, 3))
        if u["office"]:
            u["home"] = "Northvale"
        u["vpn_city"] = r.choice([c for c in cities if c != u["home"]])
        users.append(u)
    U = {u["name"]: u for u in users}
    admins = [u["name"] for u in users[:6]]
    cand = [u for u in users[6:] if not u["vpn"]]
    trips = {}
    for u in r.sample(cand, min(4, len(cand) // 4)):
        d0 = r.randint(2, max(2, days - 6))
        trips[u["i"]] = (d0, d0 + r.randint(2, 3), r.choice([c for c in cities if c != u["home"]]))

    # benign: user sessions, benign failures, travel, VPN geo noise, admin routine and on-call work
    for u in users:
        trip, prev_t, prev_city = trips.get(u["i"]), None, u["home"]
        for d in range(days):
            day0, wd = T0 + d * 86400, d % 7
            if u["admin"]:
                if wd < 5 and r.random() < 0.5:
                    emit(day0 + r.uniform(8, 17) * 3600, ev(u["name"], "admin_action", u["ip"], u["home"], IDP, op=r.choice(OPS)))
                if u["oncall"] and r.random() < 0.08:
                    h = r.choice([r.uniform(19.2, 24), r.uniform(0, 5)])
                    emit(day0 + h * 3600, ev(u["name"], "admin_action", u["ip"], u["home"], IDP, op=r.choice(OPS)))
            if r.random() >= (0.95 if wd < 5 else 0.08):
                continue
            in_trip = trip is not None and trip[0] <= d <= trip[1]
            city = trip[2] if in_trip else u["home"]
            ip = f"192.0.2.{100 + u['i']}" if in_trip else ("192.0.2.10" if u["office"] and wd < 5 else u["ip"])
            hrs = sorted(min(max(r.gauss(u["start"] + u["length"] / 2, u["length"] / 4), u["start"]), u["start"] + u["length"])
                         for _ in range(r.choice([1, 1, 2, 3])))
            for h in hrs:
                t = day0 + h * 3600
                if city != prev_city and prev_t is not None:  # a real trip takes real time
                    t = max(t, prev_t + km(prev_city, city) / r.uniform(450, 650) * 3600 + 7200)
                if prev_t is not None:
                    t = max(t, prev_t + 60)
                prev_t, prev_city = t, city
                sip, sgeo = ("192.0.2.50", u["vpn_city"]) if u["vpn"] and r.random() < 0.15 else (ip, city)
                x = r.random()
                nf = 1 if x < u["fail_p"] else (r.randint(2, 4) if x < u["fail_p"] + 0.015 else 0)
                for _ in range(nf):
                    emit(t, login(u["name"], sip, sgeo, False))
                    t += r.randint(15, 60)
                emit(t, login(u["name"], sip, sgeo, True))
                for _ in range(r.randint(2, 5)):
                    t += r.randint(60, 1800)
                    emit(t, ev(u["name"], "access", sip, sgeo, r.choice(u["hosts"])))
    for j, sname in enumerate(("svc-backup", "svc-ci")):  # service accounts: steady, with token-expiry failure bursts
        sip, t, app = f"192.0.2.{200 + j}", T0 + r.randint(0, 599), "app01.example.test"
        while t < T0 + days * 86400:
            emit(t, login(sname, sip, "Northvale", True, app))
            t += 600 + r.randint(-20, 20)
        for d in [d for d in range(days) if r.random() < 0.25]:
            tt = T0 + d * 86400 + r.uniform(0, 86400)
            for _ in range(r.randint(3, 7)):
                emit(tt, login(sname, sip, "Northvale", False, app))
                tt += r.randint(20, 40)

    def op_ev(t, name, ip, geo, k=-1):
        emit(t, ev(name, "admin_action", ip, geo, IDP, op=r.choice(OPS)), k)

    def grant(t, name, actor, role, ip, geo, k=-1):
        emit(t, ev(name, "role_grant", ip, geo, IDP, actor=actor, role=role), k)

    def day_t(h0, h1, lo=2):
        return T0 + r.randint(lo, days - 2) * 86400 + r.uniform(h0, h1) * 3600

    pool = users[6:]
    r.shuffle(pool)
    for _ in range(6):  # benign: on-call elevation of an existing admin (has history)
        a = U[r.choice(admins)]
        t = day_t(9, 15)
        grant(t, a["name"], r.choice([x for x in admins if x != a["name"]]), "admin", a["ip"], a["home"])
        op_ev(t + r.uniform(300, 1800), a["name"], a["ip"], a["home"])
    for _ in range(6):  # benign: onboarding a new admin; 1 in 4 acts within minutes, rest hours to days later
        a = pool.pop()
        t = day_t(9, 15)
        delay =r.uniform(1200, 3000) if r.random() < 0.25 else r.uniform(7200, 144000)
        grant(t, a["name"], r.choice(admins), "admin", a["ip"], a["home"])
        op_ev(t + delay, a["name"], a["ip"], a["home"])
    for _ in range(10):  # benign: ordinary non-privileged grants
        a = r.choice(users[6:])
        t = day_t(9, 15)
        grant(t, a["name"], r.choice(admins), r.choice(["viewer", "operator", "developer"]), a["ip"], a["home"])
        emit(t + 300, ev(a["name"], "access", a["ip"], a["home"], r.choice(a["hosts"])))

    # attacks
    def aip():
        return f"203.0.113.{r.randint(1, 250)}"

    def new(ty, var, desc):
        inst.append(dict(type=ty, variant=var, desc=desc))
        return len(inst) - 1

    def start_t(h0=0, h1=24):
        return day_t(h0, h1)

    names = [u["name"] for u in users]
    ghosts = [f"ghost{j:03d}" for j in range(40)]

    def attempts(k, seq, srcs, t, lo, hi, succ):
        for j, name in enumerate(seq):
            ip, g = srcs[j % len(srcs)]
            emit(t, login(name, ip, g, name in U and r.random() < succ), k)
            t += r.uniform(lo, hi)
        return t

    for var in ("fast", "slow"):
        for _ in range(per_cell):  # brute force: many guesses, one account
            v, ip, g = r.choice(names), aip(), r.choice(cities)
            gap, n = (r.uniform(2, 5), r.randint(30, 80)) if var == "fast" else (r.choice([300, 900, 1800, 3600, 7200]), r.randint(4, 36))
            k, t = new("brute_force", var, f"{n} guesses on one account, 1 per ~{gap:.0f}s (spans {n * gap / 3600:.1f}h)"), start_t()
            for j in range(n):
                emit(t + j * gap + r.uniform(0, gap * 0.2), login(v, ip, g, False), k)
            if r.random() < 0.3:
                emit(t + (n + 1) * gap, login(v, ip, g, True), k)
                emit(t + (n + 1) * gap + 60, ev(v, "access", ip, g, r.choice(HOSTS)), k)
        for _ in range(per_cell):  # credential stuffing: many accounts, one try each
            m = min(r.randint(30, 80) if var == "fast" else r.randint(15, 30), len(names) + len(ghosts))
            rot = var == "slow" and r.random() < 0.5
            srcs = [(aip(), r.choice(cities)) for _ in range(3 if rot else 1)]
            lo, hi = (2, 6) if var == "fast" else (120, 300)
            k = new("credential_stuffing", var, f"{m} accounts, 1 try each, ~{(lo + hi) / 2:.0f}s apart, {len(srcs)} source(s)")
            attempts(k, r.sample(names + ghosts, m), srcs, start_t(), lo, hi, 0.03)
        for _ in range(per_cell):  # password spraying: one guess per account per round
            m = r.randint(25, 40) if var == "fast" else r.randint(20, 30)
            m, rounds = min(m, len(names)), 1 if var == "fast" else 2
            rot = var == "slow" and r.random() < 0.5
            srcs = [(aip(), r.choice(cities)) for _ in range(3 if rot else 1)]
            lo, hi = (60, 120) if var == "fast" else (600, 1200)
            k = new("password_spraying", var, f"{m} accounts x {rounds} round(s), ~{(lo + hi) / 2:.0f}s apart, {len(srcs)} source(s)")
            seq, t = r.sample(names, m), start_t(0, 12)
            for _ in range(rounds):
                t = attempts(k, seq, srcs, t, lo, hi, 0.03) + r.uniform(3600, 7200)

    trip_names = {users[i]["name"] for i in trips}
    vlog = defaultdict(list)
    for t, _, d, k in E:
        if (d["action"] == "login" and d["result"] == "success" and k == -1 and d["user"] in U
                and d["user"] not in trip_names and d["geo"] == U[d["user"]]["home"]):
            vlog[d["user"]].append((t, d["geo"]))
    for var in ("fast", "slow"):
        for _ in range(per_cell):  # impossible travel: valid-looking login from a far, never-seen city
            name = r.choice(sorted(vlog))
            t0, g0 = r.choice(vlog[name])
            c = r.choice([c for c in cities if c not in (g0, U[name]["vpn_city"]) and km(g0, c) >= (3000 if var == "fast" else 1500)])
            dist = km(g0, c)
            dt = r.uniform(600, 3600) if var == "fast" else max(900, dist / r.uniform(300, 1000) * 3600)
            ip = aip()
            k = new("impossible_travel", var, f"{dist:.0f} km in {dt / 60:.0f} min ({dist / (dt / 3600):.0f} km/h)")
            emit(t0 + dt, login(name, ip, c, True), k)
            emit(t0 + dt + r.randint(30, 600), ev(name, "access", ip, c, r.choice(HOSTS)), k)
        for _ in range(per_cell):  # privilege escalation: grant then first sensitive action
            a = pool.pop()
            actor = r.choice(admins) if r.random() < 0.7 else a["name"]
            gap = r.uniform(120, 900) if var == "fast" else r.uniform(4 * 3600, 30 * 3600)
            ip, t = aip(), start_t(8, 11)
            k = new("privilege_escalation", var, f"grant then first sensitive op {gap / 60:.0f} min later, actor={'self' if actor == a['name'] else 'admin'}")
            grant(t, a["name"], actor, r.choice(sorted({"admin", "secops", "dba"})), ip, a["home"], k)
            op_ev(t + gap, a["name"], ip, a["home"], k)
            if r.random() < 0.5:
                op_ev(t + gap + r.uniform(60, 300), a["name"], ip, a["home"], k)
        for _ in range(per_cell):  # off-hours admin activity
            a, ip = r.choice(admins), aip()
            if var == "fast":
                h, n, step = r.uniform(1, 4.5), r.randint(3, 6), r.uniform(120, 300)
            else:
                # slow: hugs the edges of the day, or hides inside business hours entirely
                h = r.choice([r.uniform(5.5, 7.0), r.uniform(17.0, 19.0), r.uniform(9, 16), r.uniform(9, 16)])
                n, step = r.choice([1, 1, 2]), 600
            k, t = new("offhours_admin", var, f"{n} sensitive op(s) starting {int(h)}:{int(h % 1 * 60):02d} UTC"), start_t(h, h)
            for j in range(n):
                op_ev(t + j * step, a, ip, U[a]["home"], k)

    E.sort(key=lambda x: (x[0], x[1]))
    labels = [dict(i, events=[]) for i in inst]
    for line, (_, _, _, k) in enumerate(E, 1):
        if k >= 0:
            labels[k]["events"].append(line)
    return [x[2] for x in E], labels


def write_jsonl(path, events):
    with open(path, "w", encoding="utf-8", newline="\n") as f:
        for e in events:
            f.write(json.dumps(e) + "\n")
