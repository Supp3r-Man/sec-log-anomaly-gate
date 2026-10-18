"""Log loading and validation. Anything that cannot be judged is counted, never silently dropped."""
import json
import math
from collections import namedtuple
from datetime import datetime, timezone

SEVERITY = {"low": 1, "medium": 2, "high": 3}
SEV_NAME = {v: k for k, v in SEVERITY.items()}
RESULTS = ("success", "failure")

# Fictional cities (name -> lat, lon). Distances are what matter for the travel rule.
CITIES = {
    "Northvale": (40.7, -74.0), "Eastmere": (51.5, -0.1), "Southport": (-33.9, 151.2),
    "Westbrook": (37.8, -122.4), "Highgate": (35.7, 139.7), "Lowfield": (19.1, 72.9),
    "Midlands": (52.5, 13.4), "Rivergate": (-23.5, -46.6),
}


def km(a, b):
    (la1, lo1), (la2, lo2) = CITIES[a], CITIES[b]
    p1, p2 = math.radians(la1), math.radians(la2)
    h = math.sin((p2 - p1) / 2) ** 2 + math.cos(p1) * math.cos(p2) * math.sin(math.radians(lo2 - lo1) / 2) ** 2
    return 2 * 6371.0 * math.asin(math.sqrt(h))


class LogUnreadable(Exception):
    pass


Loaded = namedtuple("Loaded", "events bad total")


def parse_ts(s):
    if not isinstance(s, str):
        raise ValueError("ts must be a string")
    d = datetime.fromisoformat(s.replace("Z", "+00:00"))
    if d.tzinfo is None:
        d = d.replace(tzinfo=timezone.utc)
    return d.timestamp()


def iso(t):
    return datetime.fromtimestamp(t, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _need_str(o, k):
    if not isinstance(o.get(k), str) or not o[k]:
        raise ValueError(f"missing or bad {k}")


def parse_line(raw, lineno):
    o = json.loads(raw)
    if not isinstance(o, dict):
        raise ValueError("not an object")
    _need_str(o, "user")
    _need_str(o, "action")
    t = parse_ts(o.get("ts"))
    if o["action"] == "login":
        if o.get("result") not in RESULTS:
            raise ValueError("login needs result success|failure")
        _need_str(o, "src_ip")
    elif o["action"] == "role_grant":
        _need_str(o, "role")
    elif o["action"] == "admin_action":
        _need_str(o, "op")
    o["t"], o["id"] = t, lineno
    return o


def parse_events(raw):
    """Trusted in-memory events (from the generator): add t and id (= line number)."""
    return [dict(e, t=parse_ts(e["ts"]), id=i) for i, e in enumerate(raw, 1)]


def load_events(path):
    """Returns Loaded(events sorted by time, bad line numbers, non-blank line count)."""
    try:
        f = open(path, "rb")
    except OSError as e:
        raise LogUnreadable(f"cannot open {path}: {e}") from e
    ev, bad, total = [], [], 0
    with f:
        try:
            for lineno, raw in enumerate(f, 1):
                if not raw.strip():
                    continue
                total += 1
                try:
                    ev.append(parse_line(raw.decode("utf-8-sig"), lineno))
                except Exception:  # any per-line problem means that line could not be judged
                    bad.append(lineno)
        except OSError as e:
            raise LogUnreadable(f"read error on {path}: {e}") from e
    ev.sort(key=lambda e: (e["t"], e["id"]))
    return Loaded(ev, bad, total)
