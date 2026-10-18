"""Rule-level behaviour: boundaries, explainability, baselines vs naive references."""
import random
import statistics

from seclog.detect import (Alert, merge, rule_brute, rule_hour_z, rule_many_users, rule_offhours,
                           rule_privesc, rule_spike, rule_travel)
from seclog.events import km


def evs(*rows):
    out = []
    for i, r in enumerate(rows, 1):
        d = dict(user="u1", action="login", result="success", src_ip="198.51.100.1", geo="Northvale", host="h")
        d.update(r)
        d["id"] = i
        out.append(d)
    return sorted(out, key=lambda e: (e["t"], e["id"]))


def fail(t, user="u1", ip="203.0.113.5"):
    return dict(t=t, user=user, result="failure", src_ip=ip)


def test_brute_alert_names_user_events_and_reason():
    out = rule_brute(evs(*[fail(i * 10, ip=f"203.0.113.{1 + i % 2}") for i in range(5)]), n=5, w=100)
    assert len(out) == 1
    subject, _t0, _t1, ids, why = out[0]
    assert subject == "u1" and ids == [1, 2, 3, 4, 5]
    assert "5 failed logins for u1" in why and "limit 5 per 100s" in why and "2 source(s)" in why


def test_brute_counts_per_user_and_ignores_successes():
    rows = [fail(i, user="a") for i in range(3)] + [fail(i, user="b") for i in range(3)]
    rows += [dict(t=i, user="a", result="success") for i in range(10)]
    assert rule_brute(evs(*rows), n=5, w=100) == []


def test_many_users_alert_explains_source_and_counts():
    rows = [fail(i, user=f"u{i}", ip="203.0.113.9") for i in range(6)]
    out = rule_many_users(evs(*rows), k=5, w=100, ratio=0.5)
    assert len(out) == 1 and out[0][0] == "203.0.113.9"
    assert "5 distinct users failed from 203.0.113.9" in out[0][4]


def test_many_users_office_nat_with_mostly_successes_is_quiet():
    rows = [dict(t=i, user=f"u{i}", result="success", src_ip="192.0.2.10") for i in range(40)]
    rows += [fail(100 + i, user=f"v{i}", ip="192.0.2.10") for i in range(6)]
    assert rule_many_users(evs(*rows), k=5, w=1000, ratio=0.5) == []


def travel_rows(speed, d=None):
    d = d or km("Northvale", "Eastmere")
    dt = d / speed * 3600
    return [dict(t=0, geo="Northvale"), dict(t=dt, geo="Eastmere")]


def test_travel_speed_threshold_is_strict():
    assert len(rule_travel(evs(*travel_rows(1001)), v=1000, min_km=300, seen_ok=1)) == 1
    assert rule_travel(evs(*travel_rows(999)), v=1000, min_km=300, seen_ok=1) == []


def test_travel_explanation_has_both_cities_and_speed():
    why = rule_travel(evs(*travel_rows(5000)), v=1000, min_km=300, seen_ok=1)[0][4]
    assert "Northvale" in why and "Eastmere" in why and "km/h > 1000" in why


def test_travel_min_distance_and_same_city_and_failures_ignored():
    assert rule_travel(evs(*travel_rows(5000)), v=1000, min_km=9000, seen_ok=1) == []
    same = [dict(t=0), dict(t=1)]
    assert rule_travel(evs(*same), v=1, min_km=0, seen_ok=1) == []
    rows = [dict(t=0, geo="Northvale"), dict(t=60, geo="Eastmere", result="failure"), dict(t=70, geo="Atlantis")]
    assert rule_travel(evs(*rows), v=1, min_km=0, seen_ok=1) == []


def test_travel_seen_ok_suppresses_habitual_vpn_city():
    rows = []
    for j in range(2):  # home, vpn, home, vpn ... minutes apart
        rows += [dict(t=j * 1000, geo="Northvale"), dict(t=j * 1000 + 500, geo="Highgate")]
    assert len(rule_travel(evs(*rows), v=1000, min_km=300, seen_ok=1)) == 1
    assert len(rule_travel(evs(*rows), v=1000, min_km=300, seen_ok=3)) == 3


def grant(t, role="admin", user="u1"):
    return dict(t=t, user=user, action="role_grant", role=role, actor="adm00")


def op(t, user="u1"):
    return dict(t=t, user=user, action="admin_action", op="create_api_key")


def test_privesc_window_boundary_is_inclusive():
    assert len(rule_privesc(evs(grant(0), op(3600)), w=3600)) == 1
    assert rule_privesc(evs(grant(0), op(3601)), w=3600) == []


def test_privesc_alert_explains_actor_role_and_delay():
    out = rule_privesc(evs(grant(0), op(120)), w=3600)
    assert out[0][3] == [1, 2]
    assert "granted admin by adm00" in out[0][4] and "120s later" in out[0][4]


def test_privesc_ignores_users_with_history_nonpriv_roles_and_reordering():
    assert rule_privesc(evs(op(-100), grant(0), op(10)), w=3600) == []
    assert rule_privesc(evs(grant(0, role="viewer"), op(10)), w=3600) == []
    assert rule_privesc(evs(op(0), grant(10)), w=3600) == []
    assert len(rule_privesc(evs(grant(0), op(10), op(20)), w=3600)) == 1


def test_offhours_boundaries_start_inclusive_end_exclusive():
    h = 3600
    assert rule_offhours(evs(op(7 * h)), start=7, end=19) == []
    assert len(rule_offhours(evs(op(7 * h - 1)), start=7, end=19)) == 1
    assert rule_offhours(evs(op(19 * h - 1)), start=7, end=19) == []
    assert len(rule_offhours(evs(op(19 * h)), start=7, end=19)) == 1


def test_offhours_ignores_non_admin_actions_and_merges_bursts():
    assert rule_offhours(evs(dict(t=3 * 3600)), start=7, end=19) == []
    h = 3600
    assert len(rule_offhours(evs(op(3 * h), op(4 * h)), 7, 19)) == 1  # exactly 1h apart: same burst
    assert len(rule_offhours(evs(op(3 * h), op(4 * h + 1)), 7, 19)) == 2


def test_hour_z_matches_naive_reference_on_random_histories():
    r = random.Random(5)
    for _ in range(60):
        hours = [r.choice([r.uniform(8, 17), r.uniform(8, 17), r.uniform(0, 24)]) for _ in range(r.randint(1, 40))]
        z, min_hist = r.choice([2, 3, 4]), r.choice([3, 5])
        events = evs(*[op(d * 86400 + h * 3600) for d, h in enumerate(hours)])
        got = sorted(i for a in rule_hour_z(events, z, min_hist) for i in a[3])
        hist, want = [], []
        for i, h in enumerate(hours, 1):
            x = h
            if len(hist) >= min_hist:
                m, sd = statistics.fmean(hist), max(statistics.pstdev(hist), 1.0)
                if abs(h - m) / sd > z:
                    want.append(i)
                    x = m + (z * sd if h > m else -z * sd)
            hist.append(x)
        assert got == want, (hours, z, min_hist)


def spike_events(counts):
    rows = []
    for b, c in enumerate(counts):
        rows += [fail(b * 3600 + j) for j in range(c)]
    return evs(*rows)


def ref_spike(counts, z, min_count, alpha=0.1):
    mean = var = 0.0
    first = next(i for i, c in enumerate(counts) if c)
    last = max(i for i, c in enumerate(counts) if c)
    hit = []
    for b in range(first, last + 1):
        c, sd = counts[b], max(var ** 0.5, 1.0)
        x = c
        if c >= min_count and c - mean > z * sd:
            hit.append(b)
            x = min(c, mean + z * sd)
        d = x - mean
        mean += alpha * d
        var = (1 - alpha) * (var + alpha * d * d)
    return hit


def test_spike_matches_naive_ewma_reference_on_random_counts():
    r = random.Random(3)
    for _ in range(80):
        counts = [r.choice([0, 0, 0, 1, 2, 5, 9]) for _ in range(r.randint(3, 60))] + [1]
        z, mc = r.choice([2, 3, 6]), r.choice([3, 5])
        got = [a[1] // 3600 for a in rule_spike(spike_events(counts), z, mc)]
        assert got == ref_spike(counts, z, mc), (counts, z, mc)


def test_spike_thresholds_are_strict_and_min_count_gates():
    ev8 = spike_events([8, 0])  # sd floor 1, mean 0: needs 8 > z
    assert len(rule_spike(ev8, z=7.99, min_count=8)) == 1
    assert rule_spike(ev8, z=8, min_count=8) == []
    assert len(rule_spike(ev8, z=2, min_count=8)) == 1
    assert rule_spike(ev8, z=2, min_count=9) == []


def test_spike_baseline_adapts_to_chronic_failures():
    out = rule_spike(spike_events([3] * 80), z=2, min_count=3)
    hours = [a[1] // 3600 for a in out]
    assert hours and max(hours) < 40 and len(hours) < 40  # alerts at first, then the baseline absorbs it


def test_merge_same_type_subject_combines_rules_and_takes_max_severity():
    a = Alert("r1", "brute_force", 2, "u1", 0, 10, [1, 2], "a")
    b = Alert("r2", "brute_force", 3, "u1", 3000, 3100, [2, 3], "b")
    m = merge([a, b])
    assert len(m) == 1 and m[0].severity == 3 and m[0].rules == ["r1", "r2"] and m[0].ids == [1, 2, 3]
    assert a.rules == ["r1"] and a.ids == [1, 2]  # inputs not mutated


def test_merge_keeps_different_types_subjects_and_distant_alerts_apart():
    a = Alert("r1", "brute_force", 2, "u1", 0, 10, [1], "a")
    assert len(merge([a, Alert("r2", "credential_stuffing", 2, "u1", 0, 10, [1], "b")])) == 2
    assert len(merge([a, Alert("r1", "brute_force", 2, "u2", 0, 10, [2], "b")])) == 2
    assert len(merge([a, Alert("r1", "brute_force", 2, "u1", 3611, 3700, [2], "b")])) == 2
    assert len(merge([a, Alert("r1", "brute_force", 2, "u1", 3610, 3700, [2], "b")])) == 1
