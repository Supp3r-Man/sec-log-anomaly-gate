"""Sliding-window primitives: exact boundaries, plus seeded property tests against naive references."""
import random

from seclog.detect import burst_triggers, many_users_windows


def ref_burst(ts, w, k):
    out, last = [], None
    for i, t in enumerate(ts):
        n = sum(1 for u in ts[:i + 1] if t - w <= u <= t)
        if n >= k and (last is None or t > last + w):
            out.append(i)
            last = t
    return out


def ref_many(items, w, k, ratio):
    out, last = [], None
    for i, (t, _u, _f, _i) in enumerate(items):
        win = [x for x in items[:i + 1] if t - w <= x[0] <= t]
        users = {x[1] for x in win if x[2]}
        nf = sum(1 for x in win if x[2])
        if len(users) >= k and nf >= ratio * len(win) and (last is None or t > last + w):
            out.append(i)
            last = t
    return out


def idx(pairs):
    return [i for _, i in pairs]


def test_burst_triggers_when_span_equals_window_exactly():
    assert idx(burst_triggers([0, 50, 100], 100, 3)) == [2]


def test_burst_does_not_trigger_one_second_too_wide():
    assert burst_triggers([0, 50, 101], 100, 3) == []


def test_burst_needs_k_events():
    assert burst_triggers([0, 1, 2], 100, 4) == []
    assert idx(burst_triggers([0, 1, 2], 100, 3)) == [2]


def test_burst_cooldown_is_strictly_after_window():
    # k=1: trigger at 0, event at exactly 0+w is suppressed, event at w+1 triggers again
    assert idx(burst_triggers([0, 100, 101], 100, 1)) == [0, 2]


def test_burst_matches_reference_on_random_sequences():
    r = random.Random(7)
    for _ in range(400):
        ts = sorted(r.randint(0, 120) for _ in range(r.randint(0, 25)))
        w, k = r.randint(0, 40), r.randint(1, 6)
        assert idx(burst_triggers(ts, w, k)) == ref_burst(ts, w, k), (ts, w, k)


def test_many_users_matches_reference_on_random_sequences():
    r = random.Random(11)
    for _ in range(400):
        ts = sorted(r.randint(0, 150) for _ in range(r.randint(0, 30)))
        items = [(t, f"u{r.randint(0, 7)}", r.random() < 0.7, j) for j, t in enumerate(ts)]
        w, k, ratio = r.randint(0, 60), r.randint(1, 5), r.choice([0.0, 0.5, 0.8, 1.0])
        got = [win[-1][3] for win in many_users_windows(items, w, k, ratio)]
        assert got == ref_many(items, w, k, ratio), (items, w, k, ratio)


def test_many_users_repeated_guesses_on_one_user_are_not_many_users():
    items = [(i, "victim", True, i) for i in range(50)]
    assert many_users_windows(items, 100, 2, 0.5) == []


def test_many_users_distinct_count_boundary():
    items = [(i, f"u{i}", True, i) for i in range(5)]
    assert len(many_users_windows(items, 100, 5, 0.5)) == 1
    assert many_users_windows(items, 100, 6, 0.5) == []


def test_many_users_failure_ratio_boundary():
    # 2 failing users + 2 successes = exactly 50% failing
    items = [(0, "c", False, 0), (1, "d", False, 1), (2, "a", True, 2), (3, "b", True, 3)]
    assert len(many_users_windows(items, 100, 2, 0.5)) == 1
    assert many_users_windows(items, 100, 2, 0.51) == []


def test_many_users_window_edge_is_inclusive():
    items = [(0, "a", True, 0), (100, "b", True, 1)]
    assert len(many_users_windows(items, 100, 2, 1.0)) == 1
    assert many_users_windows([(0, "a", True, 0), (101, "b", True, 1)], 100, 2, 1.0) == []
