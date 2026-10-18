"""Loader (bad lines are counted, never swallowed) and generator (determinism, fictional data only)."""
import ipaddress
import json
import re

import pytest

from seclog.events import LogUnreadable, km, load_events, parse_ts
from seclog.gen import TYPES, generate, write_jsonl

GOOD = '{"ts":"2026-03-03T10:00:00Z","user":"usr001","action":"login","result":"success","src_ip":"198.51.100.1"}'
SMALL = dict(n_users=20, days=7, per_cell=2)


def write(tmp_path, data, name="log.jsonl"):
    p = tmp_path / name
    p.write_bytes(data if isinstance(data, bytes) else data.encode())
    return str(p)


def test_loader_counts_each_kind_of_bad_line_with_physical_line_numbers(tmp_path):
    lines = [GOOD, "not json", "[1,2]", '{"ts":"2026-03-03T10:00:00Z","user":"u","action":"login","result":"maybe","src_ip":"x"}',
             '{"ts":"yesterday","user":"u","action":"access"}', '{"ts":"2026-03-03T10:00:00Z","action":"access"}',
             '{"ts":"2026-03-03T10:00:00Z","user":"u","action":"login","result":"failure"}',
             '{"ts":"2026-03-03T10:00:00Z","user":"u","action":"role_grant"}', GOOD]
    out = load_events(write(tmp_path, "\n".join(lines) + "\n"))
    assert [e["id"] for e in out.events] == [1, 9]
    assert out.bad == [2, 3, 4, 5, 6, 7, 8] and out.total == 9


def test_loader_blank_lines_are_ignored_but_do_not_shift_ids(tmp_path):
    out = load_events(write(tmp_path, "\n" + GOOD + "\n\n" + GOOD + "\n"))
    assert [e["id"] for e in out.events] == [2, 4] and out.bad == [] and out.total == 2


def test_loader_invalid_utf8_line_is_bad_not_crash(tmp_path):
    out = load_events(write(tmp_path, GOOD.encode() + b"\n\xff\xfe\x00garbage\n"))
    assert len(out.events) == 1 and out.bad == [2]


def test_loader_sorts_by_time_and_handles_offsets_and_naive_timestamps(tmp_path):
    a = GOOD.replace("10:00:00Z", "12:00:00+02:00")  # same instant as 10:00Z
    b = GOOD.replace("10:00:00Z", "09:59:59")  # naive: treated as UTC
    out = load_events(write(tmp_path, "\n".join([a, GOOD, b])))
    assert [e["id"] for e in out.events] == [3, 1, 2]
    assert parse_ts("2026-03-03T10:00:00Z") == parse_ts("2026-03-03T12:00:00+02:00")


def test_loader_unreadable_paths_raise(tmp_path):
    with pytest.raises(LogUnreadable):
        load_events(str(tmp_path / "missing.jsonl"))
    with pytest.raises(LogUnreadable):
        load_events(str(tmp_path))


def test_km_known_distance_is_plausible():
    assert 5400 < km("Northvale", "Eastmere") < 5700 and km("Northvale", "Northvale") == 0


@pytest.fixture(scope="module")
def small():
    return generate(5, **SMALL)


def test_generation_is_deterministic_and_seed_sensitive(small):
    assert generate(5, **SMALL) == small
    assert generate(6, **SMALL)[0] != small[0]


def test_every_ip_is_in_a_documentation_range_and_hosts_are_fictional(small):
    nets = [ipaddress.ip_network(n) for n in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24")]
    for e in small[0]:
        assert any(ipaddress.ip_address(e["src_ip"]) in n for n in nets), e
        assert e["host"].endswith(".example.test")


def test_no_card_ssn_or_email_shapes_anywhere(small):
    blob = "\n".join(json.dumps(e) for e in small[0])
    assert not re.search(r"\b\d{13,16}\b", blob) and not re.search(r"\b\d{3}-\d{2}-\d{4}\b", blob) and "@" not in blob


def test_labels_cover_every_type_and_variant_and_ids_are_valid_lines(small):
    events, labels = small
    assert len(labels) == len(TYPES) * 2 * SMALL["per_cell"]
    assert {(lab["type"], lab["variant"]) for lab in labels} == {(t, v) for t in TYPES for v in ("fast", "slow")}
    for lab in labels:
        assert lab["events"] and all(1 <= i <= len(events) for i in lab["events"])


def test_log_has_no_label_leak_and_attacker_ips_match_labels_exactly(small):
    events, labels = small
    assert all(not ({"label", "attack", "labels"} & set(e)) for e in events)
    attack = {i for lab in labels for i in lab["events"]}
    from_attacker = {i for i, e in enumerate(events, 1) if e["src_ip"].startswith("203.0.113.")}
    assert from_attacker == attack


def test_events_are_time_sorted_and_round_trip_through_the_loader(small, tmp_path):
    events, _ = small
    p = tmp_path / "g.jsonl"
    write_jsonl(p, events)
    loaded = load_events(str(p))
    assert loaded.bad == [] and len(loaded.events) == len(events)
    assert [e["id"] for e in loaded.events] == list(range(1, len(events) + 1))
