"""Metrics bookkeeping, dev-only tuning, config validation, and measured performance floors."""
import json

import pytest

from seclog.config import DEV_SEED, TEST_SEED, ConfigError, load_config, validate
from seclog.detect import Alert, detect_all
from seclog.events import parse_events
from seclog.gen import generate
from seclog.tune import evaluate, tune


def test_evaluate_separates_tp_cross_type_fp_and_variants():
    labels = [dict(type="brute_force", variant="fast", events=[1, 2]),
              dict(type="brute_force", variant="slow", events=[5])]
    alerts = [Alert("r", "brute_force", 3, "s", 0, 1, [2], "w"),
              Alert("r", "credential_stuffing", 3, "s", 0, 1, [5], "w"),
              Alert("r", "brute_force", 3, "s", 0, 1, [9], "w")]
    res = evaluate([None] * 10, labels, alerts)
    b = res["per"]["brute_force"]
    assert (b["alerts"], b["tp"], b["xt"], b["fp"]) == (2, 1, 0, 1)
    assert (b["detected"], b["total"], b["missed"]) == (1, 2, [1])
    assert b["variant"] == {"fast": (1, 1), "slow": (0, 1)}
    assert res["per"]["credential_stuffing"]["xt"] == 1
    assert res["benign"] == 7 and res["false_alerts"] == 1 and res["fa_per_1000"] == pytest.approx(1000 / 7)


@pytest.fixture(scope="module")
def full():
    dev_raw, dev_lab = generate(DEV_SEED)
    test_raw, test_lab = generate(TEST_SEED)
    dev, test = parse_events(dev_raw), parse_events(test_raw)
    cfg, rep = tune(dev, dev_lab)
    return dict(dev=dev, dev_lab=dev_lab, test=test, test_lab=test_lab, cfg=cfg, rep=rep)


def test_dev_and_test_splits_are_different_datasets(full):
    assert DEV_SEED != TEST_SEED
    assert [e["ts"] for e in full["dev"][:50]] != [e["ts"] for e in full["test"][:50]]


def test_tuning_respects_the_false_alert_budget_on_dev(full):
    for name, r in full["rep"].items():
        assert r["fp"] <= r["allowed"], name


def test_shipped_default_config_is_exactly_the_dev_tuning_output(full):
    assert load_config() == json.loads(json.dumps(full["cfg"]))


def test_tuning_is_deterministic(full):
    assert tune(full["dev"], full["dev_lab"])[0] == full["cfg"]


def test_detectors_ignore_everything_but_event_fields(full):
    noisy = [dict(e, _label="attack", label=1) for e in full["test"]]
    a = [x.to_dict() for x in detect_all(full["test"], full["cfg"])]
    assert a == [x.to_dict() for x in detect_all(noisy, full["cfg"])]


def test_held_out_performance_floors_and_evasions_exist(full):
    res = evaluate(full["test"], full["test_lab"], detect_all(full["test"], full["cfg"]))
    fast = sum(p["variant"]["fast"][0] for p in res["per"].values())
    slow = sum(p["variant"]["slow"][0] for p in res["per"].values())
    assert fast >= 42 and slow < fast  # obvious attacks caught; low-and-slow measurably evades
    assert res["fa_per_1000"] <= 5.0


def test_alerts_are_explainable_every_alert_has_rule_events_and_reason(full):
    for a in detect_all(full["test"], full["cfg"]):
        d = a.to_dict()
        assert d["rules"] and d["event_ids"] and len(d["why"]) > 20 and d["severity"] in ("low", "medium", "high")


GOOD = {"brute_fast": {"n": 8, "w": 300}}


@pytest.mark.parametrize("bad", [
    {}, [], {"nope": {"n": 1}}, {"brute_fast": {"n": 8}}, {"brute_fast": {"n": 8, "w": 300, "x": 1}},
    {"brute_fast": {"n": 8, "w": -1}}, {"brute_fast": {"n": True, "w": 300}}, {"brute_fast": {"n": 0, "w": 300}},
    {"brute_fast": {"n": 8, "w": "300"}}, {"stuffing_fast": {"k": 5, "w": 60, "ratio": 1.5}},
    {"offhours_rule": {"start": 9, "end": 9}}])
def test_config_validation_rejects_bad_configs(bad):
    with pytest.raises(ConfigError):
        validate(bad)


def test_config_validation_accepts_good_and_load_reports_unreadable(tmp_path):
    assert validate(GOOD) == GOOD
    with pytest.raises(ConfigError):
        load_config(str(tmp_path / "nope.json"))
    p = tmp_path / "bad.json"
    p.write_text("{not json")
    with pytest.raises(ConfigError):
        load_config(str(p))
