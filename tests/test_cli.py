"""Exit codes through a real subprocess: 0 clean, 1 alerts at/above the gate, 2 could not judge."""
import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def line(ts, user="usr001", ok=True, action="login", **kw):
    d = dict(ts=ts, user=user, action=action, src_ip="198.51.100.1", host="idp.example.test", geo="Northvale")
    if action == "login":
        d["result"] = "success" if ok else "failure"
    d.update(kw)
    return json.dumps(d)


CLEAN = [line("2026-03-03T10:00:00Z"), line("2026-03-03T11:00:00Z"), line("2026-03-03T12:00:00Z")]
ATTACK = [line(f"2026-03-03T10:00:{5 * i:02d}Z", ok=False, src_ip="203.0.113.9") for i in range(12)]
OFFHOURS = [line("2026-03-03T03:00:00Z", user="adm00", action="admin_action", op="create_api_key")]


def run(*args):
    return subprocess.run([sys.executable, "-m", "seclog", *args], cwd=ROOT, capture_output=True, text=True, timeout=120)


def scan(tmp_path, lines, *args, raw=None):
    p = tmp_path / "log.jsonl"
    p.write_bytes(raw if raw is not None else ("\n".join(lines) + "\n").encode())
    return run("scan", str(p), *args)


def test_clean_log_exits_0(tmp_path):
    r = scan(tmp_path, CLEAN)
    assert r.returncode == 0 and "verdict=clean" in r.stdout


def test_attack_log_exits_1_and_explains_rule_events_and_why(tmp_path):
    r = scan(tmp_path, ATTACK)
    assert r.returncode == 1
    assert "[HIGH] brute_force subject=usr001" in r.stdout and "brute_fast" in r.stdout
    assert "events=[1,2,3" in r.stdout and "why: " in r.stdout and "failed logins for usr001" in r.stdout


def test_missing_file_and_directory_exit_2_not_0(tmp_path):
    r = run("scan", str(tmp_path / "missing.jsonl"))
    assert r.returncode == 2 and "CANNOT JUDGE" in r.stderr
    assert run("scan", str(tmp_path)).returncode == 2


def test_empty_file_and_pure_garbage_exit_2(tmp_path):
    assert scan(tmp_path, [], raw=b"").returncode == 2
    assert scan(tmp_path, [], raw=b"\n\n").returncode == 2
    r = scan(tmp_path, ["garbage"] * 20)
    assert r.returncode == 2 and "bad_lines=20" in r.stdout


def test_bad_line_limit_boundary_default_is_5(tmp_path):
    ok = scan(tmp_path, CLEAN + ["junk"] * 5)
    assert ok.returncode == 0 and "bad_lines=5" in ok.stdout
    over = scan(tmp_path, CLEAN + ["junk"] * 6)
    assert over.returncode == 2 and "6 unparseable lines exceeds limit 5" in over.stderr
    assert scan(tmp_path, CLEAN + ["junk"] * 6, "--max-bad", "6").returncode == 0
    assert scan(tmp_path, CLEAN + ["junk"], "--max-bad", "0").returncode == 2


def test_alerts_found_in_a_file_that_is_too_malformed_still_exit_2_and_are_printed(tmp_path):
    r = scan(tmp_path, ATTACK + ["junk"] * 9)
    assert r.returncode == 2 and "brute_force" in r.stdout


def test_invalid_utf8_bytes_count_as_bad_lines(tmp_path):
    r = scan(tmp_path, [], raw=("\n".join(CLEAN) + "\n").encode() + b"\xff\xfe\x00\n")
    assert r.returncode == 0 and "bad_lines=1" in r.stdout


def test_fail_on_threshold_changes_exit_code_for_a_medium_alert(tmp_path):
    assert scan(tmp_path, OFFHOURS).returncode == 1  # default gate: medium
    r = scan(tmp_path, OFFHOURS, "--fail-on", "high")
    assert r.returncode == 0 and "alerts=1" in r.stdout and "at_or_above_high=0" in r.stdout
    assert scan(tmp_path, OFFHOURS, "--fail-on", "low").returncode == 1


def test_bad_config_exits_2(tmp_path):
    cfg = tmp_path / "c.json"
    cfg.write_text('{"brute_fast": {"n": 8}}')
    assert scan(tmp_path, CLEAN, "--config", str(cfg)).returncode == 2


def test_custom_config_changes_what_is_flagged(tmp_path):
    cfg = tmp_path / "c.json"
    cfg.write_text('{"brute_fast": {"n": 13, "w": 300}}')  # only 12 failures in the log
    assert scan(tmp_path, ATTACK, "--config", str(cfg)).returncode == 0


def test_json_output_is_machine_readable(tmp_path):
    r = scan(tmp_path, ATTACK, "--json")
    out = json.loads(r.stdout)
    assert r.returncode == 1 and out["verdict"] == "alerts" and out["bad_lines"] == 0
    a = out["alerts"][0]
    assert a["type"] == "brute_force" and a["severity"] == "high" and a["event_ids"][0] == 1 and a["why"]


def test_usage_error_exits_2():
    assert run().returncode == 2
    assert run("scan").returncode == 2
    assert run("scan", "x", "--max-bad", "-1").returncode == 2


def test_gen_then_scan_roundtrip_flags_attacks(tmp_path):
    log = tmp_path / "g.jsonl"
    g = run("gen", "--seed", "3", "--out", str(log), "--labels", str(tmp_path / "l.json"), "--users", "20", "--days", "7", "--per-cell", "2")
    assert g.returncode == 0 and "attack instances" in g.stdout
    r = run("scan", str(log))
    assert r.returncode == 1 and "[HIGH]" in r.stdout


def test_demo_small_prints_measured_table():
    r = run("demo", "--small")
    assert r.returncode == 0 and "TEST (held out" in r.stdout and "false alerts per 1000 benign events" in r.stdout
