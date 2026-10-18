# STEPS

**Part A** is what I did, in order. **Part B** is how you run it.

---

## Part A: steps taken

1. **Chose the shape:** a gate, not a dashboard. One question per run (is there an alert at or above a severity?) with three honest answers: 0 clean, 1 alerts, 2 could not judge. Everything else (generator, tuning, tables) exists to justify the thresholds behind that exit code.
2. **Wrote the loader first** (`seclog/events.py`): every bad line (not JSON, not an object, missing user/action/ts, login without result or src_ip) is counted with its physical line number. Blank lines are ignored but keep their numbers, so event ids are stable line numbers.
3. **Wrote the generator** (`seclog/gen.py`): 60 fictional users, 6 admins (3 on call), office NAT, VPN-exit geo noise, 4 real trips (a trip takes distance/450-650 km/h plus 2 hours), 2 service accounts with token-expiry failure bursts, benign grants (on-call elevation, onboarding a new admin, ordinary roles). IPs only from 192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24. Labels are returned separately; the log has no label field.
4. **Injected 6 attack types x fast/slow x 8**: brute force, credential stuffing, password spraying, impossible travel, privilege escalation, off-hours admin. Slow variants are meant to sit under thresholds (lower rates, rotating sources, long gaps, hiding in business hours).
5. **Wrote the detectors** (`seclog/detect.py`): sliding-window primitives with an inclusive window and a strict cooldown, then nine rules; two are statistical per-user baselines (EWMA of hourly failures, z-score of an admin's hour of day) with winsorized updates. Every alert carries rule, event ids, and a reason string.
6. **Wrote tuning and evaluation** (`seclog/tune.py`): per rule, grid search on the dev split only; among settings within a false-alert budget, maximise detected instances. Alerts are scored as true, cross-type (a real attack of another type), or false.
7. **Wrote the CLI and config validation**, then ran the whole thing and shipped `default_config.json` from the dev-only tuning output.
8. **Wrote 75 tests** in five files: windows (10), rules (19), loader/generator (12), eval/config (20, 11 of them parametrized config cases), CLI through a real subprocess (14). Property tests compare the window code, the hour z-score, and the EWMA against naive references on seeded random inputs.
9. **Mutation-checked** 10 behaviours on a fresh copy each time (script in my scratchpad, prints PATTERN MISSED if the text is absent). All 10 were killed on the first run.
10. **Wrote the README from the real `demo` output**, then committed locally. Pushed to both accounts; CI passed on Python 3.11 and 3.13.

Problems and choices along the way:
- First run was too easy: about 95/96 recall on dev. My slow attacks were not slow enough. I slowed them (stuffing 2-5 minutes per try, spraying 10-20 minutes, privilege gap up to 30 hours, off-hours hiding inside business hours, brute force at up to 1 per 2 hours) and re-tuned. The numbers in the README are from after that change; I had not seen test-split results when choosing the new speeds beyond the first demo run, which printed both splits, so treat the test split as lightly exposed.
- A junk conditional (`... if False else ...`) and a dead assignment slipped into the first draft of the generator; caught on re-reading.
- Two of my tests were wrong, not the code: a ratio-boundary test where the window fired earlier than I assumed, and a "baseline adapts" test with z=3 where a count of 3 can never alert (floor sd 1, strict inequality).
- Checked why two fast impossible-travel attacks were missed: an earlier attacker login from the same city had made that city look familiar for the victim (history poisoning). Left as a documented evasion.
- The test count (75) is above the 35-45 I was aiming for because boundaries and CLI paths each got their own test.

---

## Part B: steps for you

1. Needs Python 3.11 or newer; no packages except pytest for the tests.
2. From the repo folder: `python -m pytest` (about 6 seconds).
3. `python -m seclog demo` prints the tuned thresholds, the dev and test tables, the missed attacks and per-rule results.
4. Try the gate: `python -m seclog gen --seed 3 --out sample.jsonl --labels sample_labels.json`, then `python -m seclog scan sample.jsonl` and `echo $?` (PowerShell: `$LASTEXITCODE`). You should see 1 and alerts that name the rule, the event line numbers, and why.
5. Try the failure paths: scan a missing file, an empty file, or a file with 6+ junk lines; each exits 2. `--max-bad 6` allows six.
6. Wire it up: in cron or CI run `python -m seclog scan path/to/auth.jsonl --fail-on high` and treat 2 as a failure too, not as "no alerts".
7. Re-tune on your own labelled dev data with `python -m seclog tune --out cfg.json`, then `scan --config cfg.json` (the tune command here only uses the built-in generator; wiring your own labels in is a gap).
8. When pushing: add the repo, push, and look at the first CI run before claiming anything about CI.
