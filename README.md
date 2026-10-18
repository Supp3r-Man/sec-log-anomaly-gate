# sec-log-anomaly-gate

![ci](https://github.com/Supp3r-Man/sec-log-anomaly-gate/actions/workflows/ci.yml/badge.svg)

A stdlib-only **attack detector for authentication/audit logs** that works as a cron or CI gate: sliding-window rules plus per-user statistical baselines (EWMA, z-score), **explainable alerts** (which rule, which event lines, why), thresholds **tuned on a dev split only** and reported on a **held-out split**, and a `scan` command whose exit code never lets an unreadable log look like a clean pass.

> **What is verified, and what is not.** 75 tests pass locally on Python 3.13 (stdlib only, plus pytest): window boundaries to the second, seeded property tests against naive reference implementations, and exit codes through a real subprocess. I also broke 10 behaviours on purpose (boundary operators, the first-time condition, the EWMA update, the bad-line limit, the exit-2 path) and the tests failed each time. **GitHub Actions has not run yet**, so no CI claim is made. **All data is synthetic**, produced by a generator I wrote, so the numbers below measure *my detectors against my own attack models*: they show the tuning and evaluation method works and where the rules break, not how this would do on real traffic, real attackers, or a real identity provider. 8 attack instances per cell means one missed attack moves a recall figure by 12 points.

## Measured results

`python -m seclog demo` (about 2 seconds). Thresholds are tuned per rule on the dev split (seed 11) with a budget of 0.5 false alerts per 1000 benign events per rule, then applied unchanged to a test split (seed 22) generated separately. Each split: about 10.9k events, 96 attack instances (6 types x fast/slow x 8).

Held-out TEST split, merged alerts (recall = attack instances detected / 8):

| attack type | fast | slow | precision | any-attack precision | alerts (tp / cross-type / false) |
|---|---|---|---|---|---|
| brute_force | 8/8 | 8/8 | 0.78 | 0.91 | 23 (18 / 3 / 2) |
| credential_stuffing | 8/8 | 3/8 | 0.58 | 1.00 | 19 (11 / 8 / 0) |
| password_spraying | 8/8 | 5/8 | 0.46 | 1.00 | 28 (13 / 15 / 0) |
| impossible_travel | 6/8 | 6/8 | 0.37 | 0.93 | 30 (11 / 17 / 2) |
| privilege_escalation | 8/8 | 6/8 | 0.67 | 0.67 | 21 (14 / 0 / 7) |
| offhours_admin | 8/8 | 5/8 | 0.39 | 0.55 | 33 (13 / 5 / 15) |

**Overall on TEST: 79/96 detected (fast 46/48, slow 33/48); 2.91 false alerts per 1000 benign events** (26 alerts that touch no attack event, 8949 benign events). On DEV, where the thresholds were fitted: 85/96 and 1.69 per 1000. The drop from dev to test is the honest cost of tuning on one sample.

How to read it: *precision* counts an alert as right only if it touches an attack of the type it claims. *Cross-type* alerts touched a real attack of another type (for example the many-users rules firing on each other's attacks, or impossible travel firing on the login a stuffing source made after guessing a password). *any-attack precision* counts those as right. *False* alerts touch no attack event at all.

### Which evasions get through (TEST)
- **Credential stuffing, slow (5 of 8 missed):** about one attempt every 3.5 minutes, 15-29 accounts, and in 4 of the 5 the attacker rotated across 3 source IPs. The per-source window never sees enough distinct users.
- **Password spraying, slow (3 of 8 missed):** all three rotated across 3 IPs, one try per account per ~15 minutes.
- **Privilege escalation, slow (2 of 8 missed):** the first sensitive action came 25-28 hours after the grant, past the 24-hour window.
- **Off-hours admin, slow (3 of 8 missed):** the attacker acted between 10:07 and 14:11 UTC, inside business hours; no hour-of-day rule can see that.
- **Impossible travel (4 missed):** two slow ones at 362 and 520 km/h look like an ordinary flight. Two *fast* ones were missed because an earlier attacker login from the same city (a stuffing success on the same victim) had taught the "city already seen for this user" suppression that it was normal. That is history poisoning, found by checking the misses, not planned.
- **Brute force:** all slow instances were caught here (4-36 guesses at up to 1 per 5 minutes) by an 8-guesses-in-24-hours rule. I did not generate an attacker below 8 guesses per day, which would pass; see Known gaps.
- The statistical baselines add little over the rules on this data: `stat_fail_spike` caught 1 slow brute force the rules also caught, and `offhours_z` caught 6/16 with 12 false alerts (the largest source of false alerts; with tiny per-user histories it is unstable).

## Run
```
python -m pip install pytest        # only for the tests
python -m pytest                    # 75 tests, about 6 seconds
python -m seclog demo               # tune on dev, print the tables above
python -m seclog gen --seed 3 --out sample.jsonl --labels sample_labels.json
python -m seclog scan sample.jsonl  # exit 0 clean / 1 alerts / 2 could not judge
python -m seclog scan log.jsonl --fail-on high --max-bad 5 --json
python -m seclog tune --out my_config.json    # re-tune; then: scan --config my_config.json
```
`scan` exit codes: **0** no alert at or above `--fail-on` (default `medium`); **1** at least one; **2** could not judge: file missing/unreadable/a directory, no parseable events, more than `--max-bad` (default 5) unparseable lines, invalid config, usage error, or any internal crash. Alerts found in a file that is too malformed are still printed, but the exit code is 2. Log lines are JSON objects with `ts` (ISO 8601), `user`, `action` (`login` needs `result` and `src_ip`; `role_grant` needs `role`; `admin_action` needs `op`).

## Layout
```
seclog/events.py   loading, validation, bad-line accounting, fictional geo table
seclog/gen.py      seeded generator: benign traffic + 12 attack variants, labels kept apart
seclog/detect.py   rules, EWMA / z-score baselines, alert merging
seclog/tune.py     metrics, dev-only grid search, report tables
seclog/config.py   config validation; default_config.json = output of `tune` on the dev split
seclog/cli.py      scan | gen | tune | demo
tests/             75 tests; STEPS.md has the build log and how to run it
```

## Known gaps
- Synthetic data from one generator and my own attacker models; both splits share the generator's habits, so dev-to-test generalisation is optimistic compared with real drift.
- Benign traffic is simple: UTC only, no time zones, no shared accounts, no password-reset storms, no scanners or health checks hammering a login page.
- Attackers do not adapt to the detectors. A real one probing for the thresholds would do better than my fixed slow variants.
- No cross-source aggregation: a stuffing run spread over many IPs, or many sources against one account, is only caught if one source or one account crosses a limit.
- Baselines are learned online from the start of the file with winsorized updates; a cold start (first days of a new account) is weak, and a patient attacker can still ramp a baseline up.
- The privilege rule only watches users with no earlier sensitive action; an attack on an existing admin is invisible to it. Attack setups for privilege and off-hours types have no preceding login.
- The 10 mutations are hand-picked, not a full mutation run; stats-heavy code (tuning objective) is covered mostly by regression tests on fixed seeds.
- Tuning picks the highest recall under the false-alert budget per rule; the combined system exceeds that budget (2.91 per 1000 on test) because nine rules each spend theirs.
