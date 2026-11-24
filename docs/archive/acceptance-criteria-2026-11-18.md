# Archived: acceptance criteria as written on 18 November 2026

Kept for the audit trail. These fixed thresholds were replaced by comparative criteria
(each detector against the packet-rate rule and against no defense, Fisher's exact test
and Mann–Whitney U with the Holm correction, plus the 10 s detection limit) because the
thresholds of 95 %, 5 % and 90 % had no published source. The held-out runs and their
data are unchanged. Current text: `docs/thesis-campaign.md` §5 and
`docs/evaluation-protocol.md` §6.

## From `docs/thesis-campaign.md`

### 5. Acceptance criteria

Agreed with the directors before the held-out runs. They are **outcomes**, not settings:
the lab measures them, the operator cannot set them. Each is read from a column of the
Results-tab row (`held_out_rows.csv`) and summarized per cell by `compare_runs.py`.

| Criterion | Meaning in plain words | Column | Measurable here? |
|---|---|---|---|
| DR ≥ 95 % | Of every 100 attackers (counted once per run), at least 95 are named by the detector at least once during the attack. | `tp`, `fn` per row → `detection_rate_pct` in the report | Yes. 2–4 attackers × 10 runs = 20–40 attackers per cell, so the Wilson interval is wide; report it. |
| FAR ≤ 5 % | Of every 100 legitimate hosts (counted once per run), at most 5 are wrongly named. | `fp`, `tn` per row → `false_alarm_rate_pct` in the report | Yes, about 20 legitimate hosts × 10 runs = 200 per cell. Only with the light lab traffic (no flash crowd): a stated limitation. |
| Detection ≤ 10 s | On average, an attacker is named at most 10 s after the attack starts. | `mean_detection_s` | Yes. It cannot be below about two polling intervals (a rate needs two polls). |
| Availability ≥ 90 % | During the attack, at least 90 of every 100 website checks succeed, and more than without defense. | `availability_attack_pct` | Yes, 1 check per second. |

Recovery time is reported but has no acceptance criterion.


## From `docs/evaluation-protocol.md` §6

Acceptance thresholds are agreed with the supervisors **before** the held-out runs and written
in the test plan. Suggested starting values: DR ≥ 0.95; FAR ≤ 0.05; average detection time
≤ 10 s; legitimate availability during the attack ≥ 90 % with a response and greater than with
no defense; service recovery ≤ 30 s; zero responses against protected hosts.
