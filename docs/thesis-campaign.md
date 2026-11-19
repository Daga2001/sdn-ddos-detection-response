# Final campaign of the thesis

The runs reported in chapter 4 of the final report. `scripts/campaign/lab_campaign.py`
sends exactly the request the workspace sends, waits for each run and keeps its full
record; nobody has to touch the forms. This guide can be handed to a person or a QA agent.

Every value has a reason; the **Basis** column says which. Where no standard prescribes
a value, it says so.

## 1. What runs

18 cells × 10 held-out runs = **180 runs**, about **12.8 h** if setup and teardown take
60 s per run (measure it with the smoke test of section 3; `--dry-plan` prints the estimate).

| Batch | Cells (scenario ids) | Runs | Time | Answers |
|---|---|---|---|---|
| 1 | `TH1-none` `TH2-none` `TH2pf-none` `TH3-none` `TH3-rule` `TH3-entropy` `TH3-llm` | 70 | ~5.0 h | SO1 (H1) and SO3 (H2–H4) on one case |
| 2 | `TH4-none` `TH4-rule` `TH4-entropy` `TH4-llm` `TH5-none` `TH5-rule` `TH5-entropy` `TH5-llm` | 80 | ~5.7 h | two victims; low rate (H3) |
| 3 | `TH2-rule` `TH2-entropy` `TH2-llm` | 30 | ~2.1 h | detectors under per-port saturation |

Run the batches in this order. Each batch is complete on its own (10 runs per cell), so
if the day ends after batch 1 or 2, the finished batches are reportable and the rest is
future work. Do not stop a batch in the middle.

## 2. Where it runs

On the **lab VM described in the report** (section 3.3.1: VMware Workstation VM with
4 virtual cores and 6 GB of RAM on the Ryzen 5 7600 / RTX 5060 computer; Ollama on that
host's GPU). Two reasons:

* **Safety.** The runner container is privileged and loads Open vSwitch networks into
  the host kernel. The README forbids running it on a shared or production machine.
* **Validity.** The report states the cost of every decision (CPU, memory, time) on
  that hardware. Runs on another machine, or next to unrelated containers, measure
  something else and cannot be pooled with the report's description.

Before starting, check on that machine (a QA agent can do every check except the
`sudo` line, which a person types):

| Check | Command | Expected |
|---|---|---|
| No unrelated containers | `docker ps --format '{{.Names}}'` | only `sdn-ddos-detection-response-*` (or nothing yet) |
| Disk and `/tmp` | `df -h / /tmp /var/lib/docker` | several GB free on each |
| Open vSwitch kernel module | `sudo modprobe openvswitch` (person), then `make lab-doctor` | doctor passes |
| Model on the host | `ollama list` on the host | `llama3.2:3b` present |

## 3. Commands (on the lab VM, repository root)

```bash
git pull
test -f .env || cp .env.example .env
make lab-setup                                  # local credentials (kept if present)
docker compose up -d --wait postgres
docker compose exec -T postgres psql -U sdn_user -d sdn_monitor \
  -v ON_ERROR_STOP=1 < database/migrations/002_lab.sql   # safe to repeat
make lab-doctor                                 # after `sudo modprobe openvswitch`
docker compose up -d && curl -fsS http://localhost:8080/health   # {"status":"ready"}
set -a; . ./.env; set +a
export SDN_GIT_COMMIT=$(git rev-parse HEAD)
# the runner refuses to start if it cannot reach the lab runner container
# (sdn-ddos-detection-response-runner-1; override with SDN_LAB_RUNNER_CONTAINER)

# smoke test: one TC-1 and one LLM run; check both finish "completed" and note wall_s
PYTHONPATH=src python3 scripts/campaign/lab_campaign.py TH1-none TH3-llm --poll 1 \
    --records records/smoke --out smoke.jsonl

# freeze: write the date-time and commit into the report (3.5.4)
date -Iseconds; git rev-parse HEAD

# batch 1 (use tmux so a closed terminal does not stop it)
PYTHONPATH=src python3 scripts/campaign/lab_campaign.py --poll 1 --rounds 10 --seed 2026 \
    --records records/held_out --out held_out.jsonl \
    TH1-none TH2-none TH2pf-none TH3-none TH3-rule TH3-entropy TH3-llm
# batch 2 (seed 2027) and batch 3 (seed 2028): same command with their ids

# results: one row per run, then the statistics
(cd web && node --experimental-strip-types scripts/result_rows.ts ../records/held_out/*.json) > held_out_rows.csv
python3 scripts/compare_runs.py held_out_rows.csv --frozen-at <freeze time> --out held_out_report.md
```

Without Node on the VM: `docker run --rm -v "$PWD":/w -w /w/web node:24-bookworm-slim node --experimental-strip-types scripts/result_rows.ts ../records/held_out/*.json > held_out_rows.csv`.

**Send back for the report:** `held_out_rows.csv`, `held_out_report.md`, `held_out.jsonl`,
`smoke.jsonl`, the freeze lines, and the `versions` event of one run (report Appendix B).

**A run marked `valid = no`** is dropped by `compare_runs.py` and listed; do not re-run it
by hand. Report how many were dropped. **If a batch stops** (power cut), re-run it with
`--rounds` = the rounds still missing and a new seed.

## 4. Design and its basis

| Decision | Value | Basis |
|---|---|---|
| Repetitions | 10 held-out runs per cell | RFC 8456 §4.7 (SHOULD ≥ 10). `compare_runs.py` flags cells with fewer. |
| Order | randomized complete blocks: each round runs every cell of the batch once, new random order per round, recorded seed | NIST/SEMATECH e-Handbook §5.3.3.2; Jain (1991). |
| Phases | baseline, attack, recovery in every run | RFC 8456 §5.3.2 (without and with load); NIST SP 800-115 (planned, documented tests). |
| Arms | no defense, packet-rate rule, entropy, LLM | no defense = reference (H4); the rule = the LLM prompt's own decision rule (Arp et al. 2022, appropriate baseline). |
| Frozen settings, one fingerprint per cell | no pilot or calibration runs: polling and detector settings come from development measurements | Arp et al. 2022 (data snooping). |
| Polling | 1 s for every arm | Development: availability during a 3-attacker flood 100 % at 1 s, 37 % at 2 s, 26–37 % at 5 s (report Appendix C). |
| Durations | baseline 75 s, attack 60 s, recovery 60 s (all cases) | No standard prescribes them. Baseline = 30 s entropy warm-up + the 40 s margin used by the lab's campaigns + 5 s; attack = detection ≤ 10 s, two confirmations, 50 more website checks; recovery = the controller's 60 s idle timeout, so per-port rules of the flood can expire within the run. |
| Entropy | fast-reaction preset: 1 s windows, normalised Shannon entropy, k-sigma EWMA band (k = 2.5, α = 0.2), 30 warm-up windows, 2 windows to alarm | Makes the warm-up fit the 75 s baseline. Normalised entropy as in Ding et al. (2022). |
| LLM | `llama3.2:3b`, prompt `lab`, 5 samples per poll, threshold 0.8 | 5 ≥ the largest number of attackers (4). Threshold fixed in advance (not tuned on reported runs). |
| Rule | 50 pkt/s, 5 samples per poll | the prompt's attack threshold. |
| TC-1 table limit | 1 500 rules in table 0 of every switch, refuse when full | Open vSwitch has no small default limit; 1 500 = HP ProCurve 5406zl hardware table (Kuźniar et al., PAM 2015). |
| Statistics | Wilson 95 % intervals for DR and FAR; mean, Student-t 95 % interval, median for times; Mann–Whitney U and rank-biserial r | Wilson (1927); Brown, Cai, DasGupta (2001); Mann & Whitney (1947). |

## 5. Acceptance criteria (outcomes, not settings)

| Criterion | Meaning | Column |
|---|---|---|
| DR ≥ 95 % | of every 100 attackers (once per run), at least 95 are named during the attack | `tp`, `fn` → `detection_rate_pct` |
| FAR ≤ 5 % | of every 100 legitimate hosts (once per run), at most 5 are wrongly named | `fp`, `tn` → `false_alarm_rate_pct` |
| Detection ≤ 10 s | mean time from attack start to first naming of an attacker | `mean_detection_s` |
| Availability ≥ 90 % | during the attack, ≥ 90 of every 100 website checks succeed, and more than without defense | `availability_attack_pct` |

## 6. Response: values and what would happen otherwise

* **Block**, not rate limit: a 50 pkt/s limit would leave TC-5 (30 pkt/s) untouched.
* **2 detections within 30 s**: one detection blocked two legitimate clients in
  development; the count-in-a-window design is Snort's `detection_filter`, Suricata's
  `threshold`, fail2ban's `maxretry`/`findtime`. With independent per-poll error *p* and
  1 s polling, a false block needs two namings in 30 s: ≈ 435 *p*² instead of
  1 − (1 − *p*)³⁰ (4 % instead of 26 % for *p* = 1 %). Cost: one more poll.
* **300 s**: longer than every attack, so an attacker is not released mid-attack.
* **Never the servers** (10.0.0.1–10.0.0.5): a victim's replies have the flood's rate;
  blocking it would be a self-inflicted denial of service.
* **Not a dry run**: a dry run cannot show the effect on availability.

## 7. Form fields, for a run started by hand

| Form (label) | API field | Value |
|---|---|---|
| Topology | `topology` | `scripts/campaign/topologia_universidad.json` |
| Forwarding | `forwarding` | Per-port for TC-1 and TC-2; Port-free otherwise |
| Attackers | `attackers` | TC-1/TC-2/TC-2pf/TC-5: h_wifi1, h_lab1. TC-3: h_wifi1, h_lab1, h_prof1. TC-4: h_wifi1, h_wifi2, h_lab1, h_lab2 |
| Victims / HTTP service | `victims` | h_web; TC-4: h_web, h_files |
| Traffic kind | `traffic` | SYN; TC-3, TC-4: SYN and UDP |
| Rate · packets/s | `rate` | 1000; TC-5: 30 |
| Baseline / Attack / Recovery · seconds | | 75 / 60 / 60 |
| Run purpose | `purpose` | Held-out (reported) |
| Test case | `scenario` | TC-1, TC-2, TC-2pf, TC-3, TC-4, TC-5 |
| Flow-table limit · rules | `flow_table_limit` | 1500 for TC-1; empty otherwise |
| Detector | `detection.mode` | Off / Packet-rate rule / Entropy / LLM |
| Poll every · s | `poll_seconds` | 1 |
| Model; Prompt profile | | llama3.2:3b; lab |
| Samples per poll | `llm_max_samples` | 5 |
| Attack probability ≥ | `threshold` | 0.8 |
| Attack at ≥ pkt/s | `rule_pktrate` | 50 |
| Entropy | `entropy` | window 1 s, warm-up 30, consecutive 2, measure norm, rest default |
| Apply a response to detected attackers | `mitigation` | on, except no defense |
| Policy; Detections needed; Within · s; Block lasts · s | | Block; 2; 30; 300 |
| Never act on · addresses | `protected` | 10.0.0.1–10.0.0.5 |
| Simulation only (dry run) | `dry_run` | off |
