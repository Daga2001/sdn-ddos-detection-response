# Final campaign of the thesis

This is the procedure for the runs reported in the final report (chapters 3 and 4).
It was followed on 18–19 Nov 2026; section 0 records what happened.
It runs unattended: `scripts/campaign/lab_campaign.py` sends exactly the request the
workspace sends, waits for each run, and keeps its full record. Nothing has to be typed
into the forms during the campaign; the table at the end says what each form field is
set to, for a run started by hand.

Every value below has a reason. The **Basis** column names the standard or the
measurement it comes from. Where no standard prescribes a value, it says so.

## 0. What was run (18–19 Nov 2026)

| Step | Record |
|---|---|
| Machine | the VMware VM of the report (section 3.3.1) |
| Pilot `TP` | 27 runs (`records/pilot`, `pilot.jsonl`). The rule of section 4 chose **1 s**: at 5 s entropy named its first attacker after 11.5–16.8 s; at 0.5 s the LLM arm kept 42–65 % availability with 15–16 false positives per run; at 1 s every detector met both criteria (100 % availability). |
| Calibration `TC` | 12 runs, 6 on TC-3 and 6 on TC-5 (`records/calibration`). No setting changed afterwards. |
| Freeze | 2026-11-18T14:11:20Z, commit `fee8ae6` (branch `campana-18nov`, PR #39) |
| Held-out `TH` | 170 runs, 10 rounds. Seeds 2026 (rounds 1–4, the last completed with seed 2030), 2031, 2032 and 2033. 4 runs failed (TH2-llm, TH4-llm, TH5-llm, TH5-rule). |
| Completion | one extra round of those four cells, and TC-1, from `main` (section 2b) |

## 1. Order of work and time

| Step | Group | Runs | Machine time | Purpose |
|---|---|---|---|---|
| 0 | smoke | 2 | 20 min | the lab, Ollama and the scripts work on the VM |
| 1 | `TP` pilot | 27 | 3.6 h | choose the polling interval (0.5, 1 or 5 s) |
| 2 | `TC` calibration | 12 | 1.9 h | check the frozen LLM and entropy settings at that interval |
| 3 | freeze | – | – | record date, commit and settings fingerprints |
| 4 | `TH` held-out | 170 | 24.7 h | the reported runs: 17 cells × 10 rounds |
| 5 | analysis | – | 1 h | rows, statistics, tables of chapter 4 |

The times assume 60 s of setup and teardown per run; `--dry-plan` prints the estimate,
and the `wall_s` field of the output shows the real value. A run cannot go faster than
its phases: the emulation runs in real time.

## 2. Commands

On the VM, in the repository root, with the lab up (README, "Run the lab": `make lab-setup`,
the migration, `make lab-doctor`, `docker compose up -d`) and the model pulled
(`ollama pull llama3.2:3b` on the host):

```bash
git pull
set -a; . ./.env; set +a
export SDN_GIT_COMMIT=$(git rev-parse HEAD)   # recorded with every run

# 0. smoke test: one LLM run and one rule run, no randomization
PYTHONPATH=src python3 scripts/campaign/lab_campaign.py TP3-llm TP3-rule --poll 1 \
    --records records/smoke --out smoke.jsonl

# 1. pilot: 3 detectors x 3 intervals x 3 rounds, random order inside each round
PYTHONPATH=src python3 scripts/campaign/lab_campaign.py --group TP --poll 0.5,1,5 \
    --rounds 3 --seed 1 --records records/pilot --out pilot.jsonl

# rows of the Results tab, then the statistics (pilot runs only)
(cd web && node --experimental-strip-types scripts/result_rows.ts ../records/pilot/*.json) > pilot_rows.csv
python3 scripts/compare_runs.py pilot_rows.csv --purpose pilot --out pilot_report.md
```

Choose the interval with the rule of section 4, then (`P` = the chosen interval):

```bash
# 2. calibration (LLM and entropy on TC-3 and TC-5)
PYTHONPATH=src python3 scripts/campaign/lab_campaign.py --group TC --poll P \
    --rounds 3 --seed 7 --records records/calibration --out calibration.jsonl

# 3. freeze: write down the date and time, the commit and the fingerprints
date -Iseconds; git rev-parse HEAD

# 4. held-out campaign (about 25 h; run it inside tmux so it survives a closed terminal)
tmux new -s campaign
PYTHONPATH=src python3 scripts/campaign/lab_campaign.py --group TH --poll P \
    --rounds 10 --seed 2026 --records records/held_out --out held_out.jsonl

# 5. analysis
(cd web && node --experimental-strip-types scripts/result_rows.ts ../records/held_out/*.json) > held_out_rows.csv
python3 scripts/compare_runs.py held_out_rows.csv --frozen-at <freeze time> \
  --out held_out_cells.csv > held_out_report.md   # --out: one CSV row per cell; the report is stdout
```

Without Node on the VM, step 5 runs in the web image's base:
`docker run --rm -v "$PWD":/w -w /w/web node:24-bookworm-slim node --experimental-strip-types scripts/result_rows.ts ../records/held_out/*.json > held_out_rows.csv`.

**If the campaign stops** (power cut, VM restart): every finished run is already in
`records/` and `held_out.jsonl`. Count the finished rounds, and start again with the
same command and a new `--seed`, with `--rounds` set to the rounds still missing. Because
every round holds every cell once, the cells stay balanced.

**A run is not counted** when its row says `valid = no` (`validity_notes` says why);
`compare_runs.py` drops it and lists it. Do not delete it and do not re-run it in its
place by hand: the next round gives the cell its next run. Report how many were dropped.

## 2b. Completing the campaign (after the 170 runs)

Both additions run from `main` (merge of `campana-18nov`, PR #40). On `main`, the
cells of the 170 runs give the same settings fingerprints and phases as recorded
(checked for every cell of the extra round). The code that differs from `fee8ae6` is
off for these runs: the optional cloud backend and the flow-table limit, which only
TC-1 uses. The lab bakes the code into its images, so rebuild them first:

```bash
git checkout main && git pull
docker compose up -d --build
set -a; . ./.env; set +a; export SDN_GIT_COMMIT=$(git rev-parse HEAD)

# 1. extra round of the four cells with 9 valid runs (about 35 min)
PYTHONPATH=src python3 scripts/campaign/lab_campaign.py --poll 1 --rounds 1 --seed 2034 \
  --records records/held_out_extra --out held_out_extra.jsonl \
  TH2-llm TH4-llm TH5-llm TH5-rule

# 2. TC-1: table 0 of every switch limited to 1 500 rules, 10 runs (about 80 min)
PYTHONPATH=src python3 scripts/campaign/lab_campaign.py --poll 1 --rounds 10 --seed 2035 \
  --records records/held_out_tc1 --out held_out_tc1.jsonl TH1-none
```

The report states that these 20 runs used the commit of `main`, not `fee8ae6`.

## 3. Design and its basis

| Decision | Value | Basis |
|---|---|---|
| Repetitions per cell | 10 held-out runs | RFC 8456 §4.7: a test SHOULD be repeated at least 10 times. `compare_runs.py` flags cells with fewer. |
| Order of runs | randomized complete blocks: each round runs every cell once, in a new random order (seeded) | Randomization and blocking against drifts of the machine: NIST/SEMATECH e-Handbook of Statistical Methods §5.3.3.2; Jain (1991), experimental design. The seed makes the order reproducible. |
| Without and with attack in each run | baseline, attack, recovery phases | RFC 8456 §5.3.2 measures without and with load; NIST SP 800-115 asks for planned, documented tests. |
| Arms | no defense, packet-rate rule, entropy, LLM | The no-defense arm is the reference for H4; the rule is the baseline that the LLM's prompt describes (Arp et al. 2022: an appropriate baseline). |
| Calibration separated from held-out | settings frozen before the held-out runs; only `held_out` runs reported; one settings fingerprint per cell | Arp et al. 2022 (data snooping). `compare_runs.py --frozen-at` refuses runs before the freeze. |
| Proportions | DR and FAR pooled over the runs of a cell, Wilson 95 % interval | Wilson (1927); Brown, Cai and DasGupta (2001) recommend it over the normal interval for small n. |
| Continuous metrics | mean with Student-t 95 % interval, median and range | Jain (1991), ch. 13. |
| Comparisons | two-sided Mann–Whitney U, rank-biserial effect size | Non-parametric: no normality assumed with 10 runs per cell. |
| Phase durations | baseline 180 s, attack 120 s (TC-5: 300 s), recovery 120 s | No standard prescribes them. Baseline: entropy warm-up 16 windows × 5 s = 80 s plus margin; the service baseline needs ≥ 10 checks. Recovery needs 10 answered checks in a row. TC-5 is longer because a low rate takes longer to accumulate evidence. |
| Polling interval | chosen by the pilot (rule below) | Development runs: availability during a 3-attacker flood 26–37 % at 5 s, 100 % at 1 s (report, Appendix C). |
| Response | block, after 2 detections within 30 s, 300 s, never the five servers, real (not dry run) | See section 5. |

## 4. Pilot rule (stated before the pilot)

Among 0.5, 1 and 5 s, choose the **largest** interval at which, in all pilot runs,
every detector (rule, entropy, LLM) names its first attacker within 10 s and the website
availability during the attack is at least 90 %. Larger is preferred because every poll
costs controller CPU. If no interval meets both, choose the one with the highest median
availability and report that the criterion was not met.

## 5. Acceptance criteria

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

## 6. Response: why these values, and what would happen otherwise

* **Block** (not rate limit): a 50 pkt/s limit would leave TC-5 (30 pkt/s) untouched and
  still let 50 SYN/s per source through. Escalation adds 20 s of rate limiting before the
  block. The same policy is used for every detector, so the policy is not a factor.
* **2 detections within 30 s**: in development, acting on the first detection blocked two
  legitimate clients after a single false alarm (report, Appendix C). The same count-in-a-
  window design is used by Snort's `detection_filter`, Suricata's `threshold` and
  fail2ban's `maxretry`/`findtime`. If a legitimate host were wrongly named in a poll with
  probability *p*, independently, with 1 s polling, the chance of two namings in 30 s is
  about 435 *p*² instead of 1 − (1 − *p*)³⁰ (for *p* = 1 %: 4 % instead of 26 %). The
  independence is an assumption: a host that is misjudged in every poll is still blocked.
  The cost is one more poll before the block (about 1 s at 1 s polling). Three detections
  would add another poll for a smaller gain; a 10 s window could miss attackers that the
  sample budget does not judge in every poll.
* **300 s**: longer than every attack (120 s, 300 s), so an attacker is not released in
  the middle of it. A wrongly blocked host loses the service for up to 300 s, which is why
  the confirmation exists. fail2ban's default ban is 10 minutes.
* **Never the servers** (10.0.0.1–10.0.0.5): a victim's replies to a flood have the
  flood's rate, so a per-flow detector can name the victim; blocking it would be a
  self-inflicted denial of service (seen with entropy in development, Appendix C).
* **Real, not dry run**: a dry run only records, so it cannot show the effect on
  availability.

## 7. What each form field is set to

For a run started by hand from the workspace (for example to look at one cell). The
campaign sets the same values through the API.

| Form (label) | API field | Value |
|---|---|---|
| Topology | `topology` | load `scripts/campaign/topologia_universidad.json` |
| Forwarding | `forwarding` | Per-port for TC-2; Port-free for TC-2pf, TC-3, TC-4, TC-5 |
| Attackers | `attackers` | TC-2/TC-2pf/TC-5: h_wifi1, h_lab1. TC-3: h_wifi1, h_lab1, h_prof1. TC-4: h_wifi1, h_wifi2, h_lab1, h_lab2 |
| Victims / HTTP service | `victims` | h_web; TC-4: h_web and h_files |
| Traffic kind | `traffic` | SYN; TC-3 and TC-4: SYN and UDP (spread over the attackers in order) |
| Rate · packets/s | `rate` | 1000 per attack flow; TC-5: 30 |
| Baseline · seconds | `baseline` | 180 |
| Attack · seconds | `duration` | 120; TC-5: 300 |
| Recovery · seconds | `recovery` | 120 |
| Run purpose | `purpose` | Pilot / Calibration / Held-out (reported) |
| Test case | `scenario` | TC-2, TC-2pf, TC-3, TC-4, TC-5 (pilot: TC-3-poll0.5 etc.) |
| I confirm these hosts belong to my isolated lab. | `confirm_isolated_lab` | checked |
| Detector | `detection.mode` | Off / Packet-rate rule / Entropy / LLM |
| Poll every · s | `detection.poll_seconds` | the interval chosen by the pilot |
| Model | `detection.model` | llama3.2:3b (LLM) |
| Prompt profile | `detection.prompt` | lab |
| Samples per poll | `detection.llm_max_samples` | 5 (LLM and rule): at least the largest number of attackers (4) |
| Attack probability ≥ | `detection.threshold` | 0.8 (LLM) |
| Attack at ≥ pkt/s | `detection.rule_pktrate` | 50 (rule): the prompt's attack threshold |
| Entropy presets | `detection.entropy` | defaults (original preset: Shannon, k = 2.5, α = 0.2, 5 s windows, 16 warm-up windows, 2 consecutive windows) |
| Apply a response to detected attackers | `mitigation` | on, except the no-defense arm |
| Policy | `detection.response.policy` | Block |
| Detections needed | `detection.response.confirm_hits` | 2 |
| Within · s | `detection.response.confirm_seconds` | 30 |
| Block lasts · s | `detection.response.block_seconds` | 300 |
| Never act on · addresses | `detection.response.protected` | 10.0.0.1, 10.0.0.2, 10.0.0.3, 10.0.0.4, 10.0.0.5 |
| Simulation only (dry run) | `detection.response.dry_run` | off |

## References

* RFC 8456, Benchmarking Methodology for SDN Controller Performance (2018), §4.7, §5.3.2.
* NIST SP 800-115, Technical Guide to Information Security Testing and Assessment (2008).
* NIST/SEMATECH e-Handbook of Statistical Methods, §5.3.3.2 Randomized block designs,
  https://www.itl.nist.gov/div898/handbook/pri/section3/pri332.htm
* R. Jain, The Art of Computer Systems Performance Analysis, Wiley, 1991.
* D. Arp et al., Dos and Don'ts of Machine Learning in Computer Security, USENIX Security 2022.
* E. B. Wilson, Probable inference, the law of succession, and statistical inference, JASA 1927;
  L. D. Brown, T. T. Cai, A. DasGupta, Interval estimation for a binomial proportion, Stat. Sci. 2001.
* Snort 2.9 manual, `detection_filter`; Suricata user guide, thresholding; fail2ban `jail.conf`
  (`maxretry`, `findtime`, `bantime`).
* hping3(8): the source port is increased for each packet unless `--keep` is given.
