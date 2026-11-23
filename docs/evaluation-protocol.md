# Evaluation protocol for the detection and response system

This is the test standard for the thesis results chapter. It fixes **what is measured, how,
how often and how it is reported** before any result is looked at, so the LLM, the entropy
detector and the no-defense baseline are compared on equal terms. It implements the
evaluation the proposal promises (sections 2.2.8, 2.2.9, 3.4.1 and 3.4.2, Table 3.1,
equations 2 to 9) and states where the lab cannot yet do what the proposal says.

Scope and rules of engagement: every test runs only inside the isolated Mininet lab
(`SECURITY.md`). No test targets a real, campus or third-party network.

## 1. Normative basis

The protocol does not try to comply with every framework. It borrows one well-known source
for each decision it has to justify.

| Decision | Source | What is taken from it |
| --- | --- | --- |
| Phases of a security test and rules of engagement | NIST SP 800-115, *Technical Guide to Information Security Testing and Assessment* (2008) | Planning → execution → post-execution; written scope and authorization; evidence handling. The proposal already cites it (section 3.4.2) but it is missing from its bibliography. |
| Controls each test exercises | NIST SP 800-53 Rev. 5 (2020) | SC-5 (DoS protection), SI-4 (system monitoring), AU-2/AU-12 (event logging), CA-2 (assessments), CA-7 (continuous monitoring), CA-8 (penetration testing). |
| Detect / respond / recover timing | NIST CSF 2.0 (2024) and SP 800-61 Rev. 3 (2025) | DE.CM, DE.AE (detection), RS.MI (mitigation), RC.RP (recovery): time to detect, time to respond, time to recover. |
| Controller benchmarking under DoS, trial count, report format | IETF RFC 8455 / RFC 8456 (2018), *Benchmarking Methodology for SDN Controller Performance* | §5.3.2 *Handling Denial-of-Service Attacks*: the same measurements **without and with** the attack, attack type and interface stated; §4.7: each test repeated **at least 10 times**; average and variance reported. |
| Network metric definitions | IETF IPPM: RFC 2681 (round-trip delay), RFC 7680 (loss), RFC 3393 (delay variation); RFC 2544 (benchmarking methodology) | Ping RTT, loss and jitter as defined there; trial durations and reporting conventions. |
| Classifier metrics | ISO/IEC TS 4213:2022, *Assessment of machine learning classification performance* | Confusion matrix as the primary result, derived metrics, stated unit of analysis, confidence intervals, data provenance and splits. |
| Quality characteristics | ISO/IEC 25010:2023 and ISO/IEC 25059:2023 (quality model for AI systems) | Functional correctness, time behaviour, resource utilization, availability, recoverability, robustness. |
| Test documentation | ISO/IEC/IEEE 29119-3:2021 | Test plan, test case specification, test log, incident report, test completion report (section 8). |

## 2. Units of analysis and ground truth

Ground truth is the experiment definition, never the detector's output: the hosts set as
attackers are positives, the legitimate clients are negatives, the victim is reported apart.
The attack window is bounded by the recorded `attack_started` / `attack_stopped` events.

| Unit | Positive | Negative | Where it is computed |
| --- | --- | --- | --- |
| **Host per run** (primary) | attacker named at least once | legitimate client never named | Results tab |
| **Judged flow sample** (LLM) | attacker's flow during the attack phase | legitimate client's flow, or attacker's flow during the baseline | Results tab (*per-flow* rows), `scripts/evaluate_live_detection.py` |
| **Entropy window** | window inside the attack phase | window inside the baseline | `scripts/replay_entropy.py` |
| **Labeled sample set** (offline) | `label = 1` | `label = 0` | `scripts/compare_llms.py` (also Brier and output consistency) |

Always state the unit next to a number: a 98 % per-flow accuracy and a 50 % per-host detection
rate can come from the same run.

## 3. Metric catalogue

All of these appear in the Results tab for every experiment run, whatever the detector, and
are exported with **Download results row (CSV)** (one row per run, the same columns for every
detector) or **Download all metrics (CSV)** (one line per value, with its definition).
*Proposal* is where the metric is defined. C1–C6 measure the cost of each decision, which
is the new part of this work.

| ID | Metric | Definition | Proposal | ISO/IEC 25010/25059 |
| --- | --- | --- | --- | --- |
| M1 | Confusion matrix | TP, FN, FP, TN in the stated unit | §2.2.7, §3.4.1 | functional correctness |
| M2 | Detection Rate | TP / (TP + FN) | eq. 2–3 | functional correctness |
| M3 | False Alarm Rate | FP / (FP + TN) | eq. 7 | functional correctness |
| M4 | Precision, Accuracy, F1 | eq. 4–6 | eq. 4–6 | functional correctness |
| M5 | Average attack detection time | mean over detected attackers of (first naming − attack start) | §2.2.9.1 | time behaviour |
| M6 | Early Detection Rate (EDR) | attackers named ≤ **10 s** after the attack start / all attackers | §2.1.6 (horizon fixed here) | time behaviour |
| M7 | Confidence calibration | Brier score; ECE over 10 equal-width bins of P(attack) | §3.4.1 | robustness / transparency |
| M8 | Output consistency | share of repeated queries on the same window with the same verdict (offline, `--repeats ≥ 5`) | §3.4.1 | robustness |
| N1 | Latency | mean ping RTT per phase; degradation (attack − baseline) / baseline | §2.2.9.2, §3.4.1 | time behaviour |
| N2 | Packet loss | lost / sent pings per phase; degradation in **percentage points** | §3.4.1 | availability |
| N3 | Legitimate service availability | HTTP 200 checks / checks per phase | §1.5, §3.4.1 | availability |
| N4 | Legitimate request time | median website-check time per phase | §3.4.1 | time behaviour |
| N5 | Bandwidth | iperf `-u` goodput and datagram loss between legitimate pairs | §2.2.9.3 | capacity |
| S1 | Controller CPU / RAM | psutil of the Ryu process per phase (mean, peak) | §2.2.9.4 | resource utilization |
| S2 | Data-plane CPU | `ovs-vswitchd` CPU per phase | §3.4.1 | resource utilization |
| S3 | Controller throughput | Packet-Ins handled per second | §3.4.1 | capacity |
| S4 | Flow-table growth | (attack peak − baseline mean) rules / seconds to the peak | §3.4.1 | capacity |
| R1 | Response time | first response against an attacker − attack start | §1.5, §3.2.2 | time behaviour |
| R2 | Detection-to-response delay | R1 − first naming | §3.2.2 | time behaviour |
| R3 | Collateral responses | legitimate clients or victims acted on | §2.1.5 | functional correctness |
| R4 | Mitigation effectiveness | 1 − (victim packets/s ≥ 10 s after the response) / (victim packets/s before it) | §3.4.2 | effectiveness |
| T1 | Service recovery time | t_stable − t_stop; several victims: max(t_stable,i) − t_stop | eq. 8, eq. 9 | recoverability |
| T2 | Controller recovery time | t_stable − t_stop on Ryu CPU and Packet-In rate | eq. 8 | recoverability |
| C1 | Time per decision | time the controller waits for the detector / decisions (mean, median, 95th percentile); LLM: one flow sample sent to the model, entropy: one window | §1.5 (cost efficiency) | time behaviour |
| C2 | Decisions per second | decisions in the attack phase / its length; capacity = 1000 / median C1 | §1.5 | capacity |
| C3 | Detector CPU time per decision | CPU time the detector service's request threads spent deciding (thread CPU time: waiting for Ollama, health checks and other requests are not counted) / decisions | §1.5 | resource utilization |
| C4 | Detector CPU and memory | detector-service process CPU % per phase and peak memory (its own `GET /usage`) | §1.5 | resource utilization |
| C5 | Cached and skipped decisions | LLM verdicts reused for identical samples; switch polls replaced before the model judged them | §3.2.1 | capacity |
| C6 | Service lifetime under attack | seconds from the attack start to the first failed website check (in the no-defense arm, how long the service lasts) | §1.5 | availability |

GPU use, GPU memory and power on the computer that runs Ollama are not measured; with the LLM,
C3 and C4 describe the detector service only, not the model's own computation.

Degradation of a rate whose baseline is usually 0 (loss, failed checks) is reported in
percentage points; a relative change would divide by zero.

## 4. Experimental design

**Factors.** Detector {off, rule, entropy, LLM}, response {off, dry run, block, rate_limit,
escalate}, forwarding {per_port, port_free}, attack kind {SYN, UDP, ICMP}, rate, number of
attackers and victims, topology.

**Mandatory comparison arms** for every scenario:

1. **No defense** (detector off): the reference for N1–N4, S1–S4, T1–T2 and C6, as RFC 8456
   §5.3.2 requires (same measurements without and with the defense).
2. **Rule-only baseline** (detector `rule`, implemented): `pktrate ≥ 50 packets/s` applied
   to the same flow samples, with the same sample budget, order, cache and response. The
   `lab` prompt instructs the model to decide only on that threshold, so without this arm the
   contribution of the LLM cannot be separated from that of the rule.
3. **Entropy** and **LLM**, each alone (implemented). They are tested separately, not
   combined (decision of 28 Oct 2026). Classical ML detectors (Random Forest, XGBoost) are
   future work (decision of 8 Nov 2026).

**Repetitions.** At least **10 runs per cell** (RFC 8456 §4.7), in randomized order, with the
run order, seed and repository commit recorded. Run the no-defense arm in the same session as
the defended arms.

**Data separation.** Prompt examples and entropy calibration use a
*calibration* set of runs; every reported number comes from *held-out* runs recorded after the
settings were frozen. Each run records why it was made (*Run purpose* in the Experiment
panel: `exploration`, `pilot`, `calibration`, `held_out`), its test case label (e.g. `TC-2`),
a **settings fingerprint** (SHA-256 of the detector settings and the forwarding choice,
`lab/provenance.py`), the repository commit and, with the LLM, the SHA-256 of the prompt
text, the Ollama version and the model's digest and quantization. Freezing means writing
the fingerprint of the chosen settings in the test plan; a held-out run with another
fingerprint, or recorded before the freeze, is not counted (`scripts/compare_runs.py`
refuses to pool it). The current `lab` prompt examples come from the same sessions as its
evaluation set (`docs/detection-modes.md`); repeat that evaluation on new runs.

## 5. Test cases

Each test case is one row of the proposal's Table 3.1. The *lab today* column states what the
current runner can do; deviations must be reported, not hidden.

| ID | Proposal scenario | Setup | Stop condition | NIST SP 800-53 | Lab today |
| --- | --- | --- | --- | --- | --- |
| TC-0 | (implicit) benign load and flash crowd | legitimate traffic only, then a burst of legitimate requests from many clients | fixed 10 min | SI-4 | no flash-crowd generator yet: FAR under benign bursts is untested |
| TC-1 | §3.4.2.1 DDoS to switch | per_port forwarding, SYN/UDP floods with varied ports, OVS `flow_limit` set so the table can fill | table full or > 50 % legitimate loss | SC-5, SI-4 | needs an explicit `flow_limit` on the bridge; spoofed sources not generated |
| TC-2 | §3.4.2.2 DDoS to controller | per_port forwarding, floods that miss the table (new flows), 2 attackers | > 50 % legitimate loss or 5 min | SC-5, CA-7 | supported (≤ 1 000 packets/s per attacker, ≤ 300 s) |
| TC-3 | §3.4.2.3 single-host DDoS | 3 attackers (2 SYN + 1 UDP) → 1 victim | 10 min attack | SC-5, SI-4 | attack ≤ 300 s: run 2 × 300 s or raise the cap after review |
| TC-4 | §3.4.2.4 multi-host DDoS | 4 attackers → 2 victims (SYN to web, UDP to database) | 10 min attack | SC-5, SI-4 (see section 7 about SC-36, CP-7) | rate cap 1 000 packets/s per attacker (proposal: up to 10 000) |
| TC-5 | §3.4.2.5 low-rate saturation | 2 attackers at 100 packets/s constant | 60 min attack | SI-4, AU-2 | attack ≤ 300 s; requires an extended bounded mode |

Every test case runs: 300 s baseline (proposal), attack, 300 s recovery. A test is **valid**
only if the baseline reached the detector's warm-up (entropy needs ≥ 120 s), no `gap` event
dropped `detection`/`mitigation_requested` events, and the run was not interrupted
(`stop_requested`).

## 6. Statistics and acceptance criteria

`scripts/compare_runs.py` computes everything below from the Results tab's
*Download results row (CSV)* files (one per run, or stacked): it keeps valid `held_out`
runs (optionally only those after `--frozen-at`), groups them into cells (test case,
forwarding, detector, response, traffic, attackers, rate), refuses a cell whose runs have
different settings fingerprints, flags cells with fewer than 10 runs, and writes a
Markdown report plus one summary row per cell (`--out`).

* Continuous metrics (M5, N1, N4, S1–S4, R1, R2, T1, T2): mean and 95 % confidence interval
  (Student t) over runs, plus median and range.
* Proportions (M2, M3, M6, N2, N3): pooled counts over runs with a **Wilson** 95 % interval;
  never average per-run percentages of a handful of hosts.
* Defended vs no-defense, same scenario: Wilcoxon signed-rank on runs paired by order, or
  Mann–Whitney U if not paired; report the effect size.
* Two detectors on the same labeled samples (offline replay): McNemar's test.
* Calibration: reliability diagram plus Brier and ECE, on held-out samples only.
* Acceptance criteria (`acceptance` in `src/sdn_ddos/analysis/compare.py`, report section
  *Acceptance criteria*, `--criteria-out` for every test): in each scenario every detector is
  compared with the packet-rate rule (detection rate and false-alarm rate with Fisher's exact
  test on the pooled counts, mean detection time with Mann–Whitney U) and, where the service
  was lost without defense, with no defense (availability during the attack, Mann–Whitney U).
  The p-values of one scenario are Holm-adjusted together and compared with α = 0.05; the mean
  detection time must also be at most 10 s. No step draws random numbers, so the same rows
  always give the same report.

The criteria compare each detector with references measured in the same scenario (the
packet-rate rule and no defense) rather than with fixed thresholds: see
`docs/thesis-campaign.md` §5. Zero responses against protected hosts is enforced by the
code (README decision 16). The earlier fixed thresholds are kept in
`docs/archive/acceptance-criteria-2026-11-18.md`.

## 7. Known gaps between the proposal and the lab

These limit what the results chapter can claim until they are closed or the proposal is
amended.

1. **Decision rule.** The proposal mitigates only when entropy *and* the LLM agree (section
   3.2.2); the lab runs one detector per run and never combines them.
2. **Polling.** The proposal polls every 30 s while criticizing 30 s polling in Ahuja and Singal
   (section 2.2.4); the lab uses 5 s and shows that 1–2 s is needed for floods that degrade the
   service within about 10 s (`docs/detection-modes.md`).
3. **OpenFlow version.** The proposal says OpenFlow 1.0; meters for rate limiting need
   OpenFlow 1.3, which is what the lab uses.
4. **Persistent blacklist.** The proposal escalates to a persistent blacklist after 3
   detections in 5 minutes; every lab response expires (`block_seconds` ≤ 24 h).
5. **Traffic generation.** No spoofed or randomized sources, no progressive stressing,
   ≤ 1 000 packets/s per attacker and ≤ 300 s per attack. The proposal asks for spoofed
   sources, +10 Mb/s every 30 s, up to 10 000 packets/s per device and 60-minute attacks. With
   spoofed sources a per-source drop rule stops nothing; port-level mitigation would be needed.
6. **Bandwidth.** No iperf `-u` stream is run, so N5 is not measured.
7. **Features.** The LLM receives six flow features; the proposal lists flow duration, TCP
   flags and source/destination entropy as model inputs (section 3.2.1).
8. **Controls without an implementation.** SC-36 (distributed processing) and CP-7 (alternate
   processing site) are attached to TC-4, but the lab runs a single controller. Either add a
   second controller or cite only the controls actually exercised.

## 8. Documentation (ISO/IEC/IEEE 29119-3)

| Document | Where |
| --- | --- |
| Test plan (scope, factors, arms, thresholds, schedule) | a dated copy of sections 4–6 with the agreed thresholds, in `docs/decisions/` |
| Test case specification | section 5 of this file and `scripts/campaign/scenarios.py` |
| Test log | one `docs/templates/experiment-record.md` per session, plus the run id and the exported metrics CSV of each run |
| Incident report | failed or interrupted runs, `gap` events, tool errors, with their run ids |
| Test completion report | the results chapter: tables of section 3 with intervals, the comparison tests, deviations from section 7 |
