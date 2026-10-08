# Detection modes: LLM vs entropy

The controller `src/sdn_ddos/controller/app_modes.py` runs **one** detector per
run, chosen by the user. They are never combined so their behaviour can be
compared.

| `SDN_DETECTION_MODE` | Detector | Where it runs |
| --- | --- | --- |
| `llm` (default) | Flow-level LLM verdict (Llama 3.2 3B by default) | Controller -> `llm_api` (:8001) -> Ollama on the Windows host |
| `entropy` | Network-wide Shannon entropy of source/destination IPs | Inside the controller |
| `off` | None (metrics only) | - |

Every decision is stored in `detection_decisions` (`detector` column) so both
mechanisms can be compared with the same queries. Metrics and flows keep going
to the baseline tables.

## Run

```bash
# controller + detector, then open the topology in another terminal
scripts/run_detection.sh entropy          # or llm | off
scripts/start_topology.sh

# or a full baseline -> attack -> recovery experiment
scripts/run_experiment.sh entropy         # or llm
python scripts/report_experiment.py logs/experiment_entropy_<timestamp>.json
```

The attack is the repo's bounded launcher (<= 1000 pkt/s per attacker, private
addresses, `--confirm-isolated-lab`), run between Mininet hosts only.

## Detector service (graphical lab)

In the Docker lab both detectors live in **one separate container**, `detector`
(`src/sdn_ddos/detection/service.py`, `compose.detector.yaml`). The runner talks
to it through the contract it already knows (`/predict`, `/health`); only the
*active* mode answers, the other detector's route returns 409.

```bash
bash scripts/lab_detector.sh up            # lab (web/runner/inference) + detector
bash scripts/detector.sh status            # active mode/model and Ollama health
bash scripts/detector.sh models            # models installed in Ollama
bash scripts/detector.sh set --mode llm --model qwen2.5:3b
bash scripts/detector.sh set --mode entropy
bash scripts/detector.sh set --prompt lab                      # insdn | lab
bash scripts/detector.sh set --response escalate --dry-run false   # block | rate_limit | escalate
bash scripts/lab_detector.sh down
```

Experiments can be driven without the browser through the lab's own API:

```bash
python3 scripts/lab_runs.py --rate 1000 --kind syn --baseline 40 --duration 30 \
    --recovery 20 [--mitigation] [--repeat N] [--tag NAME]
bash scripts/last_run_report.sh [run_id]   # phases, who was flagged, decisions
```

* The mode is read by the controller when a run starts (Observe/Start), so
  change it *between* runs. `ryu-modes.sh` makes the runner start
  `controller/app_modes.py` instead of the baseline controller.
* Entropy state is kept per lab run id inside the service; restarting the
  container resets `/config` to the env values and the warm-up.
* The container needs the `egress` network to reach Ollama on the Windows host
  (`SDN_LLM_OLLAMA_URL`, default `http://192.168.83.1:11434`); the model is
  pre-loaded on start/change because a cold load exceeds the call timeout.
* Decisions are written by the controller to `detection_decisions` in the lab
  PostgreSQL (`postgres` container, no Neon). Fresh databases get the table
  from `database/schema.sql`; apply
  `database/migrations/001_detection_decisions.sql` to a database created before.
* Safe lab defaults: prompt `lab` and `SDN_RESPONSE_DRY_RUN=true`, so a mitigated
  run records what it *would* do and enforces nothing. `detector.sh status` then
  shows `"prompt": "lab"` and `"dry_run": true`. Enable enforcement explicitly
  (`detector.sh set --dry-run false`) once a run's decisions have been reviewed.
* Calibration: the lab baseline is only HTTP probes (~5 packets/s network-wide),
  so the container defaults `SDN_ENTROPY_MIN_RATE` to 2 (standalone: 20). With
  such a sparse baseline the adaptive band is wide: k=3 did **not** raise an
  alarm in a 20 s, 1000 pkt/s SYN flood, while k=1 with a 60 s flood did. Give
  entropy a richer baseline or tune `SDN_ENTROPY_K`/`SDN_ENTROPY_CONSECUTIVE`.
* The LLM is deterministic (temperature 0, fixed seed), so the controller caches
  verdicts by the features the model sees (`SDN_LLM_CACHE_SIZE`, default 4096);
  only new samples count against `SDN_LLM_MAX_SAMPLES`. Without the cache each
  call (~0.3 s) blocked the controller's event queue: in a 97 s run the attacker's
  flow reached `flow_stats` 36 s after the attack began (76 s spent in LLM calls);
  with it, 2 s (723 cached answers against 127 real calls).

## LLM prompt profiles and calibration

`llm_api.PROMPTS` holds two prompts with the same structure: `insdn` (default for
the dataset scripts such as `compare_llms.py`; thresholds and examples from the
InSDN dataset; the lab container defaults to `lab` instead) and `lab` (thresholds and
examples from the graphical lab's own traffic). The two `pktrate` are different
measurements: InSDN's is CICFlowMeter packets/duration of individual (often
microsecond-long) flows, the lab's is the controller's packets/s of an aggregated
flow over the last 5 s poll. Labeled lab samples (9 runs, SYN/UDP at 100-1000
pkt/s, 7792 flows) separate cleanly: legitimate <= 3.6 pkt/s, attack >= 95 pkt/s.

Same 200 flows (100 attack, 100 legitimate, half of them the highest-rate
legitimate ones), one call per flow, `scripts/compare_llms.py --prompt`:

| Prompt | Model | DR | FAR | Accuracy |
| --- | --- | --- | --- | --- |
| `insdn` | llama3.2:3b | 33 % | 12 % | 60.5 % |
| `insdn` | gemma2:2b | 0 % | 0 % | 50 % |
| `lab` | llama3.2:3b | 100 % | 4 % | 98 % |
| `lab` | gemma2:2b | 92 % | 2 % | 95 % |

```bash
python3 scripts/lab_runs.py --grid 100:syn,300:udp,1000:syn ...       # collect
python3 scripts/export_gui_samples.py RUN_ID ... --out logs/gui_samples.csv
python3 scripts/pick_fewshot.py logs/gui_samples.csv --normal-fractions 0.50,0.95,0.995
python3 scripts/sample_eval.py logs/lab_eval_all.csv --pos 100 --neg 100
python3 scripts/compare_llms.py --models llama3.2:3b,gemma2:2b --prompt lab \
    --samples logs/lab_eval_small.csv --repeats 1
```

Limits: the `lab` examples come from the same runs as the evaluation set (the
example rows are excluded, but the sessions are not independent), attacks below
~95 pkt/s were not collected, and the model still flags some legitimate flows of
exactly ~1 pkt/s (4 of 850 live decisions) despite a prompt example showing that
value as normal.

## Response mechanisms (mitigation)

Detectors only report a flagged source IP; what happens next is decided by
`controller/response.py` (policy, no Ryu) and carried out by
`controller/enforcer.py` (OpenFlow 1.3). Both detectors go through the same
hook (`_maybe_block` in `app_modes.py`), so any future detector gets the same
responses. Nothing is enforced unless the run has mitigation enabled
(`SDN_MITIGATION_ENABLED`, i.e. `experiment.mitigation` in the lab API;
`scripts/lab_runs.py --mitigation`).

| `SDN_RESPONSE_POLICY` | Behaviour |
| --- | --- |
| `block` (default) | Temporary drop of everything from the source on every switch (priority 100, `SDN_BLOCK_SECONDS`). Same as the baseline controller. |
| `rate_limit` | OpenFlow meter per source: it keeps working but is capped at `SDN_RATE_LIMIT_PPS` packets/s (burst `SDN_RATE_LIMIT_BURST`) for `SDN_RATE_LIMIT_SECONDS`. Rule priority 90, forwarded with the switch's NORMAL pipeline (Open vSwitch). |
| `escalate` | Rate-limit first; if the source keeps offering more than 2x the limit for `SDN_RESPONSE_ESCALATE_AFTER` s, block it (and free its meter). A source is also blocked if a detector flags it again once `SDN_RESPONSE_ESCALATE_AFTER` s have passed since the limit began. |

The policy (and `dry_run`) can be chosen at runtime with
`detector.sh set --response ... --dry-run ...`; the controller reads them when a
run starts, like the detection mode.

Why `escalate` looks at the offered rate and not at new detections: the limit
rule (priority 90) shadows the forwarding flow the detectors watch, and the rule
itself has no protocol or port, so a source that ignores the cap produces no new
detections. `ResponseManager.review()` therefore uses the packet counter of the
limit rule (read before the meter drops anything). Verified on real switches
(SYN flood, 1000 pkt/s, LLM `lab` prompt): `block` installs `priority=100 drop`
on the attacker; `rate_limit` cut the traffic towards the victim from ~800 to
~25 kbps; `escalate` limited at ~50 s and blocked at ~85 s, freeing the meter;
`dry_run` left no rule on any switch.

Safety rails: only addresses inside `SDN_ALLOWED_TARGET_CIDRS` are touched,
`SDN_RESPONSE_PROTECTED` (comma list of IPs/CIDRs, e.g. the victim and
infrastructure) never is, every action expires by itself, at most
`SDN_RESPONSE_MAX_ACTIVE` sources are handled at once, and
`SDN_RESPONSE_DRY_RUN=true` records what *would* be done (`dry_run_*` in
`mitigation_events.action`, no telemetry, no flows) so detector decisions can
be reviewed before trusting them. Actions are stored in `mitigation_events`
(`temporary_drop`, `rate_limit_<pps>pps`).

Caveats: a false positive blocks or throttles a legitimate host (the LLM
currently produces them, see the calibration notes), so keep `dry_run` on (the lab
container default) or protect known hosts until the detector is validated. The lab GUI only draws
`priority=100 ... drop` rules as "observed", so rate limits show up in
`ovs-ofctl -O OpenFlow13 dump-flows/dump-meters` but not in that panel.

## Entropy detector

Every `SDN_ENTROPY_WINDOW_SECONDS` (10) it computes H(src) and H(dst) over all
flows of the network, weighted by packet rate. An adaptive band (EWMA mean +/-
`SDN_ENTROPY_K` (3) std) is learned during `SDN_ENTROPY_WARMUP` (8) windows.
A window is suspicious when H(src) leaves the band (either side) or H(dst)
drops below it; the alarm is confirmed after `SDN_ENTROPY_CONSECUTIVE` (2)
suspicious windows in a row. Candidate attackers are the sources carrying at
least `SDN_ENTROPY_CANDIDATE_SHARE` (30 %) of the traffic, except the address named as the victim (`target_dst`): in
a SYN flood the victim's RST replies are flows whose source is the victim and
can exceed that share. Suspicious windows do
not update the baseline.

## LLM detector

`SDN_LLM_MODEL` selects the Ollama model (no code change). Only the
`SDN_LLM_MAX_SAMPLES` (5) fastest flows per poll are sent to the model. The
prompt is in `llm_api.py` (`PROMPT_TEMPLATE`); compare models on the same
samples with `scripts/compare_llms.py`.

## Robustness fixes over the baseline controller

Found while attacking the lab (they only live in the subclass):

* PostgreSQL writes run on a background thread with libpq keepalives
  (`config/pg_service.conf`). A dropped connection used to freeze the whole
  controller (psycopg2 blocks the event loop).
* Multipart flow-stats replies are reassembled per (switch, transaction id): an
  unfinished reply is dropped when the next poll starts or the switch
  disconnects, so two polls are never mixed (`controller/stats_buffer.py`). At most
  `SDN_MAX_FLOW_ROWS_PER_POLL` (300) flows per switch/poll are persisted.
* `SDN_FINE_GRAINED_MATCH=true`: rules always include `eth_type` and IP
  addresses/protocol, so ARP/ICMP no longer install an Ethernet-only rule that
  hides later TCP/UDP flows from `flow_stats` and the detectors.

## Known limits

* No routing between segments: attackers and victim must share a segment.
* A SYN flood makes every RST reply a new flow (~1 new flow per attack packet),
  which is the flow-table exhaustion the thesis studies; `flows_per_switch` in
  the entropy decisions records it.
* ICMP flows have no L4 port and are skipped by the LLM path (`build_model_sample`).
