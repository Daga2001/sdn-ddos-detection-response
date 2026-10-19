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
* Entropy calibration: the lab baseline is only HTTP probes (~5 packets/s network-wide),
  so the container defaults `SDN_ENTROPY_MIN_RATE` to 2 (standalone: 20). The first
  defaults (10 s window of the last poll, k=3, 8 warm-up windows) missed floods: the
  first attack window still fell inside the wide normal band and was learned as normal.
  The lab now defaults to a 5 s window averaged over every poll inside it
  (`SDN_ENTROPY_WINDOW_SECONDS=5`, `SDN_ENTROPY_WINDOW_MODE=mean`), k=2.5 and 16 warm-up
  windows (80 s). Entropy therefore needs a baseline of at least ~120 s (80 s of warm-up windows plus margin, see below); the LLM does not.
  Measured by replaying 141 recorded runs through the real detector class, selecting the
  setting on 7 calibration runs and scoring it once on 7 held-out runs (single attacker
  at 100/300/1000 pkt/s, SYN and UDP, and 3 attackers): 28/28 detected, median delay
  10.1 s against 17.8 s before (the previous k=3 default detected 86 %), no confirmed
  false alarm and no legitimate host named. Fresh live runs of the chosen setting
  detected 3/3 (11, 12 and 17 s). Limits: one topology, one kind of legitimate traffic
  and attacks of at least 100 pkt/s; the false-alarm estimate comes from about 11
  baseline windows per run.
* Optional baseline protection, off by default: `SDN_ENTROPY_UPDATE_HOLD=N` (a
  normal-looking window waits N windows before it may update the band and is discarded
  if the following ones are suspicious) and `SDN_ENTROPY_ALPHA_RUN` (slower smoothing
  after the warm-up). On the original 10 s window they raised k=3 detection from 83 % to
  100 % with no false alarms (calibration runs), but once the window is fixed they were
  not needed. `SDN_ENTROPY_DEDUPE_SWITCHES=true` counts a flow once even if several
  switches report it; it is not recommended with the lab's sparse baseline: the deduplicated
  rate drops under `SDN_ENTROPY_MIN_RATE`, windows are skipped as idle and the warm-up
  finishes later (124 s against 98 s in replay).
* The warm-up counts windows, not seconds, and a quiet window (below `SDN_ENTROPY_MIN_RATE`)
  is skipped. The window loop used to sleep a whole window *after* each evaluation, which
  spaced the windows ~6.5 s apart (a call to the detector service and a database row per
  window), so 16 windows took ~104 s: with a 108 s baseline one run had only 14 windows when the
  flood started, learned the flood as "normal" and never alarmed (k=1.5 run). Windows are now
  paced on a fixed schedule (`next_window_due`), so 16 windows take 80 s; the workspace
  asks for warm-up + 40 s of baseline because the first window waits for every switch and an
  idle window does not count.
* The LLM is deterministic (temperature 0, fixed seed), so the controller caches
  verdicts by the features the model sees (`SDN_LLM_CACHE_SIZE`, default 4096);
  only new samples count against `SDN_LLM_MAX_SAMPLES`. Without the cache each
  call (~0.3 s) blocked the controller's event queue: in a 97 s run the attacker's
  flow reached `flow_stats` 36 s after the attack began (76 s spent in LLM calls);
  with it, 2 s (723 cached answers against 127 real calls).
* The model is judged **off the event loop** (`SDN_LLM_ASYNC`, default `true`). Ryu
  handles every packet-in and every stats reply on one greenthread, so a call made
  inline holds up new flows: on the university topology (9 switches, 25 hosts) with
  one sample per poll, legitimate probes got through 55 % of the time *before any
  attack* and 0 % during and after one. The stats handler now only queues the poll;
  a dedicated greenthread judges it and then stores the rows and acts. A newer poll of
  a switch replaces its unjudged older one (the older rows are still stored, without a
  verdict), so the backlog never exceeds one poll per switch, and the poll holding the
  busiest flow is judged first. Measured on the same topology with 8 SYN attackers at
  300 pkt/s: probes through 100 % / 3-12 % / 81-90 % (baseline / attack / recovery).
  Set `SDN_LLM_ASYNC=false` to go back to inline judging.
* Which flows get the sample budget. Flows are judged busiest first, but a source the
  model flagged in the last `SDN_LLM_REPEAT_SECONDS` (30) goes after the busy
  (`SDN_LLM_BUSY_RATE`, 20 pkt/s) sources it has not flagged yet. Before this, with a
  budget of 2 and SYN floods from two hosts (four flows above 900 pkt/s) a UDP attacker at
  500 pkt/s was never judged in a whole run (2 of 3 attackers found; now 3 of 3, all within
  10.6 s). Quiet flows still come last, so the budget is not spent on legitimate traffic
  that the model sometimes flags.
* ICMP flows carry no transport port, and the sample builder used to drop any flow without
  one, so an ICMP flood never reached the model (0 of 2 attackers detected in 135 s).
  `build_model_sample` now sends ICMP with `l4_dst_port = 0` (how flow datasets record it):
  2 of 2 detected within 8.5 s, no false positive. The entropy detector never needed this.

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

Confirmation (`SDN_RESPONSE_CONFIRM_HITS`, default 1; `SDN_RESPONSE_CONFIRM_SECONDS`, 30; in the
workspace "Detections needed" / "Within"): a source is acted on only after it was flagged that many
times in different polls (detections within 2 s count once: they are one poll seen by several
switches). A flood is flagged poll after poll; the LLM's one-off false alarm on a quiet client is
not. Without it, `block` with the LLM cut off 4 of 8 legitimate clients in one 60 s run (campaign
R2) and 5 of 16 in the university network (M1); `rate_limit` and `escalate` never harmed them
because a client sending 1-3 pkt/s is far under the cap. The price is one more poll
(~5 s) before the response, and with a small sample budget more when several attackers share the
budget. A source already being handled escalates without a new confirmation.

Caveats: a false positive blocks or throttles a legitimate host (the LLM
currently produces them, see the calibration notes), so keep `dry_run` on (the lab
container default) or protect known hosts until the detector is validated. The lab GUI only draws
`priority=100 ... drop` rules as "observed", so rate limits show up in
`ovs-ofctl -O OpenFlow13 dump-flows/dump-meters` but not in that panel.

## Reaction speed: the statistics poll

Both detectors work from the switches' flow statistics, so how often the controller polls
them (`SDN_POLL_INTERVAL`, default 5 s; "Poll every · s" per run in the workspace,
`DetectionConfig.poll_seconds`) bounds how soon a flood can be seen: a rate needs two polls,
so detection takes about two intervals. This matters because a SYN flood makes every
reply a new flow and the service starts failing ~10 s into the attack, before a slow
response can land. Measured on the same attack (3 SYN attackers at 300 pkt/s, LLM, `block`,
2 detections needed):

| Poll | First detection | First block | Legitimate probes (baseline / attack / recovery) |
| --- | --- | --- | --- |
| 5 s | +11 s | +14 s | 100 / 26-37 / 80 % |
| 2 s | +5 s | +7,5 s | 100 / 37 / 95 % |
| 1 s | +1,9 s | +2,9 s | 100 / 100 / 100 % |

With 8 attackers on the university network (2400 pkt/s) the service starts failing about
6 s into the attack, before any detector that needs two 5 s polls can answer, whichever
detector it is: entropy with `block` straight away (alarm at +12 s) left the probes at
100 / 3 / 0 %, entropy with `escalate` (alarm at +23 s because the saturated controller
delays its own windows) at 100 / 9 / 100 %, LLM with `block` and 2 detections at 5 s polling
100 / 3 / 50 %. Polling every 1 s fixes most of it: LLM + `block` + 2 detections needed
(all 8 detected by +7,5 s, first block +5,2 s) kept 100 / 86 / 100 %, and entropy with 2 s
windows (`window_seconds=2`, `warmup_windows=40`) + 1 s polling (all 8 blocked at +3,1 s)
100 / 69 / 100 %. Neither has been checked against false alarms over many runs.

Acting on the first detection instead (no confirmation) also saves the service (95 %) but
blocked two legitimate clients on a false alarm. Faster polling keeps the confirmation and
the speed. The cost is load: each poll of every switch is parsed in Python, so polling
faster costs the controller more while the tables are large; if a flood is not stopped
early the collapse is worse. The flow explosion itself is left as it is: it is the
phenomenon the thesis studies.

## Entropy detector

Every `SDN_ENTROPY_WINDOW_SECONDS` (10) it computes H(src) and H(dst) over all
flows of the network, weighted by packet rate. An adaptive band (EWMA mean +/-
`SDN_ENTROPY_K` (3) std) is learned during `SDN_ENTROPY_WARMUP` (8) windows.
A window is suspicious when H(src) leaves the band (either side) or H(dst)
drops below it; the alarm is confirmed after `SDN_ENTROPY_CONSECUTIVE` (2)
suspicious windows in a row. Candidate attackers are the sources carrying at
least `SDN_ENTROPY_CANDIDATE_SHARE` (30 %) of the traffic divided by the number of sources
sending above the rate floor below (one flooder must carry 30 %; each of seven carries ~7 %
and is named at 4.3 %; before this the alarm fired, the victim was found and nobody was
accused: campaign E10, 7 attackers, 0 of 7 named), except the address named as the victim (`target_dst`): in
a SYN flood the victim's RST replies are flows whose source is the victim and
can exceed that share. A candidate must also send at least
`SDN_ENTROPY_CANDIDATE_MIN_RATE` (20) packets/s: without that floor, once the
attacker was blocked the quiet traffic left stayed outside a tight band (k=1),
the alarm stayed confirmed and each window picked another legitimate host that
held a share of that little traffic (4 legitimate hosts were blocked in one
verification run). Suspicious windows do
not update the baseline.

### Entropy measures and threshold models

The detector above is the default. Every part of it can be changed per run (Detection tab,
`Experiment.detection.entropy`, or the `SDN_ENTROPY_*` variables of the detector service),
so measures and thresholds can be compared on the same traffic.

**Measure** (`SDN_ENTROPY_MEASURE`, `SDN_ENTROPY_ORDER`), computed on the packet-rate
distribution of each watched feature:

| measure | formula | note |
|---|---|---|
| `shannon` | `-sum p log2 p` | the default |
| `norm` | Shannon / `log2(distinct values)` | 0 to 1, independent of how many hosts talk |
| `renyi` | `log2(sum p^a) / (1 - a)` | order `a`; higher orders weigh the busiest value more |
| `tsallis` | `(1 - sum p^q) / (q - 1)` | order `q`; tends to Shannon (in nats) as `q` tends to 1 |
| `min` | `-log2(max p)` | the limit of Renyi for a to infinity |

**Features** (`SDN_ENTROPY_FEATURES`): `src` and `dst` (always) plus, when asked, `dport`
(destination ports) and `proto` (protocols). The controller reads them from the match fields
of the flow statistics; under a SYN flood every reply is a flow to another port, so they are
sent to the detector as a histogram of (rate, number of ports with that rate). Each feature has
its own band; a window is suspicious when any of them leaves its band (the destination
entropy only counts when it drops).

**Threshold model** (`SDN_ENTROPY_CENTER`, `SDN_ENTROPY_SPREAD`, `SDN_ENTROPY_HISTORY`):
the band is `centre +/- k * spread`.

| `center` | centre | spread |
|---|---|---|
| `ewma` | exponentially weighted mean (`alpha`) | its exponentially weighted deviation (the original detector) |
| `mean` | mean of the last `history` windows | standard deviation, or MAD with `spread=mad` |
| `median` | median of the last `history` windows | standard deviation, or MAD (scaled by 1.4826) with `spread=mad` |
| `yu` | mean of the last `history` predictions of the improved EWMA of Yu et al. (2024) | their standard deviation; `history` defaults to 15 |

`history = 0` keeps every window of the run: the centre is then computed from the whole run,
not only from the baseline.

**Learning context** (`SDN_ENTROPY_CONTEXT`): with `normal` (the default) only windows that
look normal update the band, so a flood cannot move it (suspicious windows are discarded;
`SDN_ENTROPY_UPDATE_HOLD` also applies). With `all` every window is learned, attack windows
included: the model itself must then resist outliers, which a mean does not and a median
does up to the point where more than half of the remembered windows are the attack.

### What the workspace shows: the Threshold tab and the logs

Every window, the controller publishes an `entropy_window` event (and writes one `ENTROPY`
line to its log) with the value of each watched entropy, the band it was compared with and
its centre, the state (`warmup`, `idle`, `normal`, `suspicious`, `alarm`), the packet rate,
the number of flow rules, the busiest sources, destinations and ports, and the same window
through the other usual entropies. The **Threshold** tab (below the topology) draws it live:
one dot per window coloured by state, the shaded band and the dashed centre, with a table of
the windows and a selector to look at the same traffic through another entropy. The Timeline
keeps only the windows that were suspicious or alarmed. The events are stored with the run, so
the tab works in a replay and on older runs that have them.

### Replaying recorded windows

`SDN_ENTROPY_DUMP=/tmp/entropy_windows.jsonl` (runner container) makes the controller append
every window, with all its flows and histograms, to that file. `scripts/export_entropy_runs.py`
writes when each attack really started and stopped from the database, and
`scripts/replay_entropy.py` feeds the recorded windows to the real detector with other
settings and scores them (detections, delay, false alarms, share of attack windows flagged),
so detector variants are compared on identical traffic without running the lab:

```bash
python3 scripts/replay_entropy.py entropy_windows.jsonl runs.json
python3 scripts/replay_entropy.py entropy_windows.jsonl runs.json \
    --detail "measure=renyi,order=10,center=median,spread=mad,context=all"
```

(The flow rows the controller stores in the database are capped by
`SDN_MAX_FLOW_ROWS_PER_POLL`, so they cannot be used for this: during a flood the cap keeps
about 300 of tens of thousands of flows and the entropies come out wrong.)

## LLM detector

`SDN_LLM_MODEL` selects the Ollama model (no code change). Only the
`SDN_LLM_MAX_SAMPLES` (5) fastest flows per poll are sent to the model (a poll is
judged in the background, see above, so a slow model delays detections, not the network).
The prompt is in `llm_api.py` (`PROMPT_TEMPLATE`); compare models on the same
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
* ICMP flows have no L4 port; `build_model_sample` sends them to the LLM with port 0 (see above).
  The entropy detector does not catch a symmetric ICMP echo flood: the replies mirror the
  requests, so H(src) and H(dst) stay at the baseline's value (campaign E4: 0 of 2).
* The entropy detector is blind to floods whose source/destination entropy stays inside the
  learned band: 3 attackers against 2 victims (campaign E3: 0 of 3; offline, adding the window
  rate as a monitored signal catches it at +11.7 s with no baseline false alarm, naming the
  sources then needs a separate rule). Many-to-one floods are alarmed, and since the
  candidate rule below every source is named.
