# Current baseline versus proposal

| Topic | Implemented now | Proposal / roadmap |
| --- | --- | --- |
| Controller | Ryu application | Ryu named in proposal; OS-Ken migration may be considered later |
| Southbound protocol | OpenFlow 1.3 | Proposal contains an OpenFlow 1.0 reference that must be reconciled |
| Topology | Original 4-switch/9-host topology preserved; GUI adds three teaching presets and a bounded loop-free editor | Larger, validated scenario-specific research topologies |
| Polling | 5 seconds by default | 30-second analysis windows |
| Flow rates | Change in the switch's packet and byte counters, divided by the change in that flow's own OpenFlow age. A replaced rule (age or a counter goes down) is a new flow, not a negative rate. The controller's processing delay is not part of the rate. | The same measurement for every detector, so a busy controller cannot turn a normal client into a false attacker |
| Detection | Authenticated Random Forest-compatible API; optional separate `detector` container with a prompt-driven LLM (Ollama), **or** the packet-rate rule that is its comparison arm (same flow samples, no model), **or** a Shannon-entropy detector, chosen per run and never combined ([detection modes](detection-modes.md)) | Prompt-driven lightweight LLM plus entropy signal |
| Decision policy | Configurable probability threshold; entropy alarm after consecutive suspicious windows (default 2) with an adaptive baseline; per-flow LLM verdict (two prompt calibrations: InSDN dataset and live lab) | Two consecutive entropy windows plus LLM confirmation |
| Response | Temporary source-IP drop rule, opt-in; selectable policies `block`, `rate_limit` (OpenFlow meter) and `escalate` (limit, then block), a protected-address list (no detector names those hosts and the response never touches them; the experiment's victims by default) and a dry run | Packet dropping, rate limiting, and persistent blacklist escalation |
| Scenarios | Bounded multi-source SYN/UDP/ICMP traffic with several attackers and victims, GUI baseline/attack/recovery orchestration, a runner-owned monotonic run clock, immediate stop requests on GUI owner refresh/logout/disconnect, website checks on their own 1 s loop, and 5 ICMP echo requests/s from one normal client to each victim | Distributed, controller, switch, multi-host, and subtle low-rate scenarios with progressive stressing |
| Evaluation | Metrics collectors, GUI observations (packets/s by role, website checks, ping, Packet-Ins, flow rules, CPU), packet headers, command evidence, recorded replay and exports. A Results tab gathers every number of a run for every detector (DR, FAR, precision/accuracy/F1, detection times, EDR, per-flow DR/FAR, Brier/ECE calibration, the cost of each decision — time per decision, decisions per second, detector-service and Ryu CPU/memory —, latency/loss/availability per phase, Packet-Ins, flow-table growth, response time, mitigation effectiveness, recovery time per equations 8 and 9, a validity check) with a one-row-per-run CSV export. History > Compare runs scores record files, results-row CSVs or the lab's completed runs with the same code and reports the acceptance criteria (Fisher's exact test, Mann–Whitney U, Holm) through `POST /api/compare`, the code of `scripts/compare_runs.py`. Not measured: GPU use on the Ollama computer, iperf bandwidth and LLM output consistency (offline in `compare_llms.py`). | Full benchmarking, calibration and research validation under [the evaluation protocol](evaluation-protocol.md): ≥ 10 runs per cell, no-defense, rule-only and Random Forest comparison arms, held-out runs |
| User interface | Browser topology editor with device icons, multi-selection and bulk edits, per-field explanations, live topology diagnostics, project JSON/limited MiniEdit interchange, guided controls, a required per-port or port-free forwarding choice that is the same for every detector | Arbitrary Python import, advanced routing, full Wireshark and multi-user operation are not supported; a Detection tab and top-bar selector to choose the LLM or entropy and tune it (saved with the run), and a Results tab for every detector with a per-host confusion matrix, cost, service, response and recovery metrics and a live attack/detection chart |
| Container option | After first-time setup, `docker compose up -d` starts PostgreSQL, the workspace, and the separate detector using the existing lab/detector definitions; privileged Mininet/OVS runner, mitigation still opt-in. One canonical Compose project supports managed/external PostgreSQL through configuration; private runner addressing and a database advisory lock prevent duplicate control. | Privileged isolated-VM smoke test is still required before live integration is considered verified |

These differences are intentional documentation, not evidence that the proposal has been completed. Future changes must update this table and add experiment evidence.

The Traffic tab reserves space below the time-axis labels for its traffic and
service-latency legend, keeping the legend clear of the plotted data.

The top-bar entropy option names its configured measure (for example,
**Entropy · Shannon**). The Results tab is shown for every detector, using the setup a
run recorded during replay; entropy tuning and Threshold remain available.
Entropy presets use a two-column grid with equal-sized buttons and a separate label
so all four choices fit within the Detection settings panel.

GUI ownership uses an authenticated page connection; stopped runs never resume on
reconnect. Native transport failure detection and a five-second runner lease cover
silent disconnects. Bounded headless runs remain independent of browser lifetime.
