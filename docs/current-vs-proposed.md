# Current baseline versus proposal

| Topic | Implemented now | Proposal / roadmap |
| --- | --- | --- |
| Controller | Ryu application | Ryu named in proposal; OS-Ken migration may be considered later |
| Southbound protocol | OpenFlow 1.3 | Proposal contains an OpenFlow 1.0 reference that must be reconciled |
| Topology | Original 4-switch/9-host topology preserved; GUI adds three teaching presets and a bounded loop-free editor | Larger, validated scenario-specific research topologies |
| Polling | 5 seconds by default | 30-second analysis windows |
| Detection | Authenticated Random Forest-compatible API; optional separate `detector` container with a prompt-driven LLM (Ollama) **or** a Shannon-entropy detector, chosen per run and never combined ([detection modes](detection-modes.md)) | Prompt-driven lightweight LLM plus entropy signal |
| Decision policy | Configurable probability threshold; entropy alarm after consecutive suspicious windows (default 2) with an adaptive baseline; per-flow LLM verdict (two prompt calibrations: InSDN dataset and live lab) | Two consecutive entropy windows plus LLM confirmation |
| Response | Temporary source-IP drop rule, opt-in; selectable policies `block`, `rate_limit` (OpenFlow meter) and `escalate` (limit, then block), a protected-address list and a dry run | Packet dropping, rate limiting, and persistent blacklist escalation |
| Scenarios | Bounded multi-source SYN/UDP/ICMP traffic with several attackers and victims, GUI baseline/attack/recovery orchestration, a measured phase-timed run clock, and normal HTTP probes | Distributed, controller, switch, multi-host, and subtle low-rate scenarios with progressive stressing |
| Evaluation | Metrics collectors, GUI observations, packet headers, command evidence, recorded replay and exports | Full benchmarking, calibration and research validation |
| User interface | Browser topology editor with device icons, multi-selection and bulk edits, per-field explanations, live topology diagnostics, project JSON/limited MiniEdit interchange, guided controls | Arbitrary Python import, advanced routing, full Wireshark and multi-user operation are not supported |
| Container option | Linux Docker packaging with privileged Mininet/OVS runner; existing database reused | Privileged isolated-VM smoke test is still required before live integration is considered verified |

These differences are intentional documentation, not evidence that the proposal has been completed. Future changes must update this table and add experiment evidence.
