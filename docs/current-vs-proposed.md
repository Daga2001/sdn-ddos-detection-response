# Current baseline versus proposal

| Topic | Implemented now | Proposal / roadmap |
| --- | --- | --- |
| Controller | Ryu application | Ryu named in proposal; OS-Ken migration may be considered later |
| Southbound protocol | OpenFlow 1.3 | Proposal contains an OpenFlow 1.0 reference that must be reconciled |
| Topology | 4 switches and 9 hosts | Larger scenario-specific topologies, including 9 switches and 12 hosts |
| Polling | 5 seconds by default | 30-second analysis windows |
| Detection | Authenticated Random Forest-compatible API | Prompt-driven lightweight LLM plus entropy signal |
| Decision policy | Configurable probability threshold | Two consecutive entropy windows plus LLM confirmation |
| Response | Temporary source-IP drop rule, opt-in | Packet dropping, rate limiting, and persistent blacklist escalation |
| Scenarios | Basic bounded SYN-rate lab runner | Controller, switch, single-host, multi-host, and subtle low-rate scenarios |
| Evaluation | Metrics schema and testable collectors | Full baseline/attack/recovery benchmarking and calibration analysis |

These differences are intentional documentation, not evidence that the proposal has been completed. Future changes must update this table and add experiment evidence.
