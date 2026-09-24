# Current baseline versus proposal

| Topic | Implemented now | Proposal / roadmap |
| --- | --- | --- |
| Controller | Ryu application | Ryu named in proposal; OS-Ken migration may be considered later |
| Southbound protocol | OpenFlow 1.3 | Proposal contains an OpenFlow 1.0 reference that must be reconciled |
| Topology | Original 4-switch/9-host topology preserved; GUI adds three teaching presets and a bounded loop-free editor | Larger, validated scenario-specific research topologies |
| Polling | 5 seconds by default | 30-second analysis windows |
| Detection | Authenticated Random Forest-compatible API | Prompt-driven lightweight LLM plus entropy signal |
| Decision policy | Configurable probability threshold | Two consecutive entropy windows plus LLM confirmation |
| Response | Temporary source-IP drop rule, opt-in | Packet dropping, rate limiting, and persistent blacklist escalation |
| Scenarios | Bounded single-source SYN traffic, GUI baseline/attack/recovery orchestration and normal HTTP probes | Distributed, controller, switch, multi-host, and subtle low-rate scenarios |
| Evaluation | Metrics collectors, GUI observations, packet headers, command evidence, recorded replay and exports | Full benchmarking, calibration and research validation |
| User interface | Browser topology editor, project JSON/limited MiniEdit interchange, guided controls | Arbitrary Python import, advanced routing, full Wireshark and multi-user operation are not supported |
| Container option | Linux Docker packaging with privileged Mininet/OVS runner; existing database reused | Privileged isolated-VM smoke test is still required before live integration is considered verified |

These differences are intentional documentation, not evidence that the proposal has been completed. Future changes must update this table and add experiment evidence.
