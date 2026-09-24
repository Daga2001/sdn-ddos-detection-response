# Roadmap

## Baseline release (0.1)

- Reproducible repository and agent guidance.
- Four-switch/nine-host Mininet topology.
- OpenFlow 1.3 Ryu monitoring controller.
- Authenticated, checksum-verified inference contract.
- PostgreSQL metrics and ground-truth event schema.
- Bounded, private-address-only experiment launcher.

## Research implementation milestones

The local graphical/container workspace is implemented as an alpha option;
see [setup, limitations and the live release gate](lab-workspace.md). Next:
complete the isolated-VM container smoke test, document measured overhead, and
validate a project-owned model. Do not equate GUI screenshots, successful
image builds, or synthetic browser fixtures with experimental DDoS evidence.

1. Publish the model-training pipeline and approved model card.
2. Add entropy calculations over source and destination distributions.
3. Add consecutive-window confirmation and explicit suspicious-event state.
4. Evaluate a prompt-driven lightweight LLM beside the statistical baseline.
5. Add rate limiting and persistent blacklist escalation behind independent safety controls.
6. Implement the proposal’s controller, switch, single-host, multi-host, and subtle low-rate scenarios.
7. Add baseline/attack/recovery analysis scripts and reproducible result reports.
8. Decide whether to migrate from Ryu to OS-Ken after preserving an equivalent comparison baseline.
