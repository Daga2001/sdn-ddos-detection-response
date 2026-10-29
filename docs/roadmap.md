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

Status of items 2-5: a first implementation exists (entropy detector with
consecutive-window confirmation, prompt-driven LLM detector, rate limiting with
escalation to blocking; see [detection modes](detection-modes.md) and the review
plans in `plans/`). It has only been exercised with bounded lab runs; repeated
runs with per-condition statistics are still pending, so it is not experimental
evidence yet.

1. Publish the model-training pipeline and approved model card.
2. Add entropy calculations over source and destination distributions.
3. Add consecutive-window confirmation and explicit suspicious-event state.
4. Evaluate a prompt-driven lightweight LLM beside the statistical baseline.
5. Add rate limiting and persistent blacklist escalation behind independent safety controls.
6. Implement the proposal’s controller, switch, single-host, multi-host, and subtle low-rate scenarios.
7. Add baseline/attack/recovery analysis scripts and reproducible result reports.
8. Decide whether to migrate from Ryu to OS-Ken after preserving an equivalent comparison baseline.

Implemented: canonical Compose startup, isolated runner control addressing,
database ownership locking, GUI owner disconnect cleanup, and runner-based live
timing. Privileged network lifecycle verification remains an isolated-VM gate.
