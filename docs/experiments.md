# Experiment protocol

Every experiment needs an entry based on [`templates/experiment-record.md`](templates/experiment-record.md). Record the software versions, topology, environment variables (with secrets redacted), baseline, attack, recovery, and exact timestamps.

## Required phases

1. **Isolation check:** confirm the VM network is disconnected from unauthorized targets and the destination is a Mininet private address.
2. **Baseline:** run legitimate `ping`/`iperf3` traffic and collect metrics for a fixed period.
3. **Attack:** use only the bounded launcher from a Mininet host namespace. Keep `SDN_MITIGATION_ENABLED` disabled for the comparison run, then repeat with it enabled.
4. **Recovery:** stop traffic, continue collecting for the same declared recovery window, and define the stability threshold before inspecting results.
5. **Analysis:** compare attack and recovery values with the baseline and report detection/false-alarm and QoS metrics.

From the Mininet CLI, an authorized example is:

```text
mininet> h2b python3 -m sdn_ddos.experiments.attack_launcher --target 10.0.2.1 --rate 100 --duration 20 --confirm-isolated-lab
```

The command must be run from a Mininet host namespace, not from a workstation connected to a real network. Never remove the confirmation flag or increase limits by editing the safety checks.

## Planned scenarios

The proposal describes controller saturation, switch/host flooding, multi-attacker/multi-target traffic, and subtle low-rate attacks. These remain roadmap scenarios. Implement each as a separately reviewed, bounded protocol with a ground-truth attack window and a no-defense comparison.

GUI experiments stop when their owning tab refreshes, closes, logs out, or loses
its ownership connection. Record this as an interrupted observation window using
the `stop_requested` reason; do not count it as a completed experiment. Use the
bounded headless API scripts for campaigns that must run independently of a
browser. Other viewing/replay tabs do not own the run.
