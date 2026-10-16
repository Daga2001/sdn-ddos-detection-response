# Graphical Mininet lab (Linux container option)

The browser workspace keeps **Mininet, Open vSwitch, Ryu/OpenFlow 1.3, the existing inference API, and PostgreSQL**. It adds an editor and an observation layer, not a replacement simulator. The existing VM/CLI workflow remains available.

This is a Docker deployment: `web` runs the GUI/backend, `runner` runs Mininet/OVS/Ryu and experiment tools, and `inference` runs the detector API. Your existing PostgreSQL container stays separate. You do not install Mininet, Ryu, Python libraries, or Node.js on the host for this option. `make lab-up` checks the host, then calls Docker Compose to build and start the three containers.

On native Linux, a VM is not a runtime dependency. The runner does need the host kernel's Open vSwitch support because containers share that kernel. Only the runner uses privileged Docker access; the other two containers do not. The isolated-VM smoke test described below is the repository's verification policy, not an extra service needed to start Docker. For a plain-language walkthrough, start with the [README's Docker GUI instructions](../README.md#optional-graphical-container-workspace).

## Start with your existing database

Requirements: native Linux, local rootful Docker Engine with Compose, Bash, Make, OpenSSL, and kernel Open vSwitch support. The initial image build downloads Linux tools and Python packages; allow several minutes and several GB of disk space. macOS, Windows, Docker Desktop, rootless Docker, and remote Docker engines are not supported by this first version.

1. Keep your existing `.env`. If you do not have one, copy `.env.example` and configure the database. Do not overwrite working credentials. `SDN_PG_PORT` remains your database's **host-published** port; lab containers use port 5432 on the Docker network.
2. Set `SDN_LAB_DB_NETWORK` to the existing database container's network (default: `sdn-ddos-detection-response_default`), and `SDN_LAB_PG_HOST` to its network alias (default: `postgres`). Use the existing `SDN_PG_DB`, `SDN_PG_USER`, and `SDN_PG_PASSWORD`. This stack does not create, replace, or stop PostgreSQL.
3. Back up your database, then explicitly apply the additive migration. For the repository's existing Compose database:

   ```bash
   docker compose exec -T postgres psql -U sdn_user -d sdn_monitor \
     -v ON_ERROR_STOP=1 < database/migrations/002_lab.sql
   ```

   Substitute your own database/user if different. The migration adds GUI tables and nullable run IDs to existing metric tables; it does not delete existing data. Fresh databases initialized with `database/schema.sql` already contain these additions. Application startup never performs DDL.

4. Prepare and check the workspace:

   ```bash
   make lab-setup
   make lab-doctor
   ```

   Setup creates ignored, mode-600 credentials in `.lab/env`, retaining existing credentials on subsequent runs. Doctor is read-only. If it reports missing kernel support, an administrator must load `openvswitch` on the intended isolated Linux host (`sudo modprobe openvswitch`). Do not run that command on an unrelated or shared production host.

5. Start the three new services:

   ```bash
   make lab-up
   ```

   Open **http://localhost:8080** and paste the `SDN_LAB_TOKEN` from `.lab/env`. Do not share that file. `make lab-logs` shows service logs; `make lab-down` removes only this stack's containers/network, leaving the external database and its records in place.

One runner per database is supported. On runner startup, unfinished GUI runs become `interrupted`; they are never silently resumed. A browser disconnect does not stop an experiment: use **Stop lab**, or `make lab-down` if the GUI is unavailable. Observation sessions end after one hour; experiment traffic has its own independent process deadline.

## Working in the GUI

- Choose one of four presets: original enterprise (4 switches/9 hosts), connected enterprise (same layout, one subnet), small teaching network (1/3), or linear network (3/6).
- The managed Ryu controller is drawn as `c0` above the switches, with a dashed control link to each one. It is the lab's own service, not part of your topology: it cannot be edited, moved, deleted, or selected together with your devices, it is never counted in the link totals, and it is never written into an exported file. Select it to read its OpenFlow endpoint and live CPU/memory.
- Devices are drawn with their own icons: an Open vSwitch chassis for switches, a workstation for hosts, a rack server for hosts publishing the victim service, and a workstation with an outbound badge for the attackers. Role captions (attacker, victim, client) appear under every host an experiment uses.
- Add, drag, and remove hosts/switches. A new device is linked to the least busy switch automatically, so the canvas never holds a stranded device by accident; remove that link if you want it elsewhere. Join the small connection handles to add links.
- Select with the **Select** tool: click a device or link, drag on empty canvas for a rubber-band selection, Shift-click to add to it, and press Delete to remove everything selected. Switch to the **Pan** tool to drag the canvas instead. With several items selected, the inspector removes them in one action and applies bandwidth, delay, or loss to every selected link at once.
- Every form field carries an **i** button explaining, in plain words, what the value means and what changes when you raise or lower it.
- Select a device or link to edit host IPs, DPIDs, bandwidth, delay, or loss. Select empty canvas to name, validate, or save a topology snapshot. While you edit, the canvas footer counts the problems that would stop a run — an unlinked host, a repeated address, a loop — and the inspector lists each one with the fix.
- One **Download** button, with a dropdown for the format: project JSON or the supported MiniEdit v2 `.mn` subset. Both files import again unchanged, including the project name and description. JSON preserves fractional link settings. MiniEdit exports require whole-number bandwidth/loss, because its properties dialog parses integers. A topology that is not yet valid is not written to a file, because such a file could not be imported back; the reason is shown instead. Import warns when controller settings are remapped to the managed controller.
- **Observe** starts a fresh network with mitigation off. Select a host for interface details or three bounded pings; select a switch for its flow table. These diagnostics are disabled during experiments so they do not change the measurement workload.
- An experiment chooses one or more attackers and one or more victims in the same subnet, plus the traffic kinds to send — TCP SYN, UDP, ICMP, or a mix. Attackers and victims are picked from a paginated host table (host name, IP address, switch parent, 5 or 10 rows per page); a host already taken by the other role is shown but locked so it can never be both. Every observation and inspector tab carries a plain-language hover tooltip explaining what it shows and why it is useful. Legitimate clients are not chosen: every remaining host in the victims' subnet is inferred as one, and the workspace probes them against the victims to measure whether normal traffic still gets through. Each attacker floods every victim, so the attacker × victim product is capped (at 16 flows) to keep a run bounded; selected traffic kinds are spread across the attackers. Defaults are 30 seconds baseline, 20 seconds at 100 packets/second per flow, and 30 seconds recovery. Limits are 1,000 packets/second per flow and 300 seconds for attack traffic. The independent GNU `timeout` supervisor sends TERM at the deadline and KILL after a two-second grace period; each generator's packet count is bounded as well. No public/custom target input, spoofing, unrestricted shell, or unlimited flood is provided.
- A run clock in the header shows elapsed time, and the traffic chart shades the measured baseline, attack, and recovery phases against the clock with their durations, so the time spent in each phase is readable directly from the graph.
- Select a link to capture headers: at most 60 seconds / 2,000 packets, one capture at a time. Expand a packet row for Ethernet/IP/transport header fields. No payload or PCAP is persisted. Snap length is 256 bytes; this is a teaching view, not full Wireshark.
- **History** loads saved topology snapshots and completed/interrupted runs. Replay supports pause, speed, stepping and seeking. It reads records only—no runner commands or traffic. JSON/CSV exports contain run configuration and observations, not credentials or model artifacts.

Rejected requests answer in one sentence that names the device and the fix ("h1, h2 and h3 have no link yet; drag from each host handle to a switch"), for topology rules, import failures, and out-of-range experiment settings alike.

Supported topologies are one connected, loop-free graph, up to 32 hosts/16 switches/64 links, with one link per host and one managed controller. Host and switch names have at most nine characters to fit Linux interface names. DPIDs are positive JSON-safe integers (up to 2^53−1); larger MiniEdit hex DPIDs are rejected, not rounded. Custom Python topologies, startup commands, host routes, external interfaces, alternative controllers, routers, and switching loops are not supported. MiniEdit hosts need explicit private IPv4 addresses. Addresses must also match `SDN_ALLOWED_TARGET_CIDRS`.

The original enterprise preset deliberately retains its separate /24 subnets and has **no inter-subnet router**. Keep an experiment's attackers and victims in one department for that preset, or use connected enterprise when teaching paths across switches. Do not treat those two presets as equivalent research datasets.

## Choosing and judging the detector

With the detector container running (`scripts/lab_detector.sh up`) the workspace can pick
the detector and show how it did, with no shell commands:

* **Detector selector** in the top bar: switch between the installed LLMs (listed from
  Ollama), entropy, or no detection. It edits the same setup as the Detection tab.
* **Detection tab** (right panel): the detector type and its tuning. LLM: model, prompt
  profile, samples per poll, probability threshold. Entropy: window length and mode,
  band width `k`, warm-up and consecutive windows, minimum rate, and advanced settings
  (candidate share and rate, hold windows, slower smoothing, switch deduplication).
  Response: whether to apply one, its policy (`block`, `rate_limit`, `escalate`), a dry
  run (on by default), the caps and durations, and addresses never to act on.
  "Restore calibrated values" puts back the values measured in this lab
  ([detection modes](detection-modes.md)).
* **Detection results tab** (below the topology): a per-host confusion matrix, precision,
  recall, false-positive rate, accuracy and F1, the time to the first and last attacker
  detected, a per-host table, the traffic toward the victim and service probes by phase,
  the responses requested (and any legitimate client they hit), and a live chart that
  puts the flood next to the detections. It reads recorded events only, so it works
  live, in a replay and on older runs.

How the results are scored: the experiment is the ground truth. Each attacker is a
positive and each legitimate client (a host in the victims' subnet that is neither an
attacker nor a victim) a negative; the victim is not scored. An attacker the detector
named at least once is a true positive (VP), one it never named a false negative (FN), a
legitimate client it named a false positive (FP) and one it never named a true negative
(VN). Verdicts are per host and per run, so with a few hosts the rates move in large steps.

Where the setup is saved: inside the experiment settings of the run record
(`lab_runs.settings.detection`), so the run's JSON/CSV export and its replay carry it, and
the runner also records a `detection_config` event at the start of every experiment. At
run start the runner pushes the detector-side part to the detector service (`PUT /config`)
and hands the controller-side part (window shape, samples per poll, response limits) to
the Ryu process as environment variables. An experiment without a detection setup leaves
the detector as `scripts/detector.sh` set it. Asking for a detector from a lab without the
detector service, or for an LLM that Ollama does not have, is refused before any run is
created. The response stays off unless turned on, and starts as a dry run; the workspace
warns before real rules would be installed in the emulated switches.

## What the measurements mean

| Observation | Interpretation |
| --- | --- |
| Link widths, rates, and traffic chart | Measured interface-byte deltas, targeted every second; delays under load are possible. Orange means over 1 Mb/s, not a detector verdict. Summed links count a packet again at each hop. |
| HTTP latency / failures | Bounded probes from inferred legitimate clients to the victims' minimal port-8080 HTTP responders, cycling one client→victim pair every three seconds. Failed probes are missing latency points. |
| Controller CPU/RAM and flow table | Resource use of the **Ryu controller process alone** (the `ryu-manager` process, via psutil) — not the host, the container, or Mininet. CPU is a percentage of one core, so brief spikes above 100% are possible. Inference/flow polling remains five seconds by default. |
| Detection events | Actual controller/model decisions, not labels inferred from red links or scenario state. |
| Mitigation requests / observed rules | Separate request events and five-second switch-table observations (`mitigation_observed` in Timeline). A drop rule's presence does not itself prove service recovery. |
| Commands | Fixed argument arrays and bounded output from supervised subprocesses; process exit codes are recorded. |

Without a verified model, the detector reports `not_ready` and observation still works. Controller mitigation stays disabled: its toggle is hidden in the GUI until a detector microservice exists, though the runtime capability, the existing `BlockRegistry`, and the allowed-network checks remain in force. The scenario is **bounded, multi-source SYN/UDP/ICMP traffic**, not an unbounded distributed DDoS generator and not a guaranteed outage.

GUI attack-window evidence is recorded as `attack_started` / `attack_stopped`
events in `lab_events`, with the run's topology resolving host names to IPs.
The existing CLI continues to populate `attack_windows`. Analysis of GUI runs
must use their run-scoped events rather than assuming the legacy table contains
the GUI's attack windows.

When a run fails, the `error` event carries a plain-language `message` and the
exact `detail` (for example, the node and exit code of a generator that failed),
and the workspace shows both in a red card so the run can be debugged. Traffic
generators are torn down at the attack deadline, so a signal death (SIGTERM or
SIGKILL from that teardown) or the bounded `timeout` exit is expected and does
**not** fail the run; only a generator that exits on its own with a non-zero,
non-`timeout` code is treated as a real failure.

Live buffers are bounded (runner 5,000 events, browser 2,000 events / 500 packet rows). Packet observations are written in batches. Dropped controller/command observations and SSE catch-up gaps are explicitly reported. Persisted history is paginated; browser replay refuses more than 100,000 events and suggests streaming export. Producer timestamps are UTC; replay sorts by timestamp and then sequence. Use recorded timestamps, not animation speed, for analysis. This is best-effort telemetry, not a lossless capture system.

**How the controller's observations reach the runner.** The controller sends them over an
`AF_UNIX` datagram socket without ever blocking. A datagram socket holds little: the runner
container's `net.unix.max_dgram_qlen` is 10 and the default buffer is about 200 KB, roughly 25
of the ~8 KB `flows` messages, so one burst from nine switches overflowed it and, with the
runtime reading only once a second, an 8-attacker run lost 1,838 events including detections
(a detected attacker then looked undetected). Now a listener thread empties the socket as the
messages arrive (`MininetRuntime._listen`), the runtime raises the queue length and both
buffers (16 MB, `grow_buffer`), and the controller keeps its `detection` and
`mitigation_requested` events (the ones the results are scored from) and resends them until
the receiver takes them. The same run now loses none (`gap` events stay at 0). Bulk `flows`
messages can still be dropped when the runner is overwhelmed; that is reported as a `gap` and
the Detection tab says its numbers are then a lower bound.

## Architecture and security tradeoffs

| Service | Role and privileges |
| --- | --- |
| `web` | Unprivileged FastAPI + built React/React Flow/ECharts UI. Only host-published port: `127.0.0.1:8080`. |
| `runner` | Privileged Mininet/OVS, managed Ryu subprocess, bounded commands/captures. Authenticated private HTTP control; no published ports. Ryu binds loopback only. |
| `inference` | Existing checksum-verified inference API, unprivileged, internal network only; read-only `models/` mount. |
| Existing PostgreSQL | External Docker network; projects, run metadata and event history plus existing metrics. No automatic DDL. |

Browser access uses an eight-hour HttpOnly/SameSite session, a generated local token, login throttling, 1-MiB request limit, and Host/Origin checks. Runner control has a separate bearer token. No Docker socket, host networking, host PID namespace, or host OVS directories are mounted. Mininet hosts have no NAT or bridge to the container's service network. Mitigation defaults off even if the workstation environment enables it elsewhere.

**Privileged Docker is not a security boundary against hostile code.** The runner shares the Linux kernel and needs broad privileges. It is suitable only for a trusted, local, isolated research machine. The database network is shared with your existing container. Do not publish this GUI remotely or use the runner as a multi-user service. Ryu 4.34 and its Python 3.9/Eventlet environment are legacy/EOL; their isolation is a compatibility measure, not a claim that they are secure or maintained. Native/container performance also differs from VM performance—record the environment when comparing results.

The runner's distro Python sees distro Mininet; Ryu runs in a separate Python 3.9 environment. The image explicitly installs Ryu's old build requirements before building it. Eventlet 0.30.2 requires `dnspython<2`, so the previously inconsistent 2.2.1 pin is corrected to 1.16.0. OVS Python bindings are pinned to the runner's 2.17 series. Modern API/inference dependencies retain `uv.lock`. OS packages and some legacy transitive dependencies are not bit-for-bit locked: preserve the image digest and exported version event with experiment evidence.

To supply an approved model, place it in the ignored `models/` directory, set `SDN_LAB_MODEL_PATH=/models/<filename>` and `DDOS_MODEL_SHA256` in `.env`, and rebuild/recreate with `make lab-up`. Do not commit the artifact. Record its training/runtime versions in the model card.

## Verification and release gate

`make check` runs dependency-light Python checks/tests with mocked Mininet/process/database boundaries. `make web-check` builds and runs browser tests against a mocked API (install Chromium once with `cd web && npx playwright install chromium`). Neither suite creates a Mininet network, sends attack traffic, or connects to a real database.

Image builds and unprivileged import/packet-field checks are separate from a live network test. **The privileged end-to-end smoke test remains a manual release gate in the isolated VM**, per `AGENTS.md`:

1. Verify the migration and container startup; confirm no host-published runner/OpenFlow/inference ports.
2. Start the small preset in Observe; inspect interfaces, send three pings, capture a selected link, then stop. Verify no leftover bridges/processes in the runner; repeat twice.
3. Run a short, low-rate three-phase scenario with mitigation disabled. Confirm bounds, command exit, actual link/packet/service observations, and database run IDs. Do not claim detection without a verified model.
4. Test Stop during baseline/attack, browser reload during a run, and disconnect/reconnect. Test recorder loss; verify traffic ends and history is explicitly incomplete.
5. With an approved model only, verify detection/request/observed-drop events separately. Check cleanup, then replay and compare JSON/CSV timestamps. Replay must launch no processes.
6. Record host kernel, Docker version, image digests, model checksum, topology, and observed limitations. Do not mark live support verified until these steps pass.

## Detection campaign (repeatable test scenarios)

`scripts/campaign/` holds the scenarios used to test the whole detection and response path
through the lab's own API (the same request the workspace sends): refused requests, LLM and
entropy detectors, every response policy (simulated and real), protected hosts, caps, bigger
networks, a stop in mid-attack. `python3 scripts/campaign/lab_campaign.py --list` shows them;
`bash scripts/campaign/start.sh NAME --group L,E` runs them in the background on the VM and
writes `~/campaign/NAME.log` plus one JSON line per scenario in `~/campaign/results.jsonl`.
Each result is judged from the recorded events *and* from the controller's own database rows,
so a lost telemetry event cannot hide a detection. `scripts/campaign/ryu_tests.sh` runs the
controller tests, which need Ryu and therefore the runner container.

## Design sources

The editor adopts MiniEdit's approachable host/switch/link model, but uses a validated declarative contract rather than executing imported Python. Its supported file format was checked against [MiniEdit source](https://github.com/mininet/mininet/blob/master/examples/miniedit.py). Traffic-width ideas come from the [sFlow Mininet dashboard](https://github.com/sflow-rt/mininet-dashboard); this implementation uses OVS/interface/controller observations without adding sFlow-RT. Packet Tracer's teaching and simulation/realtime distinction inspired guided scenarios and explicit replay, but no Cisco software or proprietary topology format is embedded ([Cisco Packet Tracer](https://www.netacad.com/cisco-packet-tracer)).

Container caveats follow [Docker privileged-runtime documentation](https://docs.docker.com/engine/containers/run/#runtime-privilege-and-linux-capabilities) and Mininet's [namespace/process implementation](https://github.com/mininet/mininet/blob/master/mininet/node.py). Packet-header extraction uses the documented [TShark fields interface](https://www.wireshark.org/docs/man-pages/tshark.html). The legacy dependency constraint is explicit in [Eventlet 0.30.2 setup metadata](https://github.com/eventlet/eventlet/blob/v0.30.2/setup.py), and Ryu's build hooks are in its [4.34 source](https://github.com/faucetsdn/ryu/blob/v4.34/ryu/hooks.py).
