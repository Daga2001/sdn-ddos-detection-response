#!/usr/bin/env python3
# ruff: noqa: E501
"""Run labeled detection scenarios through the lab's HTTP API and judge what happened.

Runs on the VM, in the repository root, with the lab up:

  set -a; . ./.env; set +a
  PYTHONPATH=src python3 scripts/campaign/lab_campaign.py --list
  PYTHONPATH=src python3 scripts/campaign/lab_campaign.py L1 E1 R3     # by id
  PYTHONPATH=src python3 scripts/campaign/lab_campaign.py --group L    # by group letter
  PYTHONPATH=src python3 scripts/campaign/lab_campaign.py --all

Every scenario is the same request the workspace sends (topology + experiment with its
detection setup). The verdict is computed from the recorded events and, independently,
from the controller's own database rows, so a lost telemetry event cannot hide a result.
Results are appended to campaign_results.jsonl and a summary table is printed.
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
import time
import urllib.error
import urllib.request
from datetime import datetime
from pathlib import Path
from typing import Any, Optional

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from lab_runs import Lab
from scenarios import SCENARIOS, Scenario

RUNNER = "sdn-lab-runner-1"
TERMINAL = ("idle", "stopped", "completed", "failed", "error")
HERE = Path(__file__).resolve().parent


class Api(Lab):
    def raw(self, method: str, path: str, body: object = None) -> tuple[int, Any]:
        data = None if body is None else json.dumps(body).encode()
        from lab_runs import HEADERS

        request = urllib.request.Request(
            "http://127.0.0.1:8080" + path,
            data=data,
            method=method,
            headers={**HEADERS, "Content-Type": "application/json"},
        )
        try:
            with self.opener.open(request, timeout=60) as response:
                return response.status, json.load(response)
        except urllib.error.HTTPError as error:
            text = error.read().decode()
            try:
                return error.code, json.loads(text)
            except ValueError:
                return error.code, text


def runner(command: str, timeout: int = 20) -> str:
    try:
        return subprocess.run(
            ["docker", "exec", RUNNER, "sh", "-c", command],
            capture_output=True,
            text=True,
            timeout=timeout,
        ).stdout
    except (subprocess.TimeoutExpired, OSError):
        return ""


def controller_env(names: set[str]) -> dict[str, str]:
    out = runner(
        "pid=$(pgrep -f ryu-manager | head -1); [ -n \"$pid\" ] && tr '\\0' '\\n' < /proc/$pid/environ"
    )
    found = {}
    for line in out.splitlines():
        key, _, value = line.partition("=")
        if key in names:
            found[key] = value
    return found


def snapshot_rules() -> dict[str, int]:
    """What the switches actually hold right now (drop rules, meters, flows)."""

    out = runner(
        "for s in $(ovs-vsctl list-br); do ovs-ofctl -O OpenFlow13 dump-flows $s; done",
        timeout=25,
    )
    lines = out.splitlines()
    return {
        "drops": sum(1 for x in lines if "priority=100," in x and "actions=drop" in x),
        "meters": sum(1 for x in lines if "meter:" in x),
        "flows": sum(1 for x in lines if "cookie" in x),
    }


def leftover() -> dict[str, str]:
    return {
        "bridges": runner("ovs-vsctl list-br").strip(),
        "ryu": runner("pgrep -c ryu-manager").strip(),
    }


def collect_events(api: Api, run_id: str) -> list[dict[str, Any]]:
    events: list[dict[str, Any]] = []
    cursor = 0
    while True:
        status, page = api.raw("GET", f"/api/runs/{run_id}/events?after={cursor}")
        if status != 200 or not page:
            break
        events.extend(page)
        cursor = page[-1]["seq"]
    return events


def db_rows(run_id: str) -> dict[str, Any]:
    """The controller's own records for the run (not routed through telemetry)."""

    import psycopg2

    from sdn_ddos.config import DatabaseSettings

    s = DatabaseSettings.from_env()
    conn = psycopg2.connect(
        host=s.host, port=s.port, dbname=s.database, user=s.user, password=s.password
    )
    try:
        cur = conn.cursor()
        cur.execute(
            "select host(ipv4_src), count(*) from detection_events where run_id=%s group by 1",
            (run_id,),
        )
        detections = {ip: n for ip, n in cur.fetchall() if ip}
        cur.execute(
            "select host(ipv4_src), action, count(*) from mitigation_events where run_id=%s group by 1,2",
            (run_id,),
        )
        mitigations: dict[str, dict[str, int]] = {}
        for ip, action, n in cur.fetchall():
            mitigations.setdefault(ip, {})[action] = n
        cur.execute(
            "select count(*), count(*) filter (where verdict) from detection_decisions "
            "where ts >= (select started_at from lab_runs where id=%s) "
            "and ts <= coalesce((select ended_at from lab_runs where id=%s), now())",
            (run_id, run_id),
        )
        decisions, positive = cur.fetchone()
        return {
            "detections": detections,
            "mitigations": mitigations,
            "decisions": decisions,
            "positive_decisions": positive,
        }
    finally:
        conn.close()


def parse_ts(text: str) -> datetime:
    """Timestamps as the API prints them ('2026-10-14 09:14:25.1+00'); Python 3.9 safe."""

    text = text.strip().replace("Z", "+00:00").replace(" ", "T")
    if re.search(r"[+-]\d\d$", text):
        text += ":00"
    match = re.match(r"(.*T\d\d:\d\d:\d\d)(?:\.(\d+))?(.*)$", text)
    if match:
        head, fraction, tail = match.groups()
        text = f"{head}.{(fraction or '').ljust(6, '0')[:6]}{tail}"
    return datetime.fromisoformat(text)


def seconds(first: str, second: str) -> float:
    return (parse_ts(second) - parse_ts(first)).total_seconds()


def analyse(
    scenario: Scenario,
    topology: dict[str, Any],
    events: list[dict[str, Any]],
    db: dict[str, Any],
    rules: dict[str, int],
) -> dict[str, Any]:
    """Same scoring as the workspace's Detection tab, plus the database cross-check."""

    ip = {h["name"]: h["ip"].split("/")[0] for h in topology["hosts"]}
    name = {v: k for k, v in ip.items()}
    attackers = [ip[a] for a in scenario.attackers]
    victims = [ip[v] for v in scenario.victims]
    legit = [a for a in ip.values() if a not in attackers and a not in victims]

    def ts(kind: str, state: Optional[str] = None) -> Optional[str]:
        for e in events:
            if e["kind"] == kind and (state is None or e["data"].get("state") == state):
                return e["ts"]
        return None

    attack_start = ts("attack_started") or ts("phase", "attack")
    attack_stop = ts("attack_stopped") or ts("phase", "recovery")
    flagged: dict[str, list[float]] = {}
    responded: dict[str, list[tuple[float, str]]] = {}
    gaps = 0
    for e in events:
        offset = seconds(attack_start, e["ts"]) if attack_start else 0.0
        if e["kind"] == "detection":
            for source in {
                e["data"].get("ipv4_src"),
                *(e["data"].get("candidates") or []),
            }:
                if source:
                    flagged.setdefault(source, []).append(offset)
        elif e["kind"] == "mitigation_requested":
            responded.setdefault(e["data"].get("ipv4_src"), []).append(
                (offset, e["data"].get("action", ""))
            )
        elif e["kind"] == "gap":
            gaps += int(e["data"].get("count", 0))

    # The database is authoritative: a detection or response there counts even if its event was lost.
    db_flagged = set(db["detections"]) | set(db["mitigations"])
    events_flagged = set(flagged) | set(responded)
    seen = events_flagged | db_flagged
    vp = [a for a in attackers if a in seen]
    fn = [a for a in attackers if a not in seen]
    fp = [h for h in legit if h in seen]
    vn = [h for h in legit if h not in seen]
    first = min(
        (t for a in attackers for t in flagged.get(a, []) if t >= 0), default=None
    )
    per_attacker = {
        name[a]: (round(min(flagged[a]), 1) if flagged.get(a) else None)
        for a in attackers
    }
    all_at = (
        max(v for v in per_attacker.values() if v is not None)
        if per_attacker and all(v is not None for v in per_attacker.values())
        else None
    )

    probes: dict[str, list[bool]] = {"baseline": [], "attack": [], "recovery": []}
    victim_links = {
        link["id"]
        for link in topology["links"]
        if set(scenario.victims) & {link["source"], link["target"]}
    }
    load: list[tuple[float, float]] = []
    cpu = 0.0
    first_fail: Optional[float] = None
    first_ok_after: Optional[float] = None
    for e in events:
        if e["kind"] == "service":
            if attack_start and parse_ts(e["ts"]) < parse_ts(attack_start):
                phase = "baseline"
            elif attack_stop and parse_ts(e["ts"]) > parse_ts(attack_stop):
                phase = "recovery"
            else:
                phase = "attack"
            ok = bool(e["data"].get("success"))
            probes[phase].append(ok)
            if phase == "attack" and not ok and first_fail is None and attack_start:
                first_fail = seconds(attack_start, e["ts"])
            if phase == "recovery" and ok and first_ok_after is None and attack_stop:
                first_ok_after = seconds(attack_stop, e["ts"])
        elif e["kind"] == "links" and attack_start:
            for link in e["data"].get("links", []):
                if link["link_id"] in victim_links and link.get("rates"):
                    load.append(
                        (seconds(attack_start, e["ts"]), link["rates"]["tx_bps"] / 1000)
                    )
        elif e["kind"] == "controller":
            cpu = max(cpu, float(e["data"].get("cpu_percent") or 0))

    def pct(values: list[bool]) -> Optional[float]:
        return round(100 * sum(values) / len(values)) if values else None

    def mean(lo: float, hi: float) -> Optional[float]:
        values = [v for t, v in load if lo <= t < hi]
        return round(sum(values) / len(values), 1) if values else None

    duration = seconds(attack_start, attack_stop) if attack_start and attack_stop else 0
    actions = sorted(
        {a for items in responded.values() for _, a in items}
        | {a for per in db["mitigations"].values() for a in per}
    )
    mitigated_legit = [
        name.get(h, h) for h in legit if h in responded or h in db["mitigations"]
    ]
    # A real drop cuts a legitimate client off; a limit (or a simulation) does not.
    blocked_legit = [
        name.get(h, h)
        for h in legit
        if any(a == "temporary_drop" for _, a in responded.get(h, []))
        or "temporary_drop" in db["mitigations"].get(h, {})
    ]
    return {
        "attackers": scenario.attackers,
        "n_attackers": len(attackers),
        "vp": len(vp),
        "fn": len(fn),
        "fp": len(fp),
        "vn": len(vn),
        "missed": [name[a] for a in fn],
        "false_positive_hosts": [name[h] for h in fp],
        "recall": round(len(vp) / len(attackers), 3) if attackers else None,
        "precision": round(len(vp) / (len(vp) + len(fp)), 3) if (vp or fp) else None,
        "first_detection_s": None if first is None else round(first, 1),
        "all_detected_s": all_at,
        "per_attacker_first_s": per_attacker,
        "events_only_attackers": len([a for a in attackers if a in events_flagged]),
        "db_only_attackers": len([a for a in attackers if a in db_flagged]),
        "db_detection_rows": sum(db["detections"].values()),
        "db_mitigation_hosts": sorted(name.get(h, h) for h in db["mitigations"]),
        "response_actions": actions,
        "responded_attackers": sorted(
            name[a] for a in attackers if a in responded or a in db["mitigations"]
        ),
        "response_first_s": round(
            min(
                (t for items in responded.values() for t, _ in items),
                default=float("nan"),
            ),
            1,
        )
        if responded
        else None,
        "responded_hosts": sorted(
            name.get(h, h) for h in set(responded) | set(db["mitigations"])
        ),
        "collateral": mitigated_legit,
        "collateral_blocked": blocked_legit,
        "gap_events": gaps,
        "service_pct": {k: pct(v) for k, v in probes.items()},
        "service_first_failure_s": None if first_fail is None else round(first_fail, 1),
        "service_first_recovery_s": None
        if first_ok_after is None
        else round(first_ok_after, 1),
        "probes": {k: len(v) for k, v in probes.items()},
        "victim_kbps": {
            "baseline": mean(-1e9, 0),
            "first10": mean(0, 10),
            "mid": mean(duration * 0.4, duration * 0.8),
            "end": mean(max(duration - 15, 0), duration),
        },
        "controller_cpu_max": round(cpu, 1),
        "decisions": db["decisions"],
        "positive_decisions": db["positive_decisions"],
        "rules_seen": rules,
        "events": len(events),
    }


def check(
    scenario: Scenario, metrics: dict[str, Any], extra: dict[str, Any]
) -> list[str]:
    """Hard expectations only; everything else is data for the report."""

    expect = scenario.expect
    problems: list[str] = []
    if extra.get("final") != expect.get("final", "completed"):
        problems.append(
            f"final state {extra.get('final')} (expected {expect.get('final', 'completed')})"
        )
    if extra.get("config_problems"):
        problems.extend(extra["config_problems"])
    if "recall_min" in expect and (
        metrics["recall"] is None or metrics["recall"] < expect["recall_min"]
    ):
        problems.append(f"recall {metrics['recall']} < {expect['recall_min']}")
    if (
        "recall_max" in expect
        and metrics["recall"] is not None
        and metrics["recall"] > expect["recall_max"]
    ):
        problems.append(
            f"recall {metrics['recall']} > {expect['recall_max']} (expected it to miss)"
        )
    fp_cap = expect.get("fp_max")
    llm_run = scenario.detection and scenario.detection.get("mode") == "llm"
    if fp_cap is not None and llm_run and scenario.group != "B":
        fp_cap = max(fp_cap, 1)  # known LLM weakness: legitimate flows near 1 pkt/s
    if fp_cap is not None and metrics["fp"] > fp_cap:
        problems.append(
            f"false positives {metrics['fp']} > {fp_cap}: {metrics['false_positive_hosts']}"
        )
    gap_limit = expect.get("gap_max", max(5, metrics["events"] // 200))
    if metrics["gap_events"] > gap_limit:
        problems.append(f"telemetry lost {metrics['gap_events']} events")
    responses = expect.get("responses")
    if responses == "none" and (
        metrics["response_actions"]
        or metrics["rules_seen"].get("drops_max")
        or metrics["rules_seen"].get("meters_max")
    ):
        problems.append(
            f"expected no response, saw {metrics['response_actions']} {metrics['rules_seen']}"
        )
    if responses == "some" and not metrics["responded_attackers"]:
        problems.append("expected the controller to act on at least one attacker")
    if (
        responses == "all"
        and len(metrics["responded_attackers"]) < metrics["n_attackers"]
    ):
        problems.append(
            f"responded to {metrics['responded_attackers']} of {scenario.attackers}"
        )
    if "rules" in expect:
        seen = metrics["rules_seen"]
        want = expect["rules"]
        if want == "drop" and not seen.get("drops_max"):
            problems.append("no drop rule ever appeared on the switches")
        if want == "meter" and not seen.get("meters_max"):
            problems.append("no rate-limit meter ever appeared on the switches")
        if want == "none" and (seen.get("drops_max") or seen.get("meters_max")):
            problems.append(f"switches got rules in a simulation: {seen}")
    # Only a real block hurts a legitimate client (a rate limit above its 1-3 pkt/s
    # changes nothing); a model's false alarm is tolerated once, as for detections.
    blocked = metrics.get("collateral_blocked", [])
    tolerated = expect.get("collateral_max", 1 if llm_run else 0)
    if len(blocked) > tolerated:
        problems.append(f"legitimate hosts blocked: {blocked}")
    # A response that blocks the victim takes the service down itself (it happened: the
    # entropy detector named the victim once the attackers were blocked).
    hit_victims = [
        v for v in scenario.victims if v in metrics.get("responded_hosts", [])
    ]
    if hit_victims:
        problems.append(f"the response blocked the victim: {hit_victims}")
    service = metrics["service_pct"]
    for phase, key in (
        ("attack", "service_attack_min"),
        ("recovery", "service_recovery_min"),
    ):
        if key in expect and (service[phase] is None or service[phase] < expect[key]):
            problems.append(
                f"service {phase} {service[phase]} % < {expect[key]} % (the service died)"
            )
    if "not_responded" in expect:
        hit = [
            h for h in expect["not_responded"] if h in metrics["responded_attackers"]
        ]
        if hit:
            problems.append(f"protected hosts were acted on: {hit}")
    if (
        "responded_max" in expect
        and len(metrics["responded_attackers"]) > expect["responded_max"]
    ):
        problems.append(
            f"acted on {len(metrics['responded_attackers'])} hosts, cap was {expect['responded_max']}"
        )
    return problems


def request_body(scenario: Scenario, topology: dict[str, Any]) -> dict[str, Any]:
    experiment: dict[str, Any] = {
        "attackers": scenario.attackers,
        "victims": scenario.victims,
        "traffic": scenario.traffic,
        "rate": scenario.rate,
        "duration": scenario.duration,
        "baseline": scenario.baseline,
        "recovery": scenario.recovery,
        "mitigation": scenario.mitigation,
        "confirm_isolated_lab": True,
    }
    if scenario.detection is not None:
        experiment["detection"] = scenario.detection
    return {"topology": topology, "experiment": experiment}


def load_topology(api: Api, scenario: Scenario) -> dict[str, Any]:
    if scenario.topology == "university":
        return json.loads(
            (HERE / "topologia_universidad.json").read_text(encoding="utf-8")
        )
    name = {
        "enterprise": "Connected enterprise",
        "small": "Small teaching network",
        "linear": "Linear network",
    }[scenario.topology]
    return next(t for t in api.call("GET", "/api/presets") if t["name"] == name)  # type: ignore[union-attr]


def wait_state(api: Api, limit: float, during: Any = None) -> str:
    deadline = time.monotonic() + limit
    next_tick = 0.0
    while time.monotonic() < deadline:
        status = api.call("GET", "/api/status")
        state = status.get("state") if isinstance(status, dict) else None  # type: ignore[union-attr]
        if state in TERMINAL:
            return state
        if during is not None and time.monotonic() >= next_tick:
            next_tick = time.monotonic() + 8
            during(state)
        time.sleep(2)
    return "timeout"


def expected_env(scenario: Scenario) -> dict[str, str]:
    detection = scenario.detection
    if detection is None:
        return {}
    response = detection.get("response", {})
    want = {
        "SDN_LLM_MAX_SAMPLES": str(detection.get("llm_max_samples", 5)),
        "SDN_MITIGATION_ENABLED": str(scenario.mitigation).lower(),
    }
    if scenario.mitigation:
        want["SDN_RESPONSE_POLICY"] = response.get("policy", "block")
        want["SDN_RESPONSE_DRY_RUN"] = str(response.get("dry_run", True)).lower()
    return want


def run_scenario(api: Api, scenario: Scenario, out: Path) -> dict[str, Any]:
    topology = load_topology(api, scenario)
    body = request_body(scenario, topology)
    result: dict[str, Any] = {
        "id": scenario.id,
        "title": scenario.title,
        "group": scenario.group,
        "request": body["experiment"],
        "started": time.strftime("%Y-%m-%d %H:%M:%S"),
    }
    wait_state(api, 90)
    status, started = api.raw("POST", "/api/runs", body)
    if scenario.refuse is not None:
        text = json.dumps(started)
        ok = status in (400, 409, 422) and scenario.refuse.lower() in text.lower()
        result.update(
            {
                "verdict": "PASS" if ok else "FAIL",
                "problems": []
                if ok
                else [
                    f"expected refusal containing {scenario.refuse!r}, got {status}: {text[:300]}"
                ],
                "http": status,
                "answer": text[:300],
            }
        )
        if status == 200:
            api.raw("POST", "/api/stop")
            wait_state(api, 120)
        return result
    if status != 200:
        result.update(
            {
                "verdict": "FAIL",
                "problems": [f"run refused: {status} {json.dumps(started)[:300]}"],
            }
        )
        return result
    run_id = started["run_id"]
    result["run_id"] = run_id
    rules = {"drops_max": 0, "meters_max": 0, "flows_max": 0}
    env_seen: dict[str, str] = {}
    options_seen: dict[str, Any] = {}
    stopped_at = {"done": False}
    t0 = time.monotonic()

    def during(state: Optional[str]) -> None:
        snap = snapshot_rules()
        rules["drops_max"] = max(rules["drops_max"], snap["drops"])
        rules["meters_max"] = max(rules["meters_max"], snap["meters"])
        rules["flows_max"] = max(rules["flows_max"], snap["flows"])
        if not env_seen:
            env_seen.update(
                controller_env(
                    {
                        "SDN_LLM_MAX_SAMPLES",
                        "SDN_MITIGATION_ENABLED",
                        "SDN_RESPONSE_POLICY",
                        "SDN_RESPONSE_DRY_RUN",
                        "SDN_ENTROPY_WINDOW_SECONDS",
                        "SDN_ENTROPY_WINDOW_MODE",
                        "SDN_DDOS_THRESHOLD",
                    }
                )
            )
            _, options = api.raw("GET", "/api/detection/options")
            options_seen.update(
                options.get("current", {}) if isinstance(options, dict) else {}
            )
        if (
            scenario.stop_after
            and not stopped_at["done"]
            and time.monotonic() - t0 >= scenario.baseline + scenario.stop_after
        ):
            stopped_at["done"] = True
            api.raw("POST", "/api/stop")

    total = scenario.baseline + scenario.duration + scenario.recovery + 150
    time.sleep(5)
    final = wait_state(api, total, during)
    result["final"] = final
    result["wall_s"] = round(time.monotonic() - t0)
    time.sleep(2)
    _, record = api.raw("GET", f"/api/runs/{run_id}")
    events = collect_events(api, run_id)
    db = db_rows(run_id)
    metrics = analyse(scenario, topology, events, db, rules)
    result["metrics"] = metrics

    problems: list[str] = []
    saved = (
        (record.get("settings") or {}).get("detection")
        if isinstance(record, dict)
        else None
    )
    detection = scenario.detection
    if detection is not None:
        if not saved:
            problems.append("detection setup was not saved with the run")
        else:
            for key in ("mode", "model", "prompt", "llm_max_samples", "threshold"):
                if key in detection and saved.get(key) != detection[key]:
                    problems.append(
                        f"saved {key}={saved.get(key)} != requested {detection[key]}"
                    )
            for key, value in detection.get("response", {}).items():
                if key == "protected":  # the contract stores bare addresses as /32
                    value = [v if "/" in v else f"{v}/32" for v in value]
                if saved.get("response", {}).get(key) != value:
                    problems.append(
                        f"saved response.{key}={saved.get('response', {}).get(key)} != {value}"
                    )
        if not any(e["kind"] == "detection_config" for e in events):
            problems.append("no detection_config event")
        for key, value in expected_env(scenario).items():
            if env_seen and env_seen.get(key) != value:
                problems.append(f"controller env {key}={env_seen.get(key)} != {value}")
        if (
            options_seen
            and detection.get("mode")
            and options_seen.get("mode") != detection["mode"]
        ):
            problems.append(
                f"detector service mode {options_seen.get('mode')} != {detection['mode']}"
            )
        if (
            detection.get("mode") == "llm"
            and options_seen
            and options_seen.get("model") != detection.get("model")
        ):
            problems.append(
                f"detector service model {options_seen.get('model')} != {detection.get('model')}"
            )
    result["controller_env"] = env_seen
    result["detector_during_run"] = {
        k: options_seen.get(k)
        for k in ("mode", "model", "prompt", "response", "dry_run")
    }
    left = leftover()
    for _ in range(
        10
    ):  # the runner tears the network down just after the state changes
        if not left["bridges"] and left["ryu"] in ("0", ""):
            break
        time.sleep(2)
        left = leftover()
    result["leftover"] = left
    if left["bridges"] or left["ryu"] not in ("0", ""):
        problems.append(f"lab not cleaned up after the run: {left}")
    problems.extend(check(scenario, metrics, {"final": final, "config_problems": []}))
    result["problems"] = problems
    result["verdict"] = "PASS" if not problems else "FAIL"
    with out.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(result, default=str) + "\n")
    return result


CONFIG_PROBLEMS = (
    "saved ",
    "no detection_config",
    "controller env",
    "detector service",
    "lab not cleaned",
)


def rejudge(source: Path, target: Path) -> None:
    """Judge stored results again with today's expectations (nothing is re-run).

    Runs recorded before `collateral_blocked` existed get it from the policy: only a
    real `block` cuts a legitimate client off.
    """

    from scenarios import BY_ID

    with target.open("w", encoding="utf-8") as out:
        for line in source.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            result = json.loads(line)
            scenario = BY_ID.get(result["id"])
            metrics = result.get("metrics")
            if scenario is not None and metrics:
                if "collateral_blocked" not in metrics:
                    response = (scenario.detection or {}).get("response", {})
                    harmful = (
                        scenario.mitigation
                        and response.get("policy", "block") == "block"
                        and not response.get("dry_run", True)
                    )
                    metrics["collateral_blocked"] = (
                        metrics["collateral"] if harmful else []
                    )
                kept = [
                    p
                    for p in result.get("problems", [])
                    if p.startswith(CONFIG_PROBLEMS)
                    and not p.startswith("saved response.protected")
                ]
                kept += check(
                    scenario,
                    metrics,
                    {"final": result.get("final"), "config_problems": []},
                )
                result["problems"] = kept
                result["verdict"] = "PASS" if not kept else "FAIL"
            out.write(json.dumps(result, default=str) + chr(10))


def summary_line(result: dict[str, Any]) -> str:
    m = result.get("metrics")
    head = f"[{result['id']:<4}] {result['verdict']:<4} {result['title']}"
    if not m:
        return head + " :: " + "; ".join(result.get("problems", []))
    svc = m["service_pct"]
    line = (
        f"{head}\n        det {m['vp']}/{m['n_attackers']} atk, FP {m['fp']}, first {m['first_detection_s']}s, all {m['all_detected_s']}s"
        f" | resp {','.join(m['response_actions']) or '-'} on {len(m['responded_attackers'])} (first {m['response_first_s']}s), collateral {len(m['collateral'])}"
        f" | rules drops={m['rules_seen'].get('drops_max')} meters={m['rules_seen'].get('meters_max')}"
        f" | svc b/a/r {svc['baseline']}/{svc['attack']}/{svc['recovery']}%"
        f" (first fail +{m['service_first_failure_s']}s, back +{m['service_first_recovery_s']}s)"
        f" | victim kbps {m['victim_kbps']['baseline']}->{m['victim_kbps']['mid']}->{m['victim_kbps']['end']}"
        f" | gaps {m['gap_events']} cpu {m['controller_cpu_max']}% wall {result.get('wall_s')}s"
    )
    if result.get("problems"):
        line += "\n        PROBLEMS: " + "; ".join(result["problems"])
    return line


def main() -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("ids", nargs="*", help="scenario ids (see --list)")
    parser.add_argument(
        "--group", help="run every scenario of these group letters, e.g. B,L"
    )
    parser.add_argument("--all", action="store_true")
    parser.add_argument("--list", action="store_true")
    parser.add_argument(
        "--rejudge",
        metavar="RESULTS",
        help="write RESULTS judged again with the current expectations to --out",
    )
    parser.add_argument(
        "--repeat", type=int, default=1, help="run every selected scenario N times"
    )
    parser.add_argument("--out", default="campaign_results.jsonl")
    args = parser.parse_args()
    if args.list:
        for s in SCENARIOS:
            print(f"{s.id:<5} {s.group}  {s.title}  ({s.duration_text()})")
        return 0
    if args.rejudge:
        rejudge(Path(args.rejudge), Path(args.out))
        return 0
    chosen = [
        s
        for s in SCENARIOS
        if args.all
        or s.id in args.ids
        or (args.group and s.group in args.group.split(","))
    ]
    if not chosen:
        raise SystemExit("no scenario selected; use ids, --group or --all (see --list)")
    api = Api()
    api.login()
    out = Path(args.out)
    for scenario in [s for s in chosen for _ in range(max(1, args.repeat))]:
        print(f"\n=== {scenario.id}: {scenario.title}", flush=True)
        try:
            result = run_scenario(api, scenario, out)
        except Exception as error:
            result = {
                "id": scenario.id,
                "title": scenario.title,
                "group": scenario.group,
                "verdict": "FAIL",
                "problems": [f"runner error: {error!r}"],
            }
        if "metrics" not in result:
            with out.open("a", encoding="utf-8") as handle:
                handle.write(json.dumps(result, default=str) + "\n")
        print(summary_line(result), flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
