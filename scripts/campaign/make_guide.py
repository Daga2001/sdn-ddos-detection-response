#!/usr/bin/env python3
# ruff: noqa: E501
"""Turn the campaign scenarios (and, if given, their results) into a step-by-step guide.

  python3 scripts/campaign/make_guide.py [results.jsonl] > guia_pruebas.txt

For every scenario it prints what to fill in the workspace (Experiment and Detection tabs)
so the same run can be repeated by hand, what the campaign expected and, when a results
file is given, what the last execution measured.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any, Optional

sys.path.insert(0, str(Path(__file__).resolve().parent))
from scenarios import SCENARIOS, Scenario

TOPOLOGY = {
    "enterprise": 'preset "Connected enterprise" (selector Choose a preset…)',
    "small": 'preset "Small teaching network"',
    "linear": 'preset "Linear network"',
    "university": 'History ▸ Saved topologies ▸ "Edificio universitario" ▸ Load saved snapshot (o Import con resultados/topologia_universidad.json)',
}
KIND = {"syn": "TCP SYN flood", "udp": "UDP flood", "icmp": "ICMP echo flood"}
GROUP = {
    "V": "Peticiones que el laboratorio debe rechazar",
    "B": "Tráfico de apariencia legítima (el detector debe callar)",
    "L": "Detector LLM, solo detección",
    "E": "Detector de entropía, solo detección",
    "R": "Respuesta del controlador (límite, bloqueo, escalado)",
    "M": "Redes grandes, sin detector, recuperación",
    "T": "Corpus para comparar entropías y umbrales (ventanas completas grabadas, incluye cambios benignos de tráfico)",
    "U": "Modelo de umbral de entropía con respuesta: ¿cambia lo que el servicio aguanta?",
    "S": "Control de la corrida",
}


RESPONSE_FIELDS = {
    "protected": "Never act on · addresses",
    "rate_limit_pps": "Cap · pkt/s",
    "rate_limit_seconds": "Limit lasts · s",
    "escalate_after_seconds": "Escalate after · s",
    "block_seconds": "Block lasts · s",
    "confirm_hits": "Detections needed",
    "confirm_seconds": "Within · s",
}
ENTROPY_FIELDS = {
    "k": "Band width · k",
    "window_seconds": "Window · seconds",
    "window_mode": "Window mode",
    "warmup_windows": "Warm-up windows",
    "consecutive_windows": "Consecutive windows",
    "min_rate": "Minimum rate · pkt/s",
}


def detector_lines(scenario: Scenario) -> list[str]:
    d = scenario.detection
    if d is None:
        return [
            "Detección: no se toca nada (el detector conserva lo que tenía; no hay 'detection' en la corrida)."
        ]
    mode = d["mode"]
    if mode == "off":
        return [
            "Detección: botón 'No detection' (selector superior o pestaña Detection)."
        ]
    if mode == "llm":
        lines = [
            "Detección: botón 'LLM' (selector superior o pestaña Detection)",
            f"   Model = {d.get('model', 'llama3.2:3b')}   Prompt profile = {d.get('prompt', 'lab')}   Samples per poll = {d.get('llm_max_samples', 5)}   Attack probability ≥ {d.get('threshold', 0.8)}",
        ]
    else:
        e = d.get("entropy", {})
        calibrated = {
            "window_seconds": 5,
            "window_mode": "mean",
            "k": 2.5,
            "warmup_windows": 16,
            "consecutive_windows": 2,
            "min_rate": 2,
        }
        merged = {**calibrated, **e}
        lines = [
            "Detección: botón 'Entropy' (selector superior o pestaña Detection)",
            f"   Window · seconds = {merged['window_seconds']}   Window mode = {merged['window_mode']}   Band width · k = {merged['k']}   Warm-up windows = {merged['warmup_windows']}   Consecutive windows = {merged['consecutive_windows']}   Minimum rate = {merged['min_rate']}",
            "   (los valores por defecto ya son los calibrados; 'Restore calibrated values' los repone)",
        ]
        if "update_hold" in e:
            lines.append(
                f"   Advanced entropy settings ▸ hold windows (update hold) = {e['update_hold']}"
            )
        if e.get("alpha_run") is not None:
            lines.append(
                f"   Advanced entropy settings ▸ marcar 'Slower smoothing after warm-up' (alpha {e['alpha_run']})"
            )
    if d.get("poll_seconds") is not None:
        lines.append(f"   Reaction speed ▸ Poll every · s = {d['poll_seconds']}")
    r = d.get("response")
    if scenario.mitigation and r is not None:
        mode_text = (
            "SIMULACIÓN (dry run marcado)"
            if r.get("dry_run", True)
            else "REAL (dry run desmarcado; aparece el aviso rojo 'Real rules will be installed')"
        )
        extra = {k: v for k, v in r.items() if k not in ("policy", "dry_run")}
        lines.append(
            f"Respuesta: marcar 'Apply a response to detected attackers' ▸ Policy = {r.get('policy', 'block')} ▸ {mode_text}"
        )
        for key, value in extra.items():
            label = RESPONSE_FIELDS.get(key)
            if key == "protected":
                value = ", ".join(value)
            lines.append(
                f"   {label} = {value}"
                if label
                else f"   {key} = {value} (sin campo en la interfaz: solo se reproduce por la API)"
            )
    else:
        lines.append("Respuesta: sin marcar ('Apply a response…' desactivado)")
    return lines


def expectation(scenario: Scenario) -> str:
    e = scenario.expect
    parts: list[str] = []
    if scenario.refuse:
        return f"el laboratorio rechaza la petición con un mensaje que menciona «{scenario.refuse}»; no empieza ninguna corrida"
    if "recall_min" in e:
        parts.append(
            f"detecta a {'todos los' if e['recall_min'] >= 1 else 'al menos parte de los'} atacantes"
        )
    if e.get("recall_max") == 0.0:
        parts.append("no detecta nada (no debe haber alarma)")
    if "fp_max" in e:
        parts.append(
            f"como mucho {max(e['fp_max'], 1) if scenario.detection and scenario.detection.get('mode') == 'llm' and scenario.group != 'B' else e['fp_max']} falso(s) positivo(s)"
        )
    responses = e.get("responses")
    if responses == "none":
        parts.append("ninguna respuesta del controlador")
    elif responses == "some":
        parts.append("el controlador responde a algún atacante")
    if e.get("rules") == "drop":
        parts.append("aparecen reglas de descarte (priority=100 drop) en los switches")
    elif e.get("rules") == "meter":
        parts.append("aparece un medidor de límite de tasa en los switches")
    elif e.get("rules") == "none":
        parts.append("no se instala ninguna regla (simulación)")
    if "not_responded" in e:
        parts.append(
            f"no se actúa sobre {', '.join(e['not_responded'])} (protegido) aunque se detecte"
        )
    if "responded_max" in e:
        parts.append(f"se actúa sobre {e['responded_max']} fuentes como máximo")
    if e.get("final") == "stopped":
        parts.append(
            "la corrida termina en 'stopped' y el laboratorio queda limpio (sin puentes ni procesos)"
        )
    if not parts:
        parts.append("la corrida termina y queda registrada con su configuración")
    return "; ".join(parts)


def outcome(result: Optional[dict[str, Any]]) -> list[str]:
    if result is None:
        return []
    verdict = result.get("verdict", "?")
    lines = [
        f"Última ejecución: {verdict}"
        + (f"  (run {result['run_id'][:8]})" if result.get("run_id") else "")
    ]
    m = result.get("metrics")
    if m:
        svc = m["service_pct"]
        lines.append(
            f"   detectó {m['vp']}/{m['n_attackers']} atacantes (FP {m['fp']}, FN {m['fn']})"
            + (
                f"; primero a +{m['first_detection_s']} s, todos a +{m['all_detected_s']} s"
                if m["first_detection_s"] is not None
                and m["all_detected_s"] is not None
                else (
                    f"; primero a +{m['first_detection_s']} s"
                    if m["first_detection_s"] is not None
                    else "; sin detección"
                )
            )
        )
        lines.append(
            f"   respuesta: {', '.join(m['response_actions']) or 'ninguna'} sobre {len(m['responded_attackers'])} atacantes"
            + (
                f" (primera a +{m['response_first_s']} s)"
                if m["response_first_s"] is not None
                else ""
            )
            + f"; legítimos tocados: {len(m['collateral'])} {m['collateral'] or ''}"
        )
        lines.append(
            f"   reglas vistas en los switches: descartes {m['rules_seen'].get('drops_max')} · medidores {m['rules_seen'].get('meters_max')}; sondas HTTP legítimas ok baseline/ataque/recuperación = {svc['baseline']}/{svc['attack']}/{svc['recovery']} %; telemetría perdida {m['gap_events']}"
        )
    for problem in result.get("problems", []):
        lines.append(f"   ⚠ {problem}")
    if result.get("answer"):
        lines.append(f"   respuesta del laboratorio: {result['answer'][:160]}")
    return lines


def main() -> int:
    results: dict[str, dict[str, Any]] = {}
    if len(sys.argv) > 1:
        for line in Path(sys.argv[1]).read_text(encoding="utf-8").splitlines():
            if line.strip():
                row = json.loads(line)
                results[row["id"]] = row  # the last execution of each id wins
    out: list[str] = [
        "GUÍA DE PRUEBAS DEL SISTEMA DE DETECCIÓN (campaña nocturna)",
        "=" * 66,
        "",
        "Cada caso dice qué rellenar en http://localhost:8080 para repetirlo a mano.",
        "Pestaña Experiment: red, atacantes, víctima, tipo de tráfico, tasa, tiempos, casilla de confirmación.",
        "Pestaña Detection (o selector 'Detector' de la barra superior): detector, parámetros y respuesta.",
        "Resultados: pestaña 'Detection' debajo de la topología (matriz VP/FN/FP/VN, métricas, gráfica en tiempo real).",
        "Las mismas pruebas se pueden lanzar por API en la VM:",
        "  bash scripts/campaign/start.sh NOMBRE --group L,E      (o ids sueltos: M1 R3 E1)",
        "  cat ~/campaign/NOMBRE.log",
        "",
    ]
    last_group = ""
    for s in SCENARIOS:
        if s.group != last_group:
            last_group = s.group
            out += ["", f"## Grupo {s.group}: {GROUP[s.group]}", "-" * 66]
        out.append(f"\n[{s.id}] {s.title}")
        out.append(f"Red: {TOPOLOGY[s.topology]}")
        out.append(
            f"Atacantes: {', '.join(s.attackers)}   Víctima(s): {', '.join(s.victims)}   Tráfico: {' + '.join(KIND[k] for k in s.traffic)}   Tasa: {s.rate} pkt/s por atacante y víctima"
        )
        out.append(
            f"Tiempos: Baseline {s.baseline} s · Attack {s.duration} s · Recovery {s.recovery} s   (marcar 'I confirm these hosts belong to my isolated lab')"
        )
        out.extend(detector_lines(s))
        out.append(f"Esperado: {expectation(s)}")
        if s.stop_after:
            out.append(
                f"Pulsar 'Stop lab' a los {s.stop_after} s de empezar el ataque."
            )
        out.extend(outcome(results.get(s.id)))
    print("\n".join(out))
    return 0


if __name__ == "__main__":
    sys.exit(main())
