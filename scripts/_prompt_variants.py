# ruff: noqa: E501  (CLI help and messages)
import json
import sys

import requests

sys.path.insert(0, "src")
sys.path.insert(0, "scripts")
from compare_llms import synthetic_samples

from sdn_ddos.detection.llm_api import PredictSample

HEAD = "Sos un clasificador de trafico de red. Decidis solo por la tasa de paquetes por segundo (pktrate).\n"
RULE = "Regla: pktrate menor que 1000 -> normal (is_ddos=false). pktrate mayor o igual que 10000 -> ataque (is_ddos=true). Entre 1000 y 10000 -> ambiguo.\n"
FMT = 'Responde SOLO JSON: {"is_ddos": true|false, "confidence": 0.0-1.0}\n'


def v_rates_only(s):
    return (
        HEAD
        + RULE
        + f"Flujo: pktrate={s.pktrate:.2f} paquetes/seg, byterate={s.byterate:.0f} bytes/seg, proto={s.ip_proto}, puerto={s.l4_dst_port}\n"
        + FMT
    )


def v_words(s):
    r = s.pktrate
    scale = (
        "MUY POR DEBAJO de 1000"
        if r < 100
        else "por debajo de 1000"
        if r < 1000
        else "entre 1000 y 10000"
        if r < 10000
        else "por encima de 10000"
    )
    return (
        HEAD
        + RULE
        + f"Flujo: pktrate={r:.2f} paquetes/seg (esto esta {scale}), byterate={s.byterate:.0f} bytes/seg, proto={s.ip_proto}, puerto={s.l4_dst_port}\n"
        + FMT
    )


VARIANTS = {"rates_only": v_rates_only, "words": v_words}
with open("/tmp/pos.txt") as handle:
    real = [PredictSample(**json.loads(line)) for line in handle if line.strip()]
synth = synthetic_samples(60, 7)


def ask(prompt, model="llama3.2:3b"):
    r = requests.post(
        "http://192.168.83.1:11434/api/generate",
        json={
            "model": model,
            "prompt": prompt,
            "stream": False,
            "format": "json",
            "options": {"temperature": 0, "seed": 42},
        },
        timeout=90,
    )
    v = json.loads(r.json()["response"])
    return bool(v["is_ddos"]) if isinstance(v["is_ddos"], bool) else str(
        v["is_ddos"]
    ).lower() == "true", float(v["confidence"])


for name, fn in VARIANTS.items():
    real_out = [ask(fn(s)) for s in real]
    correct = 0
    for s, y in synth:
        d, c = ask(fn(s))
        p = c if d else 1 - c
        correct += int((p >= 0.8) == bool(y))
    print(
        f"{name:11} real-legit-flagged={sum(1 for d, c in real_out if d)}/{len(real)}  synthetic-acc={correct / len(synth):.2f}"
    )
