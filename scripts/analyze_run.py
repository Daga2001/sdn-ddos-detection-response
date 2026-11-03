"""Detailed analysis of one lab run from its recorded events.

The truth is the recorded attack (no model labels). On the VM:
  set -a; . ./.env; set +a
  PYTHONPATH=src python3 scripts/analyze_run.py [RUN_ID_PREFIX]
Without an argument it analyses the latest finished run that had an attack.
"""

import json
import sys
from collections import Counter, defaultdict

import psycopg2

from sdn_ddos.config import DatabaseSettings

prefix = sys.argv[1] if len(sys.argv) > 1 else ""
s = DatabaseSettings.from_env()
c = psycopg2.connect(
    host=s.host, port=s.port, dbname=s.database, user=s.user, password=s.password
)
cur = c.cursor()
if prefix:
    cur.execute(
        "select id::text, started_at, ended_at, topology from lab_runs "
        "where id::text like %s",
        (prefix + "%",),
    )
else:  # latest finished run that had an attack
    cur.execute(
        "select id::text, started_at, ended_at, topology from lab_runs "
        "where ended_at is not null and id in "
        "(select run_id from lab_events where kind='attack_stopped') "
        "order by started_at desc limit 1"
    )
rid, st, en, topo = cur.fetchone()
ip_of = {h["name"]: h["ip"].split("/")[0] for h in topo["hosts"]}
name_of = {v: k for k, v in ip_of.items()}
cur.execute("select kind, ts, data from lab_events where run_id=%s order by ts", (rid,))
events = cur.fetchall()
a0 = next(ts for k, ts, d in events if k == "attack_started")
a1 = next(ts for k, ts, d in events if k == "attack_stopped")
start = next(d for k, ts, d in events if k == "attack_started")
attackers = [ip_of[h] for h in start["attackers"]]
victim = ip_of[start["victims"][0]]
dur = (a1 - a0).total_seconds()


def off(ts):
    return (ts - a0).total_seconds()


print(
    "RUN",
    rid[:8],
    "| baseline %.0f s, attack %.0f s, recovery %.0f s"
    % ((a0 - st).total_seconds(), dur, (en - a1).total_seconds()),
)
print(
    "attackers:",
    [(h, ip_of[h]) for h in start["attackers"]],
    "victim:",
    start["victims"],
    victim,
    "| rate",
    start["rate"],
    start["traffic"],
    "mitigation",
    start["mitigation"],
)

# ---- detection events
det = [(off(ts), d) for k, ts, d in events if k == "detection"]
print("\n== Detecciones (%d eventos) ==" % len(det))
by_src = defaultdict(list)
for t, d in det:
    by_src[d.get("ipv4_src")].append(round(t, 1))
for src, times in by_src.items():
    kind = "ATACANTE" if src in attackers else "LEGITIMO (falso positivo)"
    print("  %-12s %-9s %-26s en t=%s" % (src, name_of.get(src, "?"), kind, times[:8]))
first_att = min(
    (t for src, ts_ in by_src.items() if src in attackers for t in ts_), default=None
)
print("  primera deteccion de un atacante: %s s tras empezar el ataque" % first_att)
print(
    "  atacantes detectados:",
    sorted({name_of[a] for a in by_src if a in attackers}),
    "de",
    [name_of[a] for a in attackers],
)

# ---- probes (legitimate clients) by phase
phases = defaultdict(list)
for k, ts, d in events:
    if k == "service":
        p = "baseline" if ts < a0 else ("ataque" if ts <= a1 else "recuperacion")
        phases[p].append((bool(d["success"]), d.get("latency_ms"), d.get("client")))
print("\n== Servicio para clientes legitimos (sondas HTTP hacia la victima) ==")
for p in ("baseline", "ataque", "recuperacion"):
    v = phases[p]
    if not v:
        continue
    ok = sum(1 for x in v if x[0])
    lat = [x[1] for x in v if x[0] and x[1] is not None]
    print(
        "  %-13s %3d/%-3d exitosas (%.0f%%)  latencia media %.0f ms"
        % (
            p,
            ok,
            len(v),
            100 * ok / len(v),
            sum(lat) / len(lat) if lat else float("nan"),
        )
    )
failed = Counter(
    x[2] for p in ("ataque", "recuperacion") for x in phases[p] if not x[0]
)
print("  sondas fallidas por cliente (ataque+recuperacion):", dict(failed))

# ---- victim load over time
load = []
for k, ts, d in events:
    if k == "links":
        for link in d["links"]:
            if link["link_id"] == "link-" + start["victims"][0] and link.get("rates"):
                load.append((off(ts), link["rates"]["tx_bps"] / 1000.0))
print("\n== Carga hacia la victima (kbps, enlace del switch a la victima) ==")


def avg(lo, hi):
    v = [x for t, x in load if lo <= t < hi]
    return (sum(v) / len(v), len(v)) if v else (float("nan"), 0)


edges = [
    (-1e9, 0, "antes del ataque"),
    (0, 10, "primeros 10 s"),
    (10, 40, "10-40 s"),
    (40, dur, "40 s hasta el fin del ataque"),
    (dur, dur + 15, "15 s tras el fin"),
]
for lo, hi, label in edges:
    m, n = avg(lo, hi)
    print("  %-30s %9.1f kbps  (n=%d)" % (label, m, n))
peak = max((x for t, x in load if 0 <= t <= dur), default=None)
print("  pico durante el ataque: %.0f kbps" % peak if peak else "  sin datos")

# ---- response
cur.execute(
    "select ts, host(ipv4_src), action, duration_seconds, affected_switches "
    "from mitigation_events where run_id=%s order by ts",
    (rid,),
)
mit = cur.fetchall()
print("\n== Respuesta (mitigation_events) ==")
for ts, ip, action, secs, nsw in mit:
    who = "ATACANTE" if ip in attackers else ("VICTIMA" if ip == victim else "LEGITIMO")
    print(
        "  t=%+6.1f s  %-10s %-9s %-22s duracion %ss  switches %s"
        % (off(ts), ip, name_of.get(ip, "?"), action, secs, nsw),
        "<-",
        who,
    )
req = [(off(ts), d) for k, ts, d in events if k == "mitigation_requested"]
obs = [(off(ts), d) for k, ts, d in events if k == "mitigation_observed"]
print("  mitigation_requested: %d, mitigation_observed: %d" % (len(req), len(obs)))
if req:
    print("  primer request en t=%.1f s: %s" % (req[0][0], json.dumps(req[0][1])[:200]))
if obs:
    print(
        "  primera observacion en t=%.1f s: %s"
        % (obs[0][0], json.dumps(obs[0][1])[:260])
    )
    srcs = Counter(
        (d.get("ipv4_src") or d.get("src") or str(sorted(d.keys()))[:60])
        for t, d in obs
    )
    print("  observaciones por origen:", dict(list(srcs.items())[:6]))
legit_hit = [ip for ts, ip, a, secs, n in mit if ip not in attackers and ip != victim]
print(
    "  clientes legitimos afectados por la respuesta:",
    sorted(set(legit_hit)) or "ninguno",
)
