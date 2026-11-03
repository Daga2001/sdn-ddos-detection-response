# Plan 2: validar las respuestas del controlador y cerrar la evaluación de detección en el lab

Plan aprobado el 2026-10-06. Al final se incluye el **estado actual (2026-10-07)** y las preguntas para revisión.

## Contexto
Ya estaban hechos el servicio `detector` (LLM + entropía, sin Neon), el perfil de prompt `lab` recalibrado con datos del propio lab, la caché del LLM en el controlador y los mecanismos de respuesta (`controller/response.py` política + `controller/enforcer.py` OpenFlow). Faltaba validar con rigor lo que solo se probó una vez, medir el efecto de la respuesta con repeticiones y documentar. Todo en archivos propios; no se tocan archivos del tutor.

## Lo que ya se había verificado (datos reales, base local del lab)
- Recalibración: sobre las mismas 200 muestras del lab, prompt `insdn` → llama3.2:3b DR 33 %, gemma2:2b DR 0 %; prompt `lab` → llama DR 100 % / FAR 4 %, gemma DR 92 % / FAR 2 %. Los 7792 flujos etiquetados (9 corridas, SYN/UDP a 100-1000 pkt/s) separan limpio en `pktrate`: legítimo ≤ 3.6 pkt/s, ataque ≥ 95 pkt/s.
- Con el LLM síncrono, el flujo del atacante tardaba 36 s en aparecer en `flow_stats` (≈76 s de 97 s bloqueado en llamadas al LLM); con la caché de veredictos aparece a los 2 s (723 respuestas de caché frente a 127 llamadas reales).
- `rate_limit` a 50 pkt/s en switches reales: el tráfico hacia la víctima bajó de ~800 a ~25 kbps y se mantuvo hasta terminar el ataque; el LLM limitó también a 4 clientes legítimos (falsos positivos con `pktrate` = 1.0).
- Disponibilidad HTTP con y sin respuesta con una sola corrida por condición: no concluyente.

## Trabajo propuesto
1. Validar en vivo las otras políticas con mitigación activada (LLM + prompt `lab`): `block`, `escalate` y `dry_run`, comprobando con `ovs-ofctl dump-flows` y `meter-stats`.
2. Repeticiones: `--repeat N` en `scripts/lab_runs.py`, N=5 por condición (sin respuesta / `rate_limit` / `block`) y un script de agregación (media ± desviación del % de éxito y la latencia de las sondas legítimas por fase).
3. Falsos positivos y colateral: medir cuántos clientes legítimos son limitados o bloqueados; repetir con lista protegida y con `dry_run`; probar `gemma2:2b` en vivo. El pre-filtro por umbral antes del LLM queda como decisión del tutor (lo haría híbrido).
4. Entropía con datos del lab: barrer `SDN_ENTROPY_K` (1, 2, 3) con ataques de 60 s.
5. Entregables: hoja nueva en `Resultados_TDG_SDN.xlsx`, documento de operación y ampliar `docs/detection-modes.md`.
6. Limpieza y cierre: temporales de la VM, `docker image prune`, apagado seguro.

## Verificación prevista
`pytest`, prueba de cada política en switches reales y en `mitigation_events`, tabla media ± desviación generada por script desde la base, y comprobar que ninguna corrida use Neon.

---

# Estado actual (2026-10-07)

## Hecho desde el plan
- **Política de respuesta y `dry_run` seleccionables en caliente** desde el servicio (`PUT /config`; `scripts/detector.sh set --response block|rate_limit|escalate --dry-run true|false`), sin recrear el runner. Con tests.
- **`--repeat` y `--tag`** en `scripts/lab_runs.py`.
- **Validación en vivo de las tres políticas** (LLM + prompt `lab`, SYN a 1000 pkt/s, mitigación activada):
  - `block`: regla `priority=100 actions=drop` sobre el atacante (7119 paquetes descartados en `s1`).
  - `escalate`: **la primera prueba falló** (el atacante quedaba solo limitado y nunca se bloqueaba). Causa: la regla de límite (prioridad 90) tapa el flujo de reenvío original que ven los detectores, así que dejaba de haber evidencia nueva. Se rediseñó: `ResponseManager.review()` escala a bloqueo según la **tasa que la fuente sigue ofreciendo** (contador de la propia regla de límite, antes del meter), si supera 2× el límite durante `SDN_RESPONSE_ESCALATE_AFTER` s. Revalidado: límite a los ~50 s y `drop` a los 85 s con el meter liberado; los clientes legítimos quedaron solo limitados.
  - `dry_run`: cero reglas en los switches y filas `dry_run_*` en `mitigation_events`.
- **Calidad alineada con el CI del tutor:** `ruff format --check`, `ruff check`, `mypy src/sdn_ddos` y `pytest` (166 pasan, cobertura 81 %, mínimo 80 %) y `bash -n` de los scripts; además 4 tests de la caché que requieren Ryu (se saltan fuera de su entorno).

## Pendiente
- `scripts/summarize_runs.py` (agregación por fase y condición) y un script que encadene las condiciones.
- Matriz de repeticiones (N=5 × sin respuesta / `rate_limit` / `block`).
- Colateral y falsos positivos: lista protegida, `dry_run` y `gemma2:2b` en vivo.
- Barrido de `SDN_ENTROPY_K` con datos del lab.
- Hoja nueva en el Excel de resultados, documento de operación y limpieza final.

## Limitaciones conocidas
- El LLM sigue dando falsos positivos sobre flujos legítimos de exactamente 1.0 pkt/s (4 de 850 decisiones en vivo; 4 de 100 en la evaluación), de modo que `block` puede causar colateral real; `rate_limit` casi no afecta a clientes de ~1 pkt/s.
- El prompt `lab` cubre ataques de 100 a 1000 pkt/s y una sola topología; los ejemplos del prompt salen de las mismas corridas que la evaluación (filas excluidas, pero no sesiones independientes).
- La GUI solo dibuja como "observadas" las reglas `priority=100 drop`; el límite de tasa se ve con `ovs-ofctl`.
- Una corrida falló al arrancar por un error de UTF-8 del propio lab (transitorio, sin datos).

## Preguntas para el tutor
1. ¿Se acepta mantener dos perfiles de prompt (`insdn` para el dataset y `lab` para el entorno en vivo) y reportar la diferencia de dominio como hallazgo?
2. ¿Se evalúa un pre-filtro por umbral antes del LLM para reducir falsos positivos, aun siendo un detector híbrido, o se reporta el FAR del LLM tal cual?
3. ¿Qué política de respuesta se prefiere por defecto mientras el detector no esté validado (`rate_limit`/`escalate` con lista protegida o `dry_run`, en lugar de `block`)?
4. ¿Cuántas repeticiones por condición se consideran suficientes (N=5 o N=3)?
5. ¿Conviene validar el prompt `lab` con sesiones nuevas e independientes de las de calibración antes de reportar resultados?

---

# Revisión del PR #20 y correcciones (2026-10-08)

La revisión del tutor pidió cuatro correcciones obligatorias. Las cuatro se confirmaron leyendo el código antes de corregirlas y cada una tiene una prueba de regresión.

| # | Hallazgo | Corrección | Prueba |
| --- | --- | --- | --- |
| 1 | Una base nueva no crea `detection_decisions` (solo estaba en la migración), así que las decisiones se perdían y los reportes salían vacíos. | La tabla y su índice se añadieron a `database/schema.sql`; la migración se mantiene para bases ya creadas. | `test_fresh_databases_create_detection_decisions` |
| 2 | Los fragmentos de una respuesta multipart se agrupaban solo por `dpid`: dos sondeos podían mezclarse y esa lista alimentaba detección y mitigación. | Nuevo `controller/stats_buffer.py`: un búfer por `(dpid, xid)`; si empieza otro `xid` se descarta el incompleto y se ignoran sus fragmentos tardíos; al desconectarse el switch se limpia su búfer (y el estado de entropía de ese switch). | `tests/test_stats_buffer.py` (7 casos, incluido el de dos respuestas con el mismo `dpid` y distinto `xid`) y `tests/test_app_modes_stats.py` (manejador y desconexión, entorno de Ryu) |
| 3 | Una alarma de entropía podía bloquear o limitar a la víctima: sus respuestas RST son flujos con ella como origen y pueden superar el 30 %. | `entropy.py` excluye `target_dst` de los candidatos, y el controlador omite además esa dirección antes de responder. | `test_the_victim_is_never_listed_as_a_candidate_even_with_heavy_replies` |
| 4 | El contenedor del lab usaba por defecto el prompt `insdn` (33 % de detección en el lab) y `dry_run=false`. | `compose.detector.yaml` y `.env.example` usan por defecto el prompt `lab` y `SDN_RESPONSE_DRY_RUN=true`; la documentación muestra el estado resultante y cómo activar la aplicación real. | `test_lab_defaults_use_the_calibrated_prompt_and_keep_enforcement_opt_in` |

Observaciones no bloqueantes: la documentación ahora menciona que `escalate` también bloquea si un detector vuelve a marcar a la fuente pasado el periodo de gracia; el PR sigue siendo grande pero es una sola funcionalidad; las casillas de la plantilla del PR las completa quien lo abrió.

Comprobaciones tras las correcciones: `ruff format --check`, `ruff check`, `mypy src/sdn_ddos` y `pytest` pasan (176 tests, cobertura 81 %), y los tests que requieren Ryu pasan en su entorno.

## Efecto sobre las pruebas en curso
- Las corridas de la matriz de repeticiones ya iniciadas se ejecutaron con el código **anterior** a las correcciones 2 y 3. Se tratan como piloto: tras redesplegar se repetirán con el código corregido y se compararán, en lugar de mezclar ambos conjuntos.
- Pendiente de verificar en vivo con el código corregido: que una alarma de entropía con mitigación activada deje reglas solo sobre el atacante y no sobre la víctima (el caso que describe el hallazgo 3).
