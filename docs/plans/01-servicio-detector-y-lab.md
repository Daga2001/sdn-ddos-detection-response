# Plan 1: servicio de detección (LLM + entropía) en un contenedor Docker, integrado al lab gráfico, sin Neon

Plan aprobado el 2026-10-06 e implementado después (ver `02-validacion-respuestas-y-estado.md` para el estado actual).

## Contexto
El tutor dejó un lab gráfico en Docker (`compose.lab.yaml`: web / runner / inference + Postgres local). Los detectores propios (LLM vía Ollama y entropía de Shannon) corrían como procesos sueltos en la VM y escribían a Neon. Objetivo: un **contenedor propio** que aloje ambos mecanismos (siempre separados, nunca mezclados), conectarlo al runner del lab para que el panel "Detector / Detection events" funcione, elegir modo y modelo LLM sin reiniciar, y **dejar Neon** (todo a la Postgres local del lab). No se toca ningún archivo del tutor.

## Hallazgos que condicionaron el diseño (verificados en el código)
- El runner llama a `SDN_DDOS_SERVICE_URL` (`POST /predict`, cabecera `X-Api-Key`, esquema de 6 features) y consulta `GET <misma base>/health` cada ~5 s con timeout de 1 s; solo `{"status":"ready"}` pinta "ready" en la GUI (`lab/runtime.py`).
- El runner arranca Ryu con el módulo fijo `sdn_ddos.controller.app`, pero el binario es configurable con `SDN_RYU_MANAGER` y el entorno del runner se hereda al proceso Ryu.
- "Detection events" de la GUI son los eventos `detection` que el controlador emite por `Telemetry`. El camino LLM ya los emitía; el camino de entropía no, y hubo que agregarlo.
- La red `control` es `internal: true` (sin salida): el detector necesita además una red con salida para llegar a Ollama en el host.
- `llm_api.py` ya cumplía el contrato `/predict` + `/health`; `entropy.py` es Python puro y reutilizable. El estado de entropía (EWMA + racha) debe vivir por corrida.

## Diseño
**Servicio `detector`** (un contenedor, dos detectores en rutas separadas, reutilizando `llm_api.py` y `entropy.py`):
- `POST /predict` → LLM. Solo responde si el modo activo es `llm`.
- `POST /entropy/observe {run_id, scope, flows}` → entropía, un `EntropyDetector` por `run_id`. Solo si el modo es `entropy`.
- `GET /config`, `PUT /config`, `GET /models` (con `X-Api-Key`): modo, modelo y (después) prompt y política de respuesta.
- `GET /health` sin auth, sensible al modo.
- Sin acceso a la base de datos: las decisiones las escribe el controlador.

**Controlador** (`controller/app_modes.py`, subclase del controlador del tutor): lee el modo del servicio al iniciar la corrida; la entropía usa un cliente HTTP con la misma interfaz que el detector local; al confirmar emite un evento `detection` para la GUI.

**Cableado sin tocar archivos del tutor:** `compose.detector.yaml` (override de `compose.lab.yaml`), un wrapper `containers/ryu-modes.sh` que sustituye el módulo del controlador, y `scripts/lab_detector.sh` / `scripts/detector.sh`.

**Neon → Postgres local:** `.env` apunta a la Postgres del lab; se aplica la migración `database/migrations/001_detection_decisions.sql`.

## Verificación prevista
Tests unitarios, `/health` desde el runner, prueba sintética de `/entropy/observe`, corridas en la GUI en modo LLM y en modo entropía (decisiones separadas en `detection_decisions`, eventos en la GUI), y comprobar que el runner usa `SDN_PG_HOST=postgres`.

## Riesgos
- Ryu debe cargar `sdn_ddos.controller.app_modes` por módulo.
- Alcanzabilidad de Ollama desde el contenedor (NAT de VMware y firewall del host).
- Reiniciar el contenedor resetea la configuración a los valores de entorno y el calentamiento de la entropía.
