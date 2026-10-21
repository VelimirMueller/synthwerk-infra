---
title: Local stack
slug: local-stack
status: beta
epic: E1
owner: infra
paths: ["compose.yaml", "compose/**", "scripts/**", ".env.example"]
api: []
events: []
mcp: []
updated: 2026-10-21
---

# Local stack

> **In 30 seconds**
> - `docker compose up --wait` starts edge, WAF, bus, database, telemetry and pulse on one machine. Each has a health check.
> - Pulse streams the status of each part at `/pulse/v1/health/stream`. A stopped part shows as `down` within 30 s.

## What it does

- Starts Traefik v3 (edge), Coraza (WAF), NATS JetStream (bus), PostgreSQL 18 (database) and grafana/otel-lgtm (telemetry).
- Starts a stub backend at `/stub` so the edge has a target.
- Starts synthwerk-pulse. It checks the parts in `compose/pulse/targets.yaml` every 5 s.
- Runs pulse from its GHCR image, pinned by digest (`ghcr.io/velimirmueller/synthwerk-pulse`).
- Routes `/pulse` through the chain `edge-secure-stream`. It has no `buffering` middleware, because buffering holds an SSE response back.
- Pins every image by tag and digest.
- Keeps the bus and the database on an internal network without published ports.
- Starts Ollama only with the `ollama` profile.

## How to use

1. Run `scripts/init-env.sh`. It writes `.env` with random dev passwords.
2. Run `docker compose up --wait`.
3. Run `tests/stack/stack_test.sh`.
4. Open Grafana at `http://localhost:3000`.
5. Watch the status: `curl -N http://127.0.0.1:8080/pulse/v1/health/stream`.
6. Stop with `docker compose down`. Add `--volumes` to delete the data.

## Rules and limits

| Rule | Value |
|---|---|
| Edge port on the host | `127.0.0.1:8080` (`SYNTHWERK_EDGE_HTTP_PORT`) |
| Telemetry ports on the host | `127.0.0.1:3000` UI, `4317` OTLP gRPC, `4318` OTLP HTTP |
| Bus and database ports on the host | none |
| Networks | `edge` (published), `app` and `data` (internal), `models` (Ollama egress) |
| Health check timeout in CI | 300 s |
| Service env | `SYNTHWERK_PLATFORM_ENV`, `OTEL_EXPORTER_OTLP_ENDPOINT`, `OTEL_SERVICE_NAME` (anchor `x-service-env`) |
| Service OTLP | gRPC on `telemetry:4317` (anchor `x-service-env`). The edge sends OTLP HTTP on 4318 from `traefik.yml`. |
| Pulse check interval | 5 s per target. Down after 2 failed checks, up after 3 good checks. |

## Events

| Type | When |
|---|---|
| None. | |

## Errors

| Status | Problem type | Cause |
|---|---|---|
| None. | | |

## Tests

- `tests/stack/stack_test.sh` — `stack - every default service - healthy`
- `tests/stack/stack_test.sh` — `pulse stream - stub stopped - down within 30 s, ok after start`
- `.github/workflows/ci.yml` job `stack` — `docker compose up --wait` and the stack test

## Changes

| Date | Change |
|---|---|
| 2026-10-21 | First version. Pulse slot open for synthwerk#26. |
| 2026-10-21 | Pulse joins the stack (synthwerk#24, synthwerk#26). |
