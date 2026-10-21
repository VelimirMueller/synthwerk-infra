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
> - `docker compose up --wait` starts edge, WAF, bus, database and telemetry on one machine. Each has a health check.

## What it does

- Starts Traefik v3 (edge), Coraza (WAF), NATS JetStream (bus), PostgreSQL 18 (database) and grafana/otel-lgtm (telemetry).
- Starts a stub backend at `/stub` so the edge has a target.
- Pins every image by tag and digest.
- Keeps the bus and the database on an internal network without published ports.
- Starts Ollama only with the `ollama` profile.

## How to use

1. Run `scripts/init-env.sh`. It writes `.env` with random dev passwords.
2. Run `docker compose up --wait`.
3. Run `tests/stack/stack_test.sh`.
4. Open Grafana at `http://localhost:3000`.
5. Stop with `docker compose down`. Add `--volumes` to delete the data.

## Rules and limits

| Rule | Value |
|---|---|
| Edge port on the host | `127.0.0.1:8080` (`SYNTHWERK_EDGE_HTTP_PORT`) |
| Telemetry ports on the host | `127.0.0.1:3000` UI, `4317` OTLP gRPC, `4318` OTLP HTTP |
| Bus and database ports on the host | none |
| Networks | `edge` (published), `app` and `data` (internal), `models` (Ollama egress) |
| Health check timeout in CI | 300 s |

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
- `.github/workflows/ci.yml` job `stack` — `docker compose up --wait` and the stack test

## Changes

| Date | Change |
|---|---|
| 2026-10-21 | First version. Pulse slot open for synthwerk#26. |
