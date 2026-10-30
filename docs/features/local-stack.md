---
title: Local stack
slug: local-stack
status: beta
epic: E1
owner: infra
paths: ["compose.yaml", "compose/**", "scripts/**", ".env.example", "waf/**", "zitadel/**", "studio/**"]
api: []
events: []
mcp: []
updated: 2026-10-30
---

# Local stack

> **In 30 seconds**
> - `docker compose up --wait` starts edge, WAF, bus, database, telemetry, pulse, Zitadel, Mailpit, identity and llm on one machine. Each has a health check.
> - Zitadel is at `http://auth.localhost:8080`. identity and llm are at `/identity` and `/llm` on the edge, with CORS for the local frontends.
> - Pulse streams the status of each part at `/pulse/v1/health/stream`. A stopped part shows as `down` within 30 s.
> - `docker compose --profile studio up --build --wait` also builds and starts studio from a synthwerk-studio checkout, at `http://localhost:3001`.
> - `docker compose --profile vision up --build --wait` also builds and starts vision at `/vision` on the edge. It takes widget tokens from identity.

## What it does

- Starts Traefik v3 (edge), Coraza (WAF), NATS JetStream (bus), PostgreSQL 18 (database) and grafana/otel-lgtm (telemetry).
- Starts a stub backend at `/stub` so the edge has a target.
- Loads a collector overlay into telemetry (`OTELCOL_EXTRA_ARGS`, `compose/telemetry/otelcol-client-ip.yaml`). It truncates client IPs in every span before export: IPv4 to /24, other values dropped.
- Starts synthwerk-pulse. It checks the parts in `compose/pulse/targets.yaml` every 5 s.
- Runs pulse from its GHCR image, pinned by digest (`ghcr.io/velimirmueller/synthwerk-pulse`).
- Routes `/pulse` through the chain `edge-secure-stream`. It has no `buffering` middleware, because buffering holds an SSE response back.
- Pins every image by tag and digest.
- Keeps the bus and the database on an internal network without published ports.
- Starts Ollama only with the `ollama` profile.
- Runs the one-shot `database-init` on every `up` (`compose/database/init.sql`, idempotent). It creates the roles `identity` and `llm`, each owning one schema in the `synthwerk` database, and the role `zitadel` owning the `zitadel` database. It applies the passwords from `.env` on every run.
- Runs the one-shot `zitadel-bootstrap` after Zitadel is healthy: orgs, project, roles, studio app and sign-in policies as code. See [Zitadel setup as code](zitadel-bootstrap.md).
- Starts Zitadel v4.20.0 (`zitadel`) and its Login UI v2 (`zitadel-login`), per D-42. The edge routes them by host name: `/` and `/ui/v2/login*` go to the login UI, everything else goes to the API over h2c.
- Starts synthwerk-identity and synthwerk-llm from their GHCR images, pinned by digest. `/llm` uses the stream chain (no buffering) for SSE.
- Adds the CORS middleware `edge-cors` on `/identity` and `/llm`. Origins come from `SYNTHWERK_CORS_ORIGINS`. Methods are GET, POST, PATCH and OPTIONS. Headers are `Authorization` and `Content-Type`. No credentials.
- Lets gRPC, gRPC-web and Connect pass the WAF on the Zitadel host only (`SYNTHWERK_WAF_GRPC_HOSTS`, set from the Zitadel domain). There they are on the CRS content-type list, and their binary body is not inspected. The URI, query and headers are still checked. Every other host keeps the CRS defaults.
- Answers 400 to a request with more than one `Content-Type` header.
- Leaves JetStream streams (for example `EVT_LLM`) to the services: each service creates its own stream at start, like pulse.
- Runs llm with the provider from `SYNTHWERK_LLM_PROVIDER` (default `ollama`; `fake` in the CI stack test). The model of the alias `default` is `SYNTHWERK_LLM_DEFAULT_MODEL` (default `qwen3.5:4b`). The `ollama` profile also runs the one-shot `ollama-pull`, which pulls that model.
- Lets a chat prompt pass the WAF: only the JSON field `content` of `POST /llm/v1/conversations/<uuid>/messages` skips the CRS rules (rule 900230). The URI, query, headers and other fields are still checked.
- Lets PATCH pass the WAF only on `/identity/v1/orgs/<uuid>/members/<user id>` (org role change, synthwerk#29, rule 900231). CRS still checks the body. Every other route allows GET, HEAD, POST and OPTIONS only.
- identity checks tokens like llm (stack test: the local issuer), writes role changes to Zitadel as `identity-sync`, and publishes its outbox to `EVT_IDENTITY`.
- Gives identity an ES256 widget token key (synthwerk#30). The one-shot `identity-widget-key` makes it once per volume (`identity-keys`, owner 65532, mode 0400) before identity starts; it never leaves the volume. The issuer is `http://localhost:<edge port>/identity`; the key set is at `/identity/.well-known/jwks.json`.
- Routes the widget routes `/identity/v1/apps/<id>/widget-settings` and `/widget-tokens` without `edge-cors`: the widget calls them from customer sites, and identity answers CORS per app from its origin allow-list (synthwerk#38). WAF, rate limit and body limit stay on.
- Sets `SYNTHWERK_IDENTITY_EXPORT_SOURCES=llm=http://llm:8080`: the own-data export holds the llm part (synthwerk#41).
- Gives pulse the token check (`SYNTHWERK_PULSE_OIDC_*`, `SYNTHWERK_PULSE_PLATFORM_ORG_ID`) and Prometheus in telemetry for the edge numbers (`SYNTHWERK_PULSE_PROMETHEUS_URL=http://telemetry:9090`, synthwerk#40). The edge exports `traefik_service_requests_total` and `traefik_service_request_duration_seconds_bucket` with the labels `service` (for example `llm@file`) and `code`.
- Gives Zitadel the alias `auth.localhost` on the `app` network, so services in the stack reach the issuer URL (discovery, keys, token exchange). It works only with the default edge port 8080.
- Profile `studio`: builds synthwerk-studio from a checkout (`SYNTHWERK_STUDIO_SRC`, default `../synthwerk-studio`; `studio/Dockerfile`) and runs it on `127.0.0.1:3001`. It reads the OIDC client from the volume `studio-client` (the bootstrap writes it, owner 65532, mode 0400) and calls identity and pulse inside the stack. The session secret is `SYNTHWERK_STUDIO_SESSION_SECRET`; `NUXT_OIDC_REQUIRE_MFA` follows `SYNTHWERK_ZITADEL_MFA_GATE`.
- Profile `vision`: builds synthwerk-vision from a pinned commit of its main branch (`SYNTHWERK_VISION_SRC` builds a local checkout instead). synthwerk-vision publishes images only from `develop`, which it does not have yet. `SYNTHWERK_VISION_BACKEND` picks the model at build: `siglip` (default, about 1.5 GB of weights) or `mobilenet` (14 MB, CI).
- vision checks widget tokens (synthwerk#76): issuer = identity's widget issuer, key set = `http://identity:8080/.well-known/jwks.json`, audience `synthwerk-api`. The token binds each call to the origin of its app.
- The edge routes only `/vision/v1/classifications`, `/vision/v1/images`, `/vision/healthz` and `/vision/readyz`, with the chain `edge-secure` and no `edge-cors` (vision answers CORS from `SYNTHWERK_VISION_CORS_ORIGINS`). The label admin routes answer 404 on the edge.
- The one-shot `vision-admin-token` makes the label admin token once per volume `vision-admin` (synthwerk#44). vision reads its copy (uid 10001, mode 0400) into `SYNTHWERK_VISION_ADMIN_TOKEN` at start. studio reads its copy (uid 65532, mode 0400) into `NUXT_VISION_ADMIN_TOKEN` (`studio/start.mjs`) and calls `NUXT_VISION_URL=http://vision:8000`. The token is in no file in git and in no process argument.
- vision stores uploads per org with a byte and a file quota and a total byte cap (synthwerk#36, #77): `SYNTHWERK_VISION_UPLOAD_QUOTA_BYTES`, `_FILES`, `_TOTAL_BYTES`, `SYNTHWERK_VISION_UPLOAD_WRITERS`. Backend `local` (default, volume `vision-data`) or `s3` (`SYNTHWERK_VISION_STORAGE_BACKEND`).
- Profile `vision-s3`: Moto as an S3 emulator (`objectstore`, data in memory) and the one-shot `objectstore-bucket`. With `SYNTHWERK_VISION_STORAGE_BACKEND=s3`, vision stores uploads there and `/readyz` checks the bucket.
- `tests/stack/issuer.sh setup` makes a local token issuer for the stack test: an RSA key, its key set on the stub (`/issuer/jwks.json`), and `.env` lines that point llm, identity and pulse at it (pulse platform org `stack-platform`). Without it, llm trusts Zitadel (`http://auth.localhost:8080`), and its `jwks` readiness check stays `degraded` until #28/#30 wire the Zitadel audience and key set.

## How to use

1. Run `scripts/init-env.sh`. It writes `.env` with random dev passwords.
   For the stack test, also run `tests/stack/issuer.sh setup` (llm then answers with the fake provider).
   For a real model, run `docker compose --profile ollama up --wait` instead of step 2.
2. Run `docker compose up --wait`.
3. Run `tests/stack/stack_test.sh`.
4. Open Grafana at `http://localhost:3000`.
   For studio, run `docker compose --profile studio up --build --wait` and open `http://localhost:3001`. Sign-in needs the default edge port 8080.
   For vision, add `--profile vision` (and `--profile vision-s3` with `SYNTHWERK_VISION_STORAGE_BACKEND=s3`). The stack test then also checks vision.
5. Watch the status: `curl -N http://127.0.0.1:8080/pulse/v1/health/stream`.
6. Open Zitadel at `http://auth.localhost:8080`. Browsers and curl send `*.localhost` to 127.0.0.1.
   Mails from Zitadel (invites, verification) land in Mailpit at `http://127.0.0.1:8025` (D-49).
7. After a pull, run `scripts/init-env.sh` again. It appends new keys to `.env` and keeps the existing values.
8. Stop with `docker compose down`. Add `--volumes` to delete the data. This also deletes the Zitadel instance.

## Rules and limits

| Rule | Value |
|---|---|
| Edge port on the host | `127.0.0.1:8080` (`SYNTHWERK_EDGE_HTTP_PORT`) |
| Telemetry ports on the host | `127.0.0.1:3000` UI, `4317` OTLP gRPC, `4318` OTLP HTTP |
| Studio port on the host | `127.0.0.1:3001` (`SYNTHWERK_STUDIO_PORT`), profile `studio` only. Redirect URIs for `:3000` (pnpm dev) and `:3001` are in the bootstrap default. |
| Other edge port | Set `SYNTHWERK_EDGE_HTTP_PORT`, `SYNTHWERK_ZITADEL_EXTERNAL_PORT` and `SYNTHWERK_ZITADEL_PUBLIC_URL` together (for example 18080), and export `SYNTHWERK_EDGE_HTTP_PORT` for the stack test. Containers then cannot reach the issuer URL: studio sign-in and Zitadel tokens in services need 8080. |
| Vision upload size | 1 MiB (`SYNTHWERK_VISION_MAX_UPLOAD_BYTES`), the edge body limit. |
| Vision quotas in the stack | 100 MiB and 1000 files per org, 500 MiB for all orgs (`.env.example`). CI: 3 files per org. |
| Vision admin token | Made once per volume `vision-admin`; `docker compose down --volumes` makes a new one. |
| Widget key | Made once per volume; `docker compose down --volumes` makes a new key (widget tokens issued before fail). |
| New images and older images | The pinned identity, llm and pulse images predate synthwerk#30, #38, #40 and #41. They ignore the new variables, and the stack test skips those checks with a `skip:` line. |
| Bus and database ports on the host | none |
| Networks | `edge` (published), `app`, `data` and `zitadel-hooks` (internal; `zitadel-hooks` = Zitadel and identity (`172.31.250.10`) only, subnet `172.31.250.0/28`), `models` (Ollama egress) |
| Health check timeout in CI | 300 s |
| Service env | `SYNTHWERK_PLATFORM_ENV`, `OTEL_EXPORTER_OTLP_ENDPOINT`, `OTEL_SERVICE_NAME` (anchor `x-service-env`) |
| Service OTLP | gRPC on `telemetry:4317` (anchor `x-service-env`). The edge sends OTLP HTTP on 4318 from `traefik.yml`. |
| Pulse check interval | 5 s per target. Down after 2 failed checks, up after 3 good checks. |
| Zitadel URL | `http://auth.localhost:8080`. Domain, port, secure flag and URL come from `SYNTHWERK_ZITADEL_*`. They must match the public URL, else Zitadel answers "Instance not found". They are fixed at the first start of a volume. |
| Dev VPS (D-42) | `SYNTHWERK_ZITADEL_EXTERNAL_DOMAIN=synthwerkauth.velimir-mueller.de`, `_EXTERNAL_PORT=443`, `_EXTERNAL_SECURE=true`, `_PUBLIC_SCHEME=https`, `_PUBLIC_URL=https://synthwerkauth.velimir-mueller.de` |
| Generated secrets | `*_PASSWORD`, `*_SECRET` (48 hex characters), `*_MASTERKEY` (32 hex characters), by `scripts/init-env.sh` |
| Service database roles | `identity` and `llm`: own schema, `search_path` set, CONNECT and CREATE on `synthwerk` only (the migrations run `CREATE SCHEMA IF NOT EXISTS`). `zitadel`: owns the `zitadel` database. No role can reach another role's schema or database. |
| Zitadel containers | Run as root without capabilities (`cap_drop: ALL`, `no-new-privileges`, read-only). The login UI must read the PAT file that the API writes into the root-owned volume `zitadel-bootstrap`. The IAM owner PAT goes to a separate volume, `zitadel-admin`, which the login UI does not mount. |
| Memory (measured 2026-10-23, idle) | zitadel 92 MiB, zitadel-login 82 MiB, identity 51 MiB, llm 10 MiB. The spike measured 230–360 MiB for Zitadel after sign-ins. The whole stack is about 1.4 GiB, of which telemetry is about 870 MiB. The 7.7 GiB VPS has room. |

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
- `tests/stack/stack_test.sh` — `database-init, zitadel-bootstrap - one-shot - exited 0`
- `tests/stack/stack_test.sh` — `edge - identity, llm, Zitadel (ready, OIDC discovery, login UI, gRPC-web) - 200; SQL injection on the auth host - 403`
- `tests/stack/stack_test.sh` — `database - role llm - no access to schema identity or database zitadel`
- `tests/stack/stack_test.sh` — `CORS preflight - allowed origin - allow-origin set; foreign origin - not set`
- `tests/stack/stack_test.sh` — `spans in Tempo - OTLP probe with 203.0.113.57 - stored as 203.0.113.0, IPv6 dropped; edge request - no full client IP in its trace`
- `tests/waf/waf_test.go` — `gRPC, gRPC-web, Connect proto on the gRPC host - 200; gRPC on another or a lookalike host - 403; unknown content type - 403; SQL injection in a gRPC-web query - 403; two Content-Type headers - 400`
- `tests/stack/stack_test.sh` — `llm - no or forged token - 401, no message stored; signed-in send - 5 deltas spread over >= 900 ms through edge and WAF, then done; other user - 404; SQL and HTML in content - 200, in the query - 403; facts on EVT_LLM without text; logs without text`
- `tests/waf/waf_test.go` — `chat prompt - SQL, HTML, shell in content - 200; same text in another field, the query, a header, another route or GET - 403`
- `tests/stack/stack_test.sh` — `apps and widget - owner creates an app; widget settings and preflights from the app origin reach identity, foreign origin 403; widget token iss and origin; P-256 key set on the edge` (skipped with an older identity image)
- `tests/stack/stack_test.sh` — `export - llm part, complete` and `llm consumer llm-user-deleted on EVT_IDENTITY` (skipped with older images)
- `tests/stack/stack_test.sh` — `pulse - metrics 401 without a token, 403 as member, edge services from Prometheus as operator; stream with an operator token` (skipped with an older pulse image)
- `tests/stack/stack_test.sh` — `studio - home 200, health, apps and labels 401 without a session; studio container reaches the vision label admin with its token - 200` (profile studio only)
- `tests/stack/stack_test.sh` — `vision - readyz model ok; classification without, with a forged or a user token - 401; widget token from another origin - 403; widget token from the app origin - 200; upload - 201, past the file quota - 507, objects under the org in the backend; s3 - bucket check ok; label admin on the edge - 404; admin token inside the stack - 200, wrong token - 401` (profile vision only)
- `.github/workflows/ci.yml` job `stack` — `docker compose up --wait` with the profiles `vision`, `vision-s3` and `studio` (MobileNet, S3 emulator, file quota 3), and the stack test

## Changes

| Date | Change |
|---|---|
| 2026-10-21 | First version. Pulse slot open for synthwerk#26. |
| 2026-10-21 | Pulse joins the stack (synthwerk#24, synthwerk#26). |
| 2026-10-23 | Zitadel, identity and llm join the stack, with database roles, CORS and gRPC through the WAF (SW-M2-0.4). |
| 2026-10-28 | Mailpit catches Zitadel mail in local and ci (synthwerk#28, D-49). |
| 2026-10-23 | The one-shot `zitadel-bootstrap` joins the stack; the admin PAT moves to the volume `zitadel-admin` (synthwerk#28 task 2). |
| 2026-10-23 | Network `zitadel-hooks` (Zitadel to identity Actions) and the volume `zitadel-hooks` for the signing key (synthwerk#28 task 5). |
| 2026-10-28 | llm streams chat answers: provider and token issuer from the env, WAF rule for prompts, `ollama-pull`, stack test with a local issuer (synthwerk#32). |
| 2026-10-29 | Telemetry: collector overlay truncates client IPs in spans (#3). |
| 2026-10-28 | Org roles: identity token check, Zitadel grant writes as `identity-sync`, relay to `EVT_IDENTITY`, PATCH on the member route through CORS and WAF (synthwerk#29). |
| 2026-10-30 | Widget key and issuer, widget routes without edge CORS, export source llm, pulse token check and Prometheus, Zitadel issuer alias, studio profile (synthwerk#30, #37, #38, #40, #41). |
| 2026-10-30 | Pins identity, llm and pulse images published from `develop` by `deploy.yml`; llm gets `SYNTHWERK_LLM_IDENTITY_URL`, studio gets `NUXT_LLM_URL` (synthwerk#39). |
| 2026-10-30 | Vision joins the stack with the profiles `vision` and `vision-s3`: widget tokens, label admin token shared with studio, upload quotas, S3 emulator; CI runs them with studio (synthwerk#36, #44, #76, #77). |
