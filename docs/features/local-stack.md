---
title: Local stack
slug: local-stack
status: beta
epic: E1
owner: infra
paths: ["compose.yaml", "compose/**", "scripts/**", ".env.example", "waf/**", "zitadel/**", "studio/**", "cmd/zitadel-bootstrap/**"]
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
> - `docker compose --profile vision up --wait` also starts vision (published image) at `/vision` on the edge. It takes widget tokens from identity.
> - The mascot (public helper, synthwerk#48) answers at `/mascot/v1/answers` without sign-in. Its only network is shared with the edge and has no route out.
> - Studio has its own Postgres database `studio` and role `studio` for the page builder (synthwerk#107). The password is made in a volume at the first start.
> - Studio relays its page builder events to the stream `EVT_STUDIO` with its own NATS user `studio`; identity shows them in the org audit list (synthwerk#106).

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
- Routes the llm widget chat routes `/llm/v1/conversations`, `/llm/v1/conversations/<id>` and `/llm/v1/conversations/<id>/messages` without `edge-cors` (router `llm-widget`, stream chain). llm answers CORS there itself: an origin with an app in identity (llm asks `GET /internal/v1/widget-origins` and caches the answer) or `SYNTHWERK_LLM_CORS_ORIGINS` (default: the edge list `SYNTHWERK_CORS_ORIGINS`). Every other origin gets 403 on the preflight and no CORS headers. The other llm routes keep `edge-cors`.
- The edge has no route for `/identity/internal/*` (404). Those routes answer only inside the stack.
- Sets `SYNTHWERK_IDENTITY_EXPORT_SOURCES=llm=http://llm:8080`: the own-data export holds the llm part (synthwerk#41).
- Account delete (synthwerk#41): identity mounts the volume `studio-client` read-only and reads the studio client id from `SYNTHWERK_IDENTITY_ID_TOKEN_CLIENT_FILE=/zitadel/studio/studio-client.json` per call. `DELETE /v1/me` takes the studio's fresh ID token in `X-Synthwerk-Id-Token`; its `aud` must be that client id. Studio calls identity inside the stack (BFF): the edge allows no DELETE and no such header.
- Audience of Zitadel tokens: `aud` is `[client id, project id]`, never `synthwerk-api`. The `*_OIDC_AUDIENCE` default `synthwerk-api` fits only the stack test issuer. With Zitadel tokens, run `scripts/zitadel-audience.sh` after `up`: it writes the project id as the audience of identity, llm and pulse to `.env` and recreates them.
- Gives llm a second token issuer for widget tokens (synthwerk#30): `SYNTHWERK_LLM_WIDGET_ISSUER` (default: identity's widget issuer), `SYNTHWERK_LLM_WIDGET_JWKS_URL` (`http://identity:8080/.well-known/jwks.json`) and `SYNTHWERK_LLM_WIDGET_AUDIENCE` (`synthwerk-api`). Widget tokens chat on create, read and send from their `synthwerk:origin` only; export and AI settings refuse them (403). The stack test checks both.
- Gives pulse the token check (`SYNTHWERK_PULSE_OIDC_*`, `SYNTHWERK_PULSE_PLATFORM_ORG_ID`) and Prometheus in telemetry for the edge numbers (`SYNTHWERK_PULSE_PROMETHEUS_URL=http://telemetry:9090`, synthwerk#40). The edge exports `traefik_service_requests_total` and `traefik_service_request_duration_seconds_bucket` with the labels `service` (for example `llm@file`) and `code`.
- Gives Zitadel the alias `auth.localhost` on the `app` network, so services in the stack reach the issuer URL (discovery, keys, token exchange). It works only with the default edge port 8080.
- Profile `studio`: builds synthwerk-studio from a checkout (`SYNTHWERK_STUDIO_SRC`, default `../synthwerk-studio`; `studio/Dockerfile`) and runs it on `127.0.0.1:3001`. It reads the OIDC client from the volume `studio-client` (the bootstrap writes it, owner 65532, mode 0400) and calls identity and pulse inside the stack. The session secret is `SYNTHWERK_STUDIO_SESSION_SECRET`; `NUXT_OIDC_REQUIRE_MFA` follows `SYNTHWERK_ZITADEL_MFA_GATE`.
- Profile `vision`: runs the image synthwerk-vision publishes from `develop` (`deploy.yml`), pinned by digest. Model SigLIP 2 (about 1.5 GB of weights in the image), linux/amd64 only: on an arm64 Mac it runs under emulation and loads slowly.
- vision checks widget tokens (synthwerk#76): issuer = identity's widget issuer, key set = `http://identity:8080/.well-known/jwks.json`, audience `synthwerk-api`. The token binds each call to the origin of its app.
- The edge routes only `/vision/v1/classifications`, `/vision/v1/images`, `/vision/healthz` and `/vision/readyz`, with the chain `edge-secure` (WAF, rate limit, 1 MiB body limit) and no `edge-cors`. vision answers CORS itself: an origin with an app in identity (`SYNTHWERK_VISION_IDENTITY_URL`, cached lookup of `GET /internal/v1/widget-origins`) or the static list `SYNTHWERK_VISION_CORS_ORIGINS`; every other origin gets 403 on the preflight (infra#24). The label admin routes answer 404 on the edge.
- The one-shot `vision-admin-token` makes the label admin token once per volume `vision-admin` (synthwerk#44). vision reads its copy (uid 10001, mode 0400) into `SYNTHWERK_VISION_ADMIN_TOKEN` at start. studio reads its copy (uid 65532, mode 0400) into `NUXT_VISION_ADMIN_TOKEN` (`studio/start.mjs`) and calls `NUXT_VISION_URL=http://vision:8000`. The token is in no file in git and in no process argument.
- vision stores uploads per org with a byte and a file quota and a total byte cap (synthwerk#36, #77): `SYNTHWERK_VISION_UPLOAD_QUOTA_BYTES`, `_FILES`, `_TOTAL_BYTES`, `SYNTHWERK_VISION_UPLOAD_WRITERS`. Backend `local` (default, volume `vision-data`) or `s3` (`SYNTHWERK_VISION_STORAGE_BACKEND`).
- Profile `vision-s3`: Moto as an S3 emulator (`objectstore`, data in memory) and the one-shot `objectstore-bucket`. With `SYNTHWERK_VISION_STORAGE_BACKEND=s3`, vision stores uploads there and `/readyz` checks the bucket.
- Starts synthwerk-mascot (synthwerk#48) from its GHCR image, pinned by digest (linux/amd64; on an arm64 Mac it runs under emulation and needs the `/tmp` tmpfs). Model and docs index are in the image.
- The mascot's only network is `mascot`: internal, gateway mode `isolated` (the host bridge has no address there), subnet `172.31.251.0/29`. Only the edge (`172.31.251.2`) and the mascot (`172.31.251.3`) are on it. The mascot has no default route, no DNS for outside or stack names, no database, no bus and no telemetry export.
- The edge routes only `/mascot/v1/answers`, `/mascot/healthz` and `/mascot/readyz` (router `mascot`, chain `edge-secure`, no `edge-cors`). The mascot answers CORS itself for `SYNTHWERK_MASCOT_CORS_ORIGINS` (JSON list; default `["http://localhost:3000","http://localhost:3001"]`, the studio public routes).
- `FORWARDED_ALLOW_IPS=172.31.251.2`: uvicorn takes the client address from `X-Forwarded-For` only from the edge. The edge does not trust incoming `X-Forwarded-*` headers, so the mascot limit (6 questions per client a minute, 60 for all) counts real clients. A forged `X-Forwarded-For` changes nothing.
- Studio page builder database (synthwerk#107): `database-init` creates the role `studio` and the database `studio` (owner `studio`). Only `studio` may connect to it; `studio` may not connect to `synthwerk` or `zitadel`. Studio runs its own migrations on the first builder call, in the schema `public`.
- Studio relay to the bus (synthwerk#106): studio connects to `bus` as NATS user `studio` (`SYNTHWERK_NATS_STUDIO_PASSWORD`, made by `scripts/init-env.sh`). `compose/nats/nats.conf` lets that user publish only to `evt.studio.>` and create, read and update only the stream `EVT_STUDIO`; replies come on `_INBOX.>`. Studio creates `EVT_STUDIO` at start. Identity (shared NATS user) reads it with the durable consumer `identity-studio-pages` into `identity.audit_events`. Identity is pinned to `46439b3`.
- The one-shot `studio-db-secret` makes the `studio` password once per volume `studio-db` (48 hex characters, never in `.env` or git). `database-init` reads its copy (uid 70) and applies it on every `up`. `studio/start.mjs` reads its copy (uid 65532) into `NUXT_BUILDER_DATABASE_URL` (`BUILDER_DATABASE_URL_BASE` plus the password). A `NUXT_BUILDER_DATABASE_URL` set in the env wins. Studio joins the network `data` to reach the database.
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
| Studio database password | Made once per volume `studio-db`; `database-init` applies it on every `up`. To rotate: delete the volume `studio-db` (or its files) and run `up` again. |
| Mascot rate limit | 6 questions per client a minute, 60 for all clients (mascot defaults). Over the limit: 429 with `Retry-After`. |
| Widget key | Made once per volume; `docker compose down --volumes` makes a new key (widget tokens issued before fail). |
| New images and older images | The pinned images have the routes of synthwerk#30, #38, #40 and #41. An older image ignores the new variables, and the stack test skips those checks with a `skip:` line. |
| Bus and database ports on the host | none |
| Networks | `edge` (published), `app`, `data`, `zitadel-hooks` and `mascot` (internal; `zitadel-hooks` = Zitadel and identity (`172.31.250.10`) only, subnet `172.31.250.0/28`; `mascot` = edge (`172.31.251.2`) and mascot only, subnet `172.31.251.0/29`, no gateway), `models` (Ollama egress) |
| Health check timeout in CI | 300 s |
| Service env | `SYNTHWERK_PLATFORM_ENV`, `OTEL_EXPORTER_OTLP_ENDPOINT`, `OTEL_SERVICE_NAME` (anchor `x-service-env`) |
| Service OTLP | gRPC on `telemetry:4317` (anchor `x-service-env`). The edge sends OTLP HTTP on 4318 from `traefik.yml`. |
| Pulse check interval | 5 s per target. Down after 2 failed checks, up after 3 good checks. |
| Zitadel URL | `http://auth.localhost:8080`. Domain, port, secure flag and URL come from `SYNTHWERK_ZITADEL_*`. They must match the public URL, else Zitadel answers "Instance not found". They are fixed at the first start of a volume. |
| Dev VPS (D-42) | `SYNTHWERK_ZITADEL_EXTERNAL_DOMAIN=synthwerkauth.velimir-mueller.de`, `_EXTERNAL_PORT=443`, `_EXTERNAL_SECURE=true`, `_PUBLIC_SCHEME=https`, `_PUBLIC_URL=https://synthwerkauth.velimir-mueller.de` |
| Generated secrets | `*_PASSWORD`, `*_SECRET` (48 hex characters), `*_MASTERKEY` (32 hex characters), by `scripts/init-env.sh` |
| Service database roles | `identity` and `llm`: own schema, `search_path` set, CONNECT and CREATE on `synthwerk` only (the migrations run `CREATE SCHEMA IF NOT EXISTS`). `zitadel`: owns the `zitadel` database. `studio`: owns the `studio` database (synthwerk#107). No role can reach another role's schema or database. |
| Backups on dev and prd | Not in this repo yet (no deploy target). The backup job must dump all three databases: `synthwerk`, `zitadel` and `studio` (`pg_dump -Fc` per database, plus `pg_dumpall --globals-only` for the roles). The `studio` dump holds the builder pages, versions and events: losing it loses every published page. Keep the `studio` password in the secret store of the host, not in the dump job's files. Test a restore before go-live. |
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
- `tests/stack/stack_test.sh` — `llm widget CORS - preflight from the app origin on create, read, send - 204 with allow-origin; origin without an app - 403; wrong method - 403; first-party origin - 204; AI settings - edge-cors only; widget read - allow-origin; /identity/internal on the edge - 404`
- `tests/stack/stack_test.sh` — `spans in Tempo - OTLP probe with 203.0.113.57 - stored as 203.0.113.0, IPv6 dropped; edge request - no full client IP in its trace`
- `tests/waf/waf_test.go` — `gRPC, gRPC-web, Connect proto on the gRPC host - 200; gRPC on another or a lookalike host - 403; unknown content type - 403; SQL injection in a gRPC-web query - 403; two Content-Type headers - 400`
- `tests/stack/stack_test.sh` — `llm - no or forged token - 401, no message stored; signed-in send - 5 deltas spread over >= 900 ms through edge and WAF, then done; other user - 404; SQL and HTML in content - 200, in the query - 403; facts on EVT_LLM without text; logs without text`
- `tests/waf/waf_test.go` — `chat prompt - SQL, HTML, shell in content - 200; same text in another field, the query, a header, another route or GET - 403`
- `tests/stack/stack_test.sh` — `apps and widget - owner creates an app; widget settings and preflights from the app origin reach identity, foreign origin 403; widget token iss and origin; P-256 key set on the edge` (skipped with an older identity image)
- `tests/stack/stack_test.sh` — `export - llm part, complete` and `llm consumer llm-user-deleted on EVT_IDENTITY` (skipped with older images)
- `tests/stack/stack_test.sh` — `account delete - identity on the Zitadel issuer, throwaway user with password, TOTP and step-up (prompt=login, max_age=0): no ID token - 403 recent_mfa_required; fresh ID token - 202; Zitadel user removed by identity`
- `tests/stack/stack_test.sh` — `pulse - metrics 401 without a token, 403 as member, edge services from Prometheus as operator; stream with an operator token` (skipped with an older pulse image)
- `tests/stack/stack_test.sh` — `studio - home 200, health, apps and labels 401 without a session; studio container reaches the vision label admin with its token - 200` (profile studio only)
- `tests/stack/stack_test.sh` — `vision - readyz model ok; classification without, with a forged or a user token - 401; widget token from another origin - 403; widget token from the app origin - 200; upload - 201, past the file quota - 507, objects under the org in the backend; s3 - bucket check ok; label admin on the edge - 404; admin token inside the stack - 200, wrong token - 401` (profile vision only)
- `tests/stack/stack_test.sh` — `vision CORS - preflight from the app origin on classifications and images - 204 with one allow-origin; origin without an app - 403; classification answer - allow-origin; upload over 1 MiB - 413 at the edge` (profile vision only)
- `tests/stack/stack_test.sh` — `database - roles identity and llm - no connect to database studio; database studio owned by role studio`
- `tests/stack/stack_test.sh` — `page builder events - EVT_STUDIO exists; builder-check creates a page as owner.demo, publishes it twice and rolls it back; studio relays the 4 events (relayed_at, no relay_error); identity audit list holds created, published, published, rolled_back in order; roll back row has the owner as actor, version 1 after 2; no page text; a second relay of the same rows adds no audit row` (profile studio only)
- `tests/stack/stack_test.sh` — `studio builder database - start.mjs connects as role studio to database studio, may create; password in the volume, not in .env or compose.yaml; role studio - no connect to synthwerk; builder without a session - 401; owner.demo signed in through the studio code flow (password and TOTP), identity on Zitadel - session 200, builder not 503; on 200 - 3 builder tables owned by studio` (profile studio only)
- `tests/stack/stack_test.sh` — `mascot - healthz 200, readyz model and index ok, other paths 404; German and English question - 200 with a passage of docs/infrastructure.md and its GitHub URL; questions 1-6 - 200, 7th - 429 with Retry-After; forged X-Forwarded-For - still 429; second client - 200; preflight from the public site - allowed, foreign origin - not allowed`
- `tests/stack/stack_test.sh` — `mascot isolation - one network, internal, members edge and mascot only; no default route; DNS for example.com, github.com, database, bus, telemetry, identity fails; TCP to 4 outside and gateway addresses fails; control: TCP to the edge works`
- `.github/workflows/ci.yml` job `stack` — `docker compose up --wait` with the profiles `vision`, `vision-s3` and `studio` (published vision image, S3 emulator, file quota 3), and the stack test

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
| 2026-10-30 | llm trusts identity widget tokens on the chat routes (second issuer, synthwerk#30); llm image `4d0d2d2`; stack test: widget token chats from its origin, 403 from another origin and on export and AI settings. |
| 2026-10-30 | identity `5e7587f` reads the studio client id for the account delete step-up (volume `studio-client`, read-only); `scripts/zitadel-audience.sh` sets the project id as audience; vision runs its published image `5d15798` instead of a git build; stack test deletes an account with real Zitadel tokens (synthwerk#41, #36). |
| 2026-10-30 | llm answers CORS on the widget chat routes per app origin (router `llm-widget` without `edge-cors`, `SYNTHWERK_LLM_CORS_ORIGINS`); `/identity/internal/*` is off the edge; identity `dd30bea`, llm `5b5545c` (infra#21 follow-up, synthwerk#34). |
| 2026-10-30 | vision answers CORS per app origin (`SYNTHWERK_VISION_IDENTITY_URL`, vision `596589c`); llm `d387ad6` bounds its origin lookups; stack test: vision preflights, one allow-origin header, 413 over 1 MiB (infra#24). |
| 2026-10-30 | Mascot `f2850fb` joins the stack on the isolated network `mascot` behind the edge (synthwerk#48). Studio gets its own database `studio` and role, password from the one-shot `studio-db-secret`; CI builds studio `1ec1f14` (page builder) (synthwerk#107). |
| 2026-10-30 | identity `b943c91`: the widget token trade answers its preflight for every origin and makes `403 origin_not_allowed` readable, so the widgets show "not allowed" in a browser; the greeting refuses bidi controls (synthwerk-widgets#41). |
| 2026-10-30 | Studio relays its builder events to `EVT_STUDIO` with the restricted NATS user `studio`; identity `46439b3` copies them to the audit list; CI builds studio `41f90ac`; stack test proves publish and roll back reach the audit list (synthwerk#106). |
