<p>
<picture>
  <source media="(prefers-color-scheme: light)" srcset="assets/banner/hero-v2-light.svg">
  <img alt="SYNTHWERK-INFRA. One command starts the spine. Every box turns green or CI says no. Draft, M1." src="assets/banner/hero-v2-dark.svg" width="100%">
</picture>
</p>

<p>
<picture>
  <source media="(prefers-color-scheme: light)" srcset="assets/readme/lead-v2-light.svg">
  <img alt="synthwerk-infra starts the Synthwerk spine on one machine: edge, WAF, bus, database and telemetry. docker compose up --wait returns when every health check is green. Pulse joins in the next PR." src="assets/readme/lead-v2-dark.svg" width="100%">
</picture>
</p>

<p>
<picture>
  <source media="(prefers-color-scheme: light)" srcset="assets/readme/stats-v2-light.svg">
  <img alt="6 SERVICES, ALL HEALTH-CHECKED. 403 FOR A KNOWN ATTACK. 0 SECRETS IN THE REPO. 8 IMAGES PINNED BY DIGEST" src="assets/readme/stats-v2-dark.svg" width="100%">
</picture>
</p>

<br>

<p>
<img alt="01 WHAT IT DOES. FIVE BOXES. ONE COMMAND." src="assets/readme/divider-what-v2.svg" width="100%">
</p>

<p>
<picture>
  <source media="(prefers-color-scheme: light)" srcset="assets/readme/features-v2-light.svg">
  <img alt="EDGE: Traefik v3 with a rate limit, a 1 MiB body limit and the Coraza WAF with OWASP CRS v4. BUS AND DATABASE: NATS JetStream and PostgreSQL 18 on an internal network. No host ports. TELEMETRY: grafana/otel-lgtm takes OTLP on 4317 and 4318. Grafana on localhost:3000" src="assets/readme/features-v2-dark.svg" width="100%">
</picture>
</p>

<p>
<picture>
  <source media="(prefers-color-scheme: light)" srcset="assets/readme/what-v2-light.svg">
  <img alt="One command: docker compose up --wait starts edge, WAF, bus, database, telemetry and a stub backend. Health checks: Every container has one. CI fails when one service is not healthy in 300 s. WAF test: SQL injection, path traversal and XSS through the edge get 403. A benign request gets 200. No secrets: scripts/init-env.sh writes .env with random dev passwords. .env is git-ignored" src="assets/readme/what-v2-dark.svg" width="100%">
</picture>
</p>

<br>

<p>
<img alt="02 QUICK START. INIT. UP. TEST." src="assets/readme/divider-start-v2.svg" width="100%">
</p>

<p>
<picture>
  <source media="(prefers-color-scheme: light)" srcset="assets/readme/start-v2-light.svg">
  <img alt="Terminal: $ scripts/init-env.sh | $ docker compose up --wait | $ tests/stack/stack_test.sh | # Grafana: http://localhost:3000 | $ docker compose down --volumes" src="assets/readme/start-v2-dark.svg" width="100%">
</picture>
</p>

<p>
<picture>
  <source media="(prefers-color-scheme: light)" srcset="assets/readme/setup-v2-light.svg">
  <img alt="scripts/init-env.sh: Copy .env.example to .env. Fill each empty password with a random value. docker compose up --wait: Build the WAF, start the stack, return when all services are healthy. tests/stack/stack_test.sh: Check health, WAF blocks, limits and fail-closed behaviour. docker compose --profile ollama up --wait: Also start Ollama for local models. Off by default" src="assets/readme/setup-v2-dark.svg" width="100%">
</picture>
</p>

<p>
<picture>
  <source media="(prefers-color-scheme: light)" srcset="assets/readme/startnotes-v2-light.svg">
  <img alt="Needs: Docker with Compose v2 or later, openssl and curl. Go 1.27 only to work on the WAF. First start: Builds the WAF image and pulls about 2 GB of images. Later starts take about 30 s" src="assets/readme/startnotes-v2-dark.svg" width="100%">
</picture>
</p>

<details>
<summary><picture><source media="(prefers-color-scheme: light)" srcset="assets/readme/links-7-v2-light.svg"><img alt="Plain text" src="assets/readme/links-7-v2-dark.svg" width="32%"></picture></summary>

```bash
scripts/init-env.sh                          # write .env with random dev passwords
docker compose up --wait                     # start, wait for every health check
tests/stack/stack_test.sh                    # health, WAF, limits, fail closed
docker compose --profile ollama up --wait    # optional: local models
docker compose down --volumes                # stop and delete the data
```

</details>

<p align="center">
<a href="compose.yaml"><picture><source media="(prefers-color-scheme: light)" srcset="assets/readme/links-1-v2-light.svg"><img alt="Compose file (compose.yaml)" src="assets/readme/links-1-v2-dark.svg" width="32%"></picture></a>
<a href=".env.example"><picture><source media="(prefers-color-scheme: light)" srcset="assets/readme/links-2-v2-light.svg"><img alt="Settings (.env.example)" src="assets/readme/links-2-v2-dark.svg" width="32%"></picture></a>
<a href="tests/stack/stack_test.sh"><picture><source media="(prefers-color-scheme: light)" srcset="assets/readme/links-3-v2-light.svg"><img alt="Stack test (tests/stack/stack_test.sh)" src="assets/readme/links-3-v2-dark.svg" width="32%"></picture></a>
</p>

<br>

<p>
<img alt="03 HOW IT WORKS. EVERY REQUEST PASSES THE WAF." src="assets/readme/divider-how-v2.svg" width="100%">
</p>

<p>
<picture>
  <source media="(prefers-color-scheme: light)" srcset="assets/readme/flow-v2-light.svg">
  <img alt="CLIENT -&gt; EDGE -&gt; WAF -&gt; SERVICE. Traefik asks the WAF first. 200 passes the request on. 403 goes back to the client." src="assets/readme/flow-v2-dark.svg" width="100%">
</picture>
</p>

<p>
<picture>
  <source media="(prefers-color-scheme: light)" srcset="assets/readme/how-v2-light.svg">
  <img alt="403: A CRS rule blocked the request. The WAF logs the rule IDs and the path, never the query or body. 413 and 429: Body over 1 MiB, or more than 50 requests per second from one IP (burst 100). 500: The WAF did not answer. The edge fails closed and lets nothing through" src="assets/readme/how-v2-dark.svg" width="100%">
</picture>
</p>

<br>

<p>
<img alt="04 USAGE. PORTS, NAMES, KNOBS." src="assets/readme/divider-usage-v2.svg" width="100%">
</p>

<p>
<picture>
  <source media="(prefers-color-scheme: light)" srcset="assets/readme/services-v2-light.svg">
  <img alt="edge: Traefik v3.7.16. Routes in compose/traefik/dynamic/. Host port 8080. waf: Coraza v3.8.1 + CRS v4.25 as forwardAuth. Built from waf/. See ADR-0001. bus: NATS 2.15.1 with JetStream. Network data only. database: PostgreSQL 18.6. Network data only. telemetry: grafana/otel-lgtm 0.36.0. Ports 3000, 4317, 4318 on 127.0.0.1. stub: nginx answers 200 at /stub. The WAF test target until pulse exists" src="assets/readme/services-v2-dark.svg" width="100%">
</picture>
</p>

<p>
<picture>
  <source media="(prefers-color-scheme: light)" srcset="assets/readme/config-v2-light.svg">
  <img alt="SYNTHWERK_&lt;SERVICE&gt;_&lt;NAME&gt;: Every setting is an env var with this shape (D-40). See .env.example. SYNTHWERK_WAF_ENGINE: On blocks. DetectionOnly logs matches without blocking. SYNTHWERK_WAF_PARANOIA_LEVEL: CRS paranoia level, 1 to 4. Default 1" src="assets/readme/config-v2-dark.svg" width="100%">
</picture>
</p>

<p>
<picture>
  <source media="(prefers-color-scheme: light)" srcset="assets/readme/reference-v2-light.svg">
  <img alt="Decisions: Why Coraza runs as its own service: docs/adr/0001-coraza-as-forwardauth-service.md. Feature docs: Local stack and edge WAF: docs/features/" src="assets/readme/reference-v2-dark.svg" width="100%">
</picture>
</p>

<p align="center">
<a href="docs/adr/0001-coraza-as-forwardauth-service.md"><picture><source media="(prefers-color-scheme: light)" srcset="assets/readme/links-4-v2-light.svg"><img alt="WAF decision (docs/adr/0001-coraza-as-forwardauth-service.md)" src="assets/readme/links-4-v2-dark.svg" width="32%"></picture></a>
<a href="docs/features/"><picture><source media="(prefers-color-scheme: light)" srcset="assets/readme/links-5-v2-light.svg"><img alt="Feature docs (docs/features/)" src="assets/readme/links-5-v2-dark.svg" width="32%"></picture></a>
<a href="LICENSE"><picture><source media="(prefers-color-scheme: light)" srcset="assets/readme/links-6-v2-light.svg"><img alt="License (LICENSE)" src="assets/readme/links-6-v2-dark.svg" width="32%"></picture></a>
</p>

<br>

<p>
<img alt="05 STATUS. DRAFT. GREEN WHEN HEALTHY." src="assets/readme/divider-status-v2.svg" width="100%">
</p>

<p>
<picture>
  <source media="(prefers-color-scheme: light)" srcset="assets/readme/status-v2-light.svg">
  <img alt="Local compose stack: beta. Edge WAF and rate limit: beta. Pulse service: next PR. Ollama profile: opt-in. OpenTofu and deploy: none yet" src="assets/readme/status-v2-dark.svg" width="100%">
</picture>
</p>

<p>
<picture>
  <source media="(prefers-color-scheme: light)" srcset="assets/readme/now-v2-light.svg">
  <img alt="Now: Draft, milestone M1. Works: Stack, WAF, health checks in CI. Next: Pulse, then deploy targets" src="assets/readme/now-v2-dark.svg" width="100%">
</picture>
</p>

<p>
<picture>
  <source media="(prefers-color-scheme: light)" srcset="assets/readme/checks-v2-light.svg">
  <img alt="go test -race ./...: WAF unit tests: attacks get 403, benign requests get 200. golangci-lint run: Lint with the blueprint config. tests/stack/stack_test.sh: Stack test against the running compose stack. shellcheck scripts/*.sh tests/stack/*.sh: Lint the shell scripts" src="assets/readme/checks-v2-dark.svg" width="100%">
</picture>
</p>

<details>
<summary><picture><source media="(prefers-color-scheme: light)" srcset="assets/readme/links-7-v2-light.svg"><img alt="Plain text" src="assets/readme/links-7-v2-dark.svg" width="32%"></picture></summary>

```bash
go test -race ./...                          # WAF unit tests
golangci-lint run                            # lint
tests/stack/stack_test.sh                    # stack test (stack must run)
shellcheck scripts/*.sh tests/stack/*.sh     # shell lint
```

</details>

<p>
<picture>
  <source media="(prefers-color-scheme: light)" srcset="assets/readme/footer-v2-light.svg">
  <img alt="VM. studio / flagship · open source · look per vm-brand playbook · MIT (c) 2026 Velimir Mueller · -- EOF -- nothing gets in without a 200 --" src="assets/readme/footer-v2-dark.svg" width="100%">
</picture>
</p>
