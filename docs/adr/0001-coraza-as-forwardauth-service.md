# ADR-0001: Run Coraza as a forwardAuth service, not as a Traefik WASM plugin

- Status: accepted
- Date: 2026-10-21
- Decision log: D-08, D-23 (edge: Traefik v3 + Coraza WAF with OWASP CRS). Fallback R-F2 in the infra design.

## Context

- D-08 puts Coraza with the OWASP Core Rule Set (CRS) in front of every service.
- The planned way was the Coraza http-wasm plugin for Traefik (`jcchavezs/coraza-http-wasm-traefik`).
- Its last release is v0.3.0 (2024-10-29). Its README says the project is in early stages and not for production.
- Test on 2026-10-21 with Traefik v3.7.16: the plugin blocks attacks on `linux/arm64`.
- On `linux/amd64`, Traefik v3.7.16 crashes at start with the plugin: `fatal error: fault`, `unsafe.Slice: len out of range`.
- The same plugin works with Traefik v3.4.1 on `linux/amd64`. Upstream issue: jcchavezs/coraza-http-wasm-traefik#23 (open, Traefik 3.4.3 and later).
- CI runners and the planned VPS are `amd64`. An old Traefik is not an option: v3.7.15 fixes three CVEs.

## Options

| Option | Good | Bad |
|---|---|---|
| A. WASM plugin, pin Traefik v3.4.1 | No extra container | Old Traefik with known CVEs. Plugin unmaintained. |
| B. Coraza Go service behind `forwardAuth` with `forwardBody` | Coraza v3 + CRS v4, maintained. Any CPU. Testable with `go test`. | One more container and one internal hop per request. Response bodies are not inspected. |
| C. ModSecurity + CRS proxy (`owasp/modsecurity-crs`) | Reference CRS engine | Not Coraza (D-08). Second reverse proxy in the path. |

## Decision

- We use option B: the `waf` service in this repo (`waf/`, `cmd/waf/`).
- Traefik calls `http://waf:8080/check` for every request. 200 lets the request pass; 403 blocks it.
- Coraza v3.8.1 with `coraza-coreruleset` v4.25.0 (CRS v4 embedded). Paranoia level 1 (`SYNTHWERK_WAF_PARANOIA_LEVEL`).

## Consequences

- The WAF fails closed: when `waf` does not answer, Traefik returns 500.
- Request bodies up to 1 MiB are inspected. The `buffering` middleware returns 413 above that.
- Response inspection is off. That was the plan for SSE routes anyway (R-F2).
- The WAF logs rule IDs, method and path. It does not log the query or the body.
- Revisit when Traefik ships a working Coraza integration for `amd64`.
- Security impact: low. Same rule set, one more internal hop on the `app` network (no egress).
