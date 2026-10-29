---
title: Edge WAF and rate limit
slug: edge-waf
status: beta
epic: E1
owner: infra
paths: ["waf/**", "cmd/waf/**", "compose/traefik/**"]
api: []
events: []
mcp: []
updated: 2026-10-29
---

# Edge WAF and rate limit

> **In 30 seconds**
> - Every request through the edge passes a rate limit, a body limit and the Coraza WAF with OWASP CRS v4.

## What it does

- Traefik applies the middleware chain `edge-secure` to every public router.
- The rate limit allows 50 requests per second per client IP, with bursts up to 100.
- The body limit rejects request bodies over 1 MiB.
- The WAF checks the request line, the headers and the body with CRS v4 at paranoia level 1.
- The WAF fails closed. When it does not answer, the edge returns 500.

## How to use

1. Add a router in `compose/traefik/dynamic/routes.yml`.
2. Set `middlewares: [edge-secure, strip-service-prefix]` on it.
3. Set `SYNTHWERK_WAF_ENGINE=DetectionOnly` to log matches without blocking while you tune rules.

## Rules and limits

| Rule | Value |
|---|---|
| Rate limit | 50 req/s average, burst 100, per client IP. Traefik must see the client IP: a proxy in front needs `sourceCriterion`. |
| Request body | 1 MiB |
| CRS paranoia level | 1 (`SYNTHWERK_WAF_PARANOIA_LEVEL`, 1 to 4) |
| Response inspection | off |
| WAF log fields | status, rule IDs, method, path. No query, no body. |
| Edge access log | no `RequestPath` (holds the query), no client IP, no headers |
| Edge spans | query values redacted (`REDACTED`); keep `tracing.safeQueryParams` unset |
| Client IP in spans | The collector keeps the IPv4 /24 (`203.0.113.57` becomes `203.0.113.0`) and drops IPv6 in `client.address`, `network.peer.address` and the old names, on every span (`compose/telemetry/otelcol-client-ip.yaml`) |
| Zitadel login UI v2 (auth host only) | Server actions (POST under `/ui/v2/login/` with `Next-Action`) may send `text/plain`; the body is parsed as JSON and inspected, CRS 942290 is off for them (Next.js `$` references). 943120 skips the argument name `sessionId` under `/ui/v2/login/`. 934110 skips `redirect_uri` and `post_logout_redirect_uri` on `/oauth/v2/authorize`, `/oauth/v2/token`, `/oidc/v1/end_session`. Without these rules nobody can sign in through the edge (rules 900223 to 900225). |
| Zitadel admin API | JSON writes from scripts are blocked (for example CRS 930120 on a user profile body). Setup code calls Zitadel inside the stack, not through the edge. |

## Events

| Type | When |
|---|---|
| None. | |

## Errors

| Status | Problem type | Cause |
|---|---|---|
| 403 | none (empty body) | A CRS rule blocked the request. |
| 413 | none | Request body over 1 MiB. |
| 429 | none | Rate limit hit. |
| 500 | none | The WAF did not answer (fail closed). |

## Tests

- `tests/waf/waf_test.go` — `Check - known attack - returns 403`, `Check - benign request - returns 200` (login UI server action, `sessionId` step, localhost `redirect_uri`; and the refusals off the auth host or outside those paths), `Check - login UI action not JSON - refused`
- synthwerk-e2e `tests/auth/*.spec.ts` — invite, passkey and password plus TOTP sign-in through the edge
- `tests/stack/stack_test.sh` — `edge - SQL injection, path traversal, XSS - 403`, `edge - burst - 429`, `edge - WAF down - 500`, `logs - canary query value - absent`, `spans in Tempo - probe span and edge trace - no full client IP`

## Changes

| Date | Change |
|---|---|
| 2026-10-21 | First version. Coraza as a forwardAuth service (ADR-0001). |
| 2026-10-28 | Exclusions for Zitadel login UI v2 and the OIDC redirect arguments (synthwerk#28). |
| 2026-10-29 | The collector truncates client IPs in spans before export (#3). |
