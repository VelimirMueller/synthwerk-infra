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
updated: 2026-10-21
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
| Rate limit | 50 req/s average, burst 100, per client IP |
| Request body | 1 MiB |
| CRS paranoia level | 1 (`SYNTHWERK_WAF_PARANOIA_LEVEL`, 1 to 4) |
| Response inspection | off |
| WAF log fields | status, rule IDs, method, path. No query, no body. |

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

- `tests/waf/waf_test.go` — `Check - known attack - returns 403`, `Check - benign request - returns 200`
- `tests/stack/stack_test.sh` — `edge - SQL injection, path traversal, XSS - 403`, `edge - burst - 429`, `edge - WAF down - 500`

## Changes

| Date | Change |
|---|---|
| 2026-10-21 | First version. Coraza as a forwardAuth service (ADR-0001). |
