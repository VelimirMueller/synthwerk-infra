---
title: Outside watcher
slug: outside-watcher
status: beta
epic: E1
owner: platform
paths: ["watch/**"]
api: []
events: []
mcp: []
updated: 2026-10-23
---

# Outside watcher

> **In 30 seconds**
> - A second, small VPS checks the dev host from outside, takes heartbeats from inside, and alerts to ntfy. Public page: https://status.velimir-mueller.de.

## What it does

- Gatus on `synthwerk-watch` (IONOS VPS, 1 vCPU, 854 MB RAM) checks the dev host and the public sites.
- Caddy in front gets the TLS certificate and serves the public status page.
- The dev host pushes two heartbeats every 5 min: `host` (alive, disk below 85 %) and `vision` (`/readyz` from inside).
- An alert goes to ntfy after 3 failed checks, or after 15 min without a heartbeat. A second alert says when it is fixed.
- pulse watches the stack from inside; this watcher sees what a visitor sees and keeps working when the dev host is down.

## How to use

1. Open https://status.velimir-mueller.de.
2. Subscribe to the topic from `/opt/gatus/.env` (`NTFY_TOPIC`) in the ntfy app.
3. Full detail with errors: `ssh -L 8080:127.0.0.1:8080 synthwerk-watch`, then http://localhost:8080.
4. Deploy a change: copy `watch/` to `/opt/gatus` on the box, then `docker compose up -d --force-recreate`.
5. Dev host side: install `watch/heartbeat/synthwerk-heartbeat.sh` as `/usr/local/bin/synthwerk-heartbeat`, the two units into `/etc/systemd/system/`, and write `/etc/synthwerk/heartbeat.env` (`GATUS_URL`, `HB_TOKEN_HOST`, `HB_TOKEN_VISION`, mode 600). Enable `synthwerk-heartbeat.timer`.

## Rules and limits

| Rule | Value |
|---|---|
| Public page hides | hostnames, URLs, ports, raw errors of the dev host |
| Heartbeat error texts | short, no host names or IPs (they show on the public page) |
| Images | pinned by digest |
| Gatus port 8080 | loopback only; public traffic goes through Caddy |
| Containers | read-only root, no capabilities (Caddy: `NET_BIND_SERVICE` only), memory limits 128 MB / 96 MB |
| Dev host fail2ban | ignores the watcher IP (`/etc/fail2ban/jail.d/00-ignore-watch.local`), else the TCP probe gets banned |
| Firewall (IONOS Cloud Panel policy) | inbound 22, 80, 443 |
| Data | Gatus history in SQLite (a few MB, pruned by Gatus); not backed up, the config in this folder is the backup |

## Events

| Type | When |
|---|---|
| None. | |

## Errors

| Status | Problem type | Cause |
|---|---|---|
| None. | | |

## Tests

- Manual on 2026-10-23: all six checks green; the public API holds no dev host IP and no token.
- Not tested: a heartbeat push with a wrong token is refused.

## Changes

| Date | Change |
|---|---|
| 2026-10-23 | First version. |
