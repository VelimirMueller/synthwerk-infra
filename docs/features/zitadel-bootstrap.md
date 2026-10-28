---
title: Zitadel setup as code
slug: zitadel-bootstrap
status: beta
epic: E1
owner: infra
paths: ["zitadel/**", "cmd/zitadel-bootstrap/**", "compose.yaml", "tests/zitadel/**"]
api: []
events: []
mcp: []
updated: 2026-10-23
---

# Zitadel setup as code

> **In 30 seconds**
> - The one-shot `zitadel-bootstrap` sets up Zitadel after every `up`: orgs, project, roles, the studio app and the sign-in policies.
> - A rerun changes nothing. Nobody clicks in the console (synthwerk#28, task 2).

## What it does

- Finds the platform org `synthwerk` (made at instance creation) and creates the org `demo`.
- Creates the project `synthwerk-api` with role assertion on, so every token carries the roles claim.
- Adds the roles `operator`, `owner`, `admin`, `member` and `end_user` (D-44, D-50).
- Grants the project to `demo` with `admin`, `member` and `end_user`.
- Creates the OIDC app `studio`: web, code and refresh grants, client secret (Basic), JWT access token, roles in the access and ID token.
- Writes the studio client id and secret to `studio-client.json` (mode 0600) in the volume `zitadel-admin`. Without the file, the next run makes a new secret.
- Sets the instance login policy: MFA required (D-47), passkeys allowed, no self-registration (D-51), no hint about unknown user names.
- Sets the password policy: 12 characters minimum with upper, lower, digit and symbol, lockout after 5 tries.
- Sets the access token lifetime to 300 s.
- Creates the Action target `identity-user-created` (`http://identity-hooks:8081/internal/zitadel/actions`) and points the event `user.human.added` at it (synthwerk#28 task 5).
- Writes the target signing key to `identity-signing.key` (mode 0400, owner 65532) in the volume `zitadel-hooks`, which identity reads. Zitadel returns the key in every target search, so each run can write it.
- Creates the test users `operator.test` (platform, `operator`) and `member.demo` (demo, `member`), only when `SYNTHWERK_ZITADEL_TEST_USER_PASSWORD` is set.

## How to use

1. Run `docker compose up --wait`. The bootstrap runs after Zitadel is healthy.
2. Read the result: `docker compose logs zitadel-bootstrap`. The last line lists the org, project and client ids.
3. Check sign-in and claims: `docker compose run --rm --no-deps zitadel-bootstrap selftest`.
4. Change a setting in `zitadel/bootstrap/bootstrap.go`, then `docker compose up --build zitadel-bootstrap`.

## Rules and limits

| Rule | Value |
|---|---|
| Connection | `http://zitadel:8080` with Host = `SYNTHWERK_ZITADEL_EXTERNAL_DOMAIN`. Not through the edge: the WAF allows only GET, HEAD, POST and OPTIONS. |
| Credential | IAM owner PAT of the machine user `bootstrap-admin`, written at instance creation to `zitadel-admin/admin.pat`. It expires 2099-01-01: accepted locally. Before dev, a shorter expiry and a rotation step are an open follow-up. |
| Volume `zitadel-admin` | Mounted by `zitadel` and `zitadel-bootstrap` only. `zitadel-login` mounts `zitadel-bootstrap` (login-client PAT) and cannot read the admin PAT. |
| Policy updates | Zitadel replaces the whole policy on PUT. The bootstrap reads the policy, sets its own fields and sends all fields back. |
| "Not changed" answers | Zitadel answers 400, code 9, when a PUT changes nothing. The bootstrap counts that as success. |
| Studio URIs | Exact `http(s)` URIs, comma list, no wildcard. An `http` URI turns on Zitadel dev mode for the app. |
| Test users | Local and ci only. The password is the `.env` value plus `Aa1!` (complexity policy). Leave the key out on dev and prd. |
| MFA and the session API | The selftest signs in with a password only and still gets a token: Zitadel enforces "MFA required" in the login UI, not in the session API. The access token has no `amr` claim, and the pre-access-token Action gets no session data. Services must not trust MFA from the policy alone: `RequireMFA` stays fail closed ([ADR-0002](../adr/0002-mfa-is-enforced-by-the-zitadel-login-ui-only.md)). |
| Self-registration | Off on every org (`allowRegister: false`, D-51). Users come by invite: create the user, then `POST /v2/users/{id}/invite_code`. |
| Mail | `SYNTHWERK_ZITADEL_SMTP_HOST` (default `mailpit:1025`): the bootstrap creates and activates the SMTP provider `synthwerk-local` without TLS and login (D-49). Empty = the provider is left alone (dev and prd use Resend). |
| Action target network | Zitadel's default deny list blocks every private range, so no container is reachable. `ZITADEL_HTTPCLIENT_DENYLIST` is that list with one hole: identity's fixed address `172.31.250.10` on the internal network `zitadel-hooks` (`172.31.250.0/28`, alias `identity-hooks`). The gateway and Zitadel's own address stay denied. Any port on that address is open to a target, so only IAM owners may create targets. The name `identity` resolves on `app` and stays denied. |
| Subnet clash | If the host or Docker already uses `172.31.250.0/28`, `up` fails with an address pool error. Change the subnet, identity's `ipv4_address` and the hole in `ZITADEL_HTTPCLIENT_DENYLIST` together. |
| `::ffff:0:0/96` | Left out of the deny list: in v4.20.0 it matches every IPv4 address, so no IPv4 target works with it. The IPv4 CIDRs still block mapped literals such as `[::ffff:127.0.0.1]` (measured 2026-10-23). |
| Action caching | Zitadel caches executions and targets: a changed execution or endpoint takes some seconds to apply. Users made in the first seconds after the bootstrap can miss the hook (seen in CI-like runs: 1 of 2 test users). Invites come later, so dev and prd are not affected. |
| Order | The bootstrap waits for identity: Zitadel resolves the target name when it saves the target. |
| Scope for org and roles | `openid profile urn:zitadel:iam:org:project:id:<project id>:aud urn:zitadel:iam:org:projects:roles urn:zitadel:iam:user:resourceowner` (`bootstrap.StudioScope`). |

## Events

| Type | When |
|---|---|
| None. | |

## Errors

| Status | Problem type | Cause |
|---|---|---|
| Exit 1 | `the bootstrap PAT belongs to org …` | The instance was made without `ZITADEL_FIRSTINSTANCE_ORG_NAME: synthwerk`. Recreate it with `docker compose down --volumes`. |
| Exit 1 | `read /zitadel/admin/admin.pat` | The instance is older than this feature. Recreate it with `docker compose down --volumes`. |
| Exit 1 | `studio URI …` | A wildcard or a non-http(s) URI in `SYNTHWERK_ZITADEL_STUDIO_*_URIS`. |

## Tests

- `tests/zitadel/bootstrap_test.go` — `Run twice on a fake Zitadel - second run creates nothing, same ids, one client secret`
- `tests/zitadel/bootstrap_test.go` — `policy update - fields it does not own - kept; read-only details - not sent`
- `tests/zitadel/bootstrap_test.go` — `PUT answers "not changed" - success`
- `tests/zitadel/bootstrap_test.go` — `client file deleted - new secret, file mode 0600`
- `tests/zitadel/bootstrap_test.go` — `no test user password - no users; bad PAT - error, no create; wildcard or relative URI - error`
- `tests/zitadel/bootstrap_test.go` — `identity hook - second run - no target create, no execution change; new URL - target updated; no URL - no target`
- `tests/stack/stack_test.sh` — `new user - one user.created row in the identity outbox; hook path through the edge - 404; unsigned hook call - 401`
- `tests/stack/stack_test.sh` — `zitadel-bootstrap - first run exited 0, rerun exits 0; selftest - both test users get org and role claims; zitadel-login - cannot read the admin PAT`

## Changes

| Date | Change |
|---|---|
| 2026-10-23 | First version (synthwerk#28 task 2). |
| 2026-10-28 | Email provider for Mailpit, MFA limitation in ADR-0002 (synthwerk#28). |
| 2026-10-23 | Action target for identity, network `zitadel-hooks`, narrowed deny list (synthwerk#28 task 5). |
