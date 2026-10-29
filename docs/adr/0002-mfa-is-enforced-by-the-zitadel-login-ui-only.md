# ADR-0002: MFA is enforced by the Zitadel login UI only; services fail closed

- Status: superseded by ADR-0004
- Date: 2026-10-28
- Decision log: D-47 (amended by this ADR), D-51

## Context

- Force MFA is on for every org (bootstrap login policy). Passkeys with user verification count as MFA.
- Zitadel v4.20.0 enforces Force MFA in its login UI only. The Session API plus the login-client PAT can finish a sign-in with a password only.
- Access tokens carry no `amr` claim. D-47 planned a pre-access-token Action that adds `amr`.
- The Action cannot do that. Its payload (`ContextInfo`, Zitadel `internal/api/oidc/userinfo.go`) holds user, org, grants and metadata. It holds no session and no auth methods.
- An Action can only report what the user has enrolled. Enrolment does not prove that this sign-in used a second factor.

## Options

| Option | Good | Bad |
|---|---|---|
| A. Action adds an enrolment flag; `RequireMFA` accepts it | Admin routes work now | A password-only Session API sign-in of an enrolled user passes. Rejected in review (HIGH). |
| B. `RequireMFA` reads only `amr`, stays fail closed | No false proof | No Zitadel access token passes `RequireMFA` today |
| C. Request execution on `CreateCallback` refuses sessions without a verified second factor | Server-side gate for every OIDC sign-in | Unbuilt, unverified on v4.20.0 |

## Decision

- We use B now. `kit/auth` `RequireMFA` reads only `amr` (synthwerk-contracts#10). No service mounts it yet.
- Option C is the follow-up: it is the only place where Zitadel shows the session to an Action.

## Consequences

- Sign-in itself is safe with the stock login UI: passkey users sign in with a passkey; password users must enrol TOTP or U2F before the first token (proved by synthwerk-e2e).
- Only holders of the login-client PAT (`zitadel-login`, the bootstrap `selftest`) or of the IAM owner PAT can mint a password-only token. Both PATs stay in their volumes and never leave the stack.
- Admin and operator routes that need proof of MFA wait for option C.
- Security impact: high, documented. The gap is limited to holders of root-level Zitadel credentials.
