# ADR-0004: MFA is enforced on the server by a request execution on the sign-in calls

- Status: accepted
- Date: 2026-10-29
- Issue: synthwerk#94
- Supersedes: ADR-0002 (option C of that ADR is now built)

## Context

- ADR-0002: Zitadel v4.20.0 enforces Force MFA in its login UI only. The Session API plus the login-client PAT can finish a sign-in with a password only.
- Access tokens carry no `amr`. kit/auth `RequireMFA` refuses every Zitadel token.
- A request execution sees the gRPC request. On `CreateCallback` that request holds the session id and the session token.
- With the session token, any authenticated caller can read the session factors (Zitadel `query.SessionByID`).
- A call target with `interruptOnError` stops the request on any error answer or no answer. An answer `{"forwardedStatusCode":403}` gives the caller 403 PermissionDenied.
- Measured on the local stack, 2026-10-29: a password-only session gets 403 on v2 and v2beta `CreateCallback`; password plus TOTP and passkey sign-ins pass.

## Options

| Option | Good | Bad |
|---|---|---|
| A. Keep ADR-0002 (UI only, `RequireMFA` refuses all) | No new moving part | Root-level PAT holders can mint password-only tokens; no route can use `RequireMFA` |
| B. Request execution on the sign-in calls; identity reads the session and refuses one without a second factor; the pre-access-token function adds `amr` from what the gate saw | Server-side gate for every OIDC, device and SAML sign-in; `RequireMFA` works | identity is in the sign-in path: identity down = no sign-in |
| C. Wait for Zitadel to put `amr` into access tokens | No own code | No date; the Session API gap stays open |

## Decision

- We use B. synthwerk-identity `internal/mfagate` serves both targets on its hook listener (network `zitadel-hooks`).
- The gate runs on `/zitadel.oidc.v2.OIDCService/CreateCallback`, `/zitadel.oidc.v2beta.OIDCService/CreateCallback`, `/zitadel.oidc.v2.OIDCService/AuthorizeOrDenyDeviceAuthorization` and `/zitadel.saml.v2.SAMLService/CreateResponse`.
- MFA uses Zitadel's own `amr` rule: a passkey with user verification counts two factors, any other check one; two or more = MFA.
- The pre-access-token function copies the `amr` of the user's newest gated sign-in (max 12 h old) into the access token. Zitadel shows no session to that function, so the `amr` is not bound to the exact session of the token. Safe, because the gate refuses every sign-in without a second factor.

## Consequences

- A password-only sign-in gets no code and no token, also through the Session API with the login-client or IAM owner PAT.
- Access tokens of gated sign-ins carry `amr` (for example `["pwd","otp","mfa"]`). Services may mount `RequireMFA`.
- Fail closed: identity down, key file missing or Zitadel unreachable from identity = sign-in refused. Claims target down = token without `amr`.
- A refresh token gives `amr` only for 12 h after the last gated sign-in (`SYNTHWERK_IDENTITY_MFA_EVIDENCE_MAX_AGE`).
- Switch: `SYNTHWERK_ZITADEL_MFA_GATE` (default false until the pinned identity image has the gate). Off = the bootstrap points the executions at no target.
- The v1 login UI does not call `CreateCallback`. `LoginV2.Required` sends every OIDC flow to login v2. An app with login version v1 would skip the gate.
- Security impact: high, positive. It closes the gap of ADR-0002.
