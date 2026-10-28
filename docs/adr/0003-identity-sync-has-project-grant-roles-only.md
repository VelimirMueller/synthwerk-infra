# ADR-0003: identity-sync writes org roles with project grant roles only

- Status: accepted
- Date: 2026-10-28
- Issue: synthwerk#29

## Context

- synthwerk-identity changes org roles (`owner`, `admin`, `member`) and must write them to the Zitadel user grant, so the next token carries the new role.
- It calls Zitadel as the machine user `identity-sync` in the platform org.
- The first version gave it the instance role `IAM_USER_MANAGER` and a PAT for 365 days. Review (MEDIUM): instance-wide user management is far more than identity needs.
- Measured on Zitadel v4.20.0 (local stack, 2026-10-28):

| Membership of the machine user | Read user grant | Write user grant | Read the org |
|---|---|---|---|
| none | no (membership not found) | no | no |
| `PROJECT_OWNER` on `synthwerk-api` (platform org) | no | no | no |
| `PROJECT_GRANT_OWNER` on the project grant of the org | yes | yes | no |

## Decision

- `identity-sync` has no instance role and no org role. It gets `PROJECT_GRANT_OWNER` on each project grant of `synthwerk-api`.
- Whoever creates a project grant for an org also grants this membership (`bootstrap.GrantIdentitySync`). Without it, a role change in that org answers 502 and nothing changes.
- identity reads the org name from the user grant (`orgName`), not from the org.
- identity refuses, before any call: the platform org (the machine user's own org), a grant that holds `operator`, and the role `operator`. The hook never mirrors platform-org grants.
- PAT: 30 days by default (`SYNTHWERK_ZITADEL_IDENTITY_PAT_LIFETIME`, min 1 h). A new PAT revokes every older PAT of the user. The bootstrap mints one only when `/zitadel/hooks/identity.pat` is missing.

## Consequences

- A leaked PAT can change user grants of `synthwerk-api` in customer orgs, for at most 30 days. It cannot write the platform org (403, stack test), give `operator` (not in any project grant), or touch other projects.
- Residual: as a user of the platform org it can still read that org's users and grants. Moving it to its own org removes this; follow-up.
- Zitadel v4.20 answers a second `POST …/grants/{id}/members` with 404, code 5, `Errors.AlreadyExists`; the bootstrap treats that message as "exists", not as "not found".
- dev (#93): rotate by deleting the PAT file and rerunning the bootstrap before the 30 days end; the old PAT is revoked in the same run. A scheduled rotation is a follow-up.
- The org sign-up flow (E4) must call `GrantIdentitySync` when it creates the project grant.
