# ADR-0005: identity-sync manages the users of customer orgs

- Status: accepted
- Date: 2026-10-30
- Issues: synthwerk#37, synthwerk#41
- Amends: ADR-0003 (the project grant role stays; an org role is added)

## Context

- ADR-0003 gave the machine user `identity-sync` only `PROJECT_GRANT_OWNER` on each project grant of `synthwerk-api`. That covers the user grants of an org, nothing else.
- synthwerk-identity now also writes users:
  - Invites (synthwerk#37) create a human user in the org and ask Zitadel for the invite code. That needs `user.write` in the org.
  - Account delete (synthwerk#41) removes the Zitadel user of a deleted account (UserService v2 `DeleteUser`). That needs `user.delete` in the user's org.
- Without them, an invite answers 502 and the remover retries and logs WARN `account.zitadel_remove_failed`.

## Options

| Option | Good | Bad |
|---|---|---|
| A. Instance role `IAM_USER_MANAGER` | One grant for every org | Users of the platform org too, incl. operators. ADR-0003 removed exactly this. |
| B. Org role `ORG_USER_MANAGER` in each customer org | Only the orgs identity serves. No right in the platform org. | Whoever creates a customer org must also add this membership. |
| C. No delete in Zitadel; deactivate only | No new right | The user stays in Zitadel after an account delete. synthwerk#41 asks for removal. |

## Decision

- We use B. `identity-sync` gets `ORG_USER_MANAGER` in each customer org, next to `PROJECT_GRANT_OWNER` on its project grant.
- `bootstrap.GrantIdentitySyncOrg` adds it. It refuses the platform org. The bootstrap calls it for `demo`.
- Whoever creates a customer org and its project grant calls `GrantIdentitySync` and `GrantIdentitySyncOrg`. The stack test does both for its own org.

## Consequences

- A leaked PAT (30 days at most, ADR-0003) can now also create, change and delete the users of customer orgs. It still cannot touch the platform org: the stack test proves a 403 on a delete there.
- identity keeps its own guards before any call: no platform org, no `operator`.
- The org sign-up flow (E4) must grant both memberships when it makes an org.
