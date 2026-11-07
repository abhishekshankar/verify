# Writing an outcome contract

A contract says what "done" means **before** the action runs. Verify rejects a bad contract at registration (`verify validate`), never halfway through a run.

## Fields
| Field | Required | Meaning |
|---|---|---|
| `id`, `version` | yes | Stable name and semver. A changed contract gets a new version; the ledger stores the exact body and its hash. |
| `owner` | yes | Team accountable for the outcome. |
| `target_system` | yes | `stripe`, `zendesk`, `hubspot`, or your own name when you pass your own reader. |
| `subject_ref` | yes | Template for the record being checked, filled from the claim: `refund:{refund_id}`. |
| `subject_present` | no | Field that is truthy only when the record exists. Missing → `not_observed`. Default `refund.amount`. |
| `preconditions` | no | Checks that must hold for the action to make sense. Any false → `inapplicable`. |
| `postconditions` | yes, ≥1 | Checks that must all hold for `pass`. |
| `forbidden` | no | Side effects that must not exist. Any true → `fail`. |
| `required_level` | yes | `L1`–`L4`, the level a pass reaches. |
| `settle_window_s` | yes | Seconds to wait before each readback (eventual consistency). |
| `max_attempts` | yes | Readbacks before giving up on `not_observed` or `blocked`. |
| `scope` | yes | Every field the reader may return. Each check's `path` must be in scope. |

A check is `{"path": "refund.amount", "op": "eq", "value": "{amount}"}`. `value` in braces is taken from the claim.

| `op` | True when |
|---|---|
| `eq` / `ne` | observed equals / differs |
| `gt` / `lt` | observed is present and greater / less |
| `exists` | observed is not null |

## Verdict order
1. A precondition is false → `inapplicable`.
2. The subject is absent → `not_observed` (retried up to `max_attempts`).
3. A forbidden check is true, or a postcondition is false → `fail`.
4. Otherwise → `pass`.
A readback that can't happen raises `Blocked` → `blocked`, retried with backoff.

## Examples
- Refund: `contracts/refund.full.stripe.json`. Charge succeeded; refund succeeded for the claimed amount; never two refunds.
- Ticket solved: `contracts/ticket.solved.with_reply.zendesk.json`. Status solved and at least one public agent reply; not auto-closed.
- Deal closed: `contracts/deal.closed_won.hubspot.json`. Stage `closedwon`, claimed amount, linked to the claimed company.

Start one with `verify init stripe|zendesk|hubspot`.

## Mistakes `validate` catches
- A check path not listed in `scope`
- An unknown `op`
- Empty `postconditions`
- `required_level` outside L1–L4
- `max_attempts` < 1, or a negative `settle_window_s`
- `subject_present` not in scope

## Mistakes it can't catch
- **Checking what the agent wrote, not the effect.** For example, checking the ticket comment instead of the ticket status.
- **A reader that uses the agent's own credential.** Mark the run `independence="degraded"`.
- **A settle window shorter than the system's real lag.** You get false `not_observed`; raise `settle_window_s`.
