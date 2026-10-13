# RFC: Cross-Agent Memory Isolation and Trust Boundaries

**Status:** Draft, under review in [#167](https://github.com/OWASP/www-project-agent-memory-guard/pull/167); nothing here is implemented.
**Target:** v1.0.0. **Baseline:** [#166](https://github.com/OWASP/www-project-agent-memory-guard/pull/166), pending merge; source checked against main `733271f` (phase-one security code unchanged from `d41ec3f`). Update the baseline to main after #166 merges.

!!! warning
    Proposal only. Strict isolation, grants, coordinator and audit APIs below do not exist yet.

## Goals / Non-goals

- Opt-in isolation, bounded sharing, revocation, poisoning recovery and attributable audit.
- Declarative policies, one authorization predicate, fail-closed enforcement and an unchanged six-method `MemoryStore` interface.
- v1.0.0: one in-process coordinator with ephemeral values, metadata, grants and snapshots.
- Non-goals: distributed coordinator service, persistent strict recovery, cryptographic identity implementation or a sandbox against malicious Python in the trusted process. `RedisMemoryStore` deployments retain phase-one rules.

## Existing boundary and threats

Extend [phase one (#155)](https://github.com/OWASP/www-project-agent-memory-guard/pull/155).
`AccessPolicy` uses registry checks, first-match rules, defaults and class gates;
delete and promote currently use writers. `AgentHandle` rejects `principal=`
but forwards `source_class`. Task context is guard-wide. `_enforce()` currently
has separate `allows()` and `decide()` paths. Snapshot/rollback are admin-only,
whole-store operations; rollback also checks changed gated classes. `_emit()`
handlers are best-effort. YAML access fields are rejected today.

[#166](https://github.com/OWASP/www-project-agent-memory-guard/pull/166) characterizes
local metadata/locks/events and rollback disagreement between guards sharing
values; these are [documented limits](../getting-started/multi-agent.md#limits-to-know),
not vulnerabilities within the supported single-guard boundary.
The existing [trust-boundary diagram](threat-model.md#trust-boundaries) treats
cross-agent messages as untrusted but does not yet model principals/namespaces.

| Threat scenario | Proposed mitigation and residual risk |
| --- | --- |
| Bob reads/deletes Alice's private notes in a shared store | Owner binding and per-operation predicate; no grant means denial. Raw-store bypass remains outside the boundary. |
| Independent guards race or use stale labels/grants | One coordinator owns state and serializes decisions/commits; refuse independent strict guards. |
| Compromised Bob poisons a namespace he may write for Alice | Bind writer/provenance to each version; strict reads return a value-plus-provenance envelope, including to owners, for consumer trust decisions. Content detectors still run; authorization cannot establish truth. |
| Tool/model claims Alice, SYSTEM provenance or a different task | Trusted handle creation binds context; caller overrides are rejected. |
| Revocation, rollback or audit failure resurrects authority/hides a mutation | Current revisions, grants excluded from snapshots, accepted intent and fencing on uncertainty. Already disclosed data cannot be recalled. |

Trust the orchestrator, deployment policy authority, coordinator, verifier and
audit sink. Agents' text/tool payloads and identity fields are untrusted. Keep
raw guards/stores and handle/coordinator factories out of agent reach.

## Strict policy and authorization

Strictness is **policy-wide**, never per rule. Legacy policies retain first-match
semantics. Strict load requires `default: deny`, a closed principal registry,
`ambient_identity: false`, nonoverlapping scopes and owner-only selectors
(`["{owner}"]` or `[]`). Empty selectors disable that operation for everyone,
including grants. A separate `shareable: false` disables grants while retaining
owner rights. Owners cannot issue grants.

Restrict strict key patterns to `literal.prefix.{owner}.*` or `literal.prefix.*`:
nonempty literal dot segments, one validated principal segment for `{owner}`,
and a suffix of one or more nonempty dot-separated segments: final `*` means
`segment(\.segment)*`, with each segment excluding dots. Thus `notes.alice.todo`
and `notes.alice.review.x` match, but `notes.alice.`, `notes.alice..x` and
`notes.alice.x.` do not. Matching covers the entire key, case-sensitively;
literals match exactly. No other `*`, `?` or bracket syntax.
Literal scopes require a declared `owner:`; template scopes derive immutable
ownership from the registered owner segment. Reject any scopes whose concrete
key sets intersect, including template/literal intersections; grants must be
contained in one rule's scope. No first-writer ownership.

Illustrative **proposed schema**, not loadable today:

```yaml
access:
  isolation: strict
  default: deny
  ambient_identity: false
  principals: {alice: [], bob: [], supervisor: [lead]}
  admins: [supervisor]
  recovery:
    - id: alice-notes-recovery
      principals: [supervisor]
      owner: alice
      keys: ["notes.alice.*"]
      operations: [snapshot_capture, restore_write, restore_delete, restore_promote]
  rules:
    - name: notebooks
      keys: ["notes.{owner}.*"]
      readers: ["{owner}"]
      writers: ["{owner}"]
      deleters: ["{owner}"]
      promoters: ["{owner}"]
      shareable: true
    - name: team
      keys: ["team.*"]
      owner: alice
      readers: ["{owner}"]
      writers: ["{owner}"]
      deleters: ["{owner}"]
      promoters: []
      shareable: true
```

A pure evaluator receives actor/assurance/task, operation, key, current/target
metadata, immutable policy revision, grant-table revision and coordinator time.
`allows()`, `decide()`, `explain()` and enforcement project that one result;
optional step recording adds no second rule walk.

| Order | Condition | Verdict |
| --- | --- | --- |
| 1 | Invalid/anonymous/undeclared actor, inadequate assurance, unavailable/fenced state, malformed metadata or uncovered key | Deny |
| 2 | Protected mutation, failed current/target class gate, or empty operation selectors | Deny; grants/custodians cannot override |
| 3 | Actor is owner and operation selector contains `{owner}` | Allow |
| 4 | Non-owner read/write/delete, shareable rule and matching active grant | Allow with grant id |
| 5 | Explicit custodian performing recovery-only operation | Allow within declared recovery scope |
| 6 | Anything else, including non-owner promote | Deny |

Grants replace only the cross-owner restriction, never earlier denials. Content
policy can further restrict an allow. Creation verifies absence and derives
ownership from policy; existing values with missing metadata deny access.
Promotion checks both classes, preserves ownership and is never grantable.

Example coordinator grants: `review-42` permits Bob **read** of
`notes.alice.review.*`, task `review-42`, expiry `2026-12-01T00:00:00Z`;
`team-bob` permits Bob **read/write** of `team.*`, owner Alice.
Assume active grants, matching trusted task, asserted assurance permitted,
ordinary mutable classes and healthy audit:

| Actor | `notes.alice.review.x`: read/write/delete/promote/snapshot | `notes.alice.todo`: read/write/delete/promote/snapshot |
| --- | --- | --- |
| Alice | allow / allow / allow / allow / owner scope allow | allow / allow / allow / allow / owner scope allow |
| Bob | grant allow / deny / deny / deny / deny | deny / deny / deny / deny / deny |
| Supervisor | deny / deny / deny / deny / custodian capture allow | deny / deny / deny / deny / custodian capture allow |

Snapshot cells describe membership in an owner or custodian snapshot, not a
new single-key snapshot API. Supervisor's admin role alone confers no read or
snapshot right. For #166's `team.*`, strict conversion assigns Alice ownership:
Bob needs `team-bob` even to create a key; write can overwrite, but cannot
delete/promote. The baseline's multi-writer selectors would fail strict load.

## Grant lifecycle and trusted context

Grants live only in a coordinator-held table with its own monotonically
increasing revision, separate from immutable policy. The **policy authority**
is trusted deployment code retaining the proposed coordinator management
capability, not an agent role or existing AMG API. It alone issues/revokes
grants; Alice wanting sub-agent sharing must request it through that authority.
No delegation, wildcard recipients or promote/snapshot/rollback grants.

Each grant has a unique id, owner, contained key scope, declared recipients,
explicit read/write/delete operations, optional trusted task, assurance minimum
and expiry. Reject invalid grants; policy replacement revalidates active grants
and disables incompatible ones in the same serialized transition. Expiry uses
trusted coordinator time with no clock regression extending validity.
Revocation orders at the decision/commit boundary: earlier operations may finish,
later ones deny; handles/cache cannot retain authority. Grant changes are audited.

Strict handle APIs must additionally bind source class and trusted task at
creation and reject caller overrides of either, as well as principal/assurance,
before authorization or detectors run, even if equal to the bound value.
Every strict entry point, including adapters and bulk writes, obtains provenance
only from coordinator-issued context; raw keyword arguments, payload fields,
ambient context and guard-wide task setters cannot replace it. Calls without
that context fail closed. Restored provenance is accepted only from a validated
coordinator snapshot, never caller-supplied metadata.
`asserted` is default; only a deployment-supplied verifier can establish
`verified` during handle creation. Rules and grants can require `verified`.
Roles come only from the policy registry; receipt references alone prove nothing.
Rebinding a task requires a newly issued trusted handle. Disabling ambient
identity avoids inherited asyncio/copied-thread context authorizing strict calls.
These are explicit changes from today's handle and guard-wide task APIs.

Version metadata separates owner, writer, source class, task, assurance,
establishment mechanism and optional verifier receipt. The proposed strict
read envelope exposes this committed metadata and fresh commit version with a
copied value; absence is explicit and never represented as invented provenance
for a caller-supplied default. This is an opt-in strict API change: legacy
`read()` retains its value/default behavior, and `MemoryStore.get()` remains
unchanged. Strict consumers/adapters must accept the envelope or refuse strict
mode; silently unwrapping to the legacy API is not strict support.
Existing cross-task detection checks tasks,
not principals; no current detector supplies this cross-principal trust decision.
Compromised authorized writers remain a residual poisoning risk.

## Coordinator and recovery

Initially support coordinator-owned `InMemoryStore` only. Multiple guards may
share that coordinator, never separate security state. It serializes revision
selection, authorization, audit intent, value/metadata commit and disclosure.
Never store authoritative metadata in agent-accessible keys. Reentrant operations
are prohibited; best-effort notifications run after commit.

Strict recovery adds owner-scoped snapshot/rollback and declarative recovery
capabilities, separate from admins. Each capability binds declared principals,
an owner, key scope contained in one rule, and explicit recovery operations;
policy load rejects unbounded/ambiguous scopes or unknown operations. The
example permits Supervisor to recover Alice's notes, not Bob's notes or `team.*`.
The shared predicate denies any requested scope/key outside that capability;
never silently widen or partially execute a requested recovery. Capture evaluates
`snapshot_capture` per key: owner scope or matching capability, plus a nonempty
reader selector. A read grant does not suffice. Custodians get opaque ids and
cannot obtain plaintext via capture, ordinary reads, callbacks or listings;
recovery authority never supplies ordinary read permission or class authority.

Rollback preflights the union of current and captured scoped keys through the
shared predicate. `restore_write` applies to additions, value replacements **and
metadata-only changes**, even when value and class compare equal;
`restore_delete` covers removals and `restore_promote` additionally covers any
classification change. Compare and validate writer, source class, task,
assurance, receipt, classification and owner in current and target records. Historical
writer must be declared, provenance well-formed and snapshot-bound, and verified
assurance supported by its trusted establishment record; a receipt string alone
cannot upgrade assurance. Current policy assurance requirements still apply to
the restorer and restored provenance. Reject changed owners, policy-derived
ownership mismatches, forged/missing metadata or invalid provenance bindings;
never relabel an old writer/source/task as the restorer's identity.

Only owners or matching recovery capabilities qualify; ordinary grants do not.
Reapply current operation closures, protected-key restrictions and both class
gates: `restore_write` maps to writers, `restore_delete` to deleters,
`restore_promote` to promoters. No metadata-only shortcut bypasses these checks.
Restore values and historical provenance together, but record restorer and
recovery operation separately and allocate a **fresh monotonic commit version**
for every restored mutation, including metadata-only changes. Historical version
may be referenced as lineage; never restore old commit/version counters, policy
or grant revisions. Process epochs distinguish versions after ephemeral restart.
Never restore grants/policy or transfer ownership. Explicitly scoped owner
recovery leaves other scopes untouched; requesting unauthorized scopes denies
the entire operation. Legacy snapshots are rejected.

Enumeration and bulk operations require an explicit bounded scope. Materialize
candidates internally and preflight all per-key permissions under one serialized
revision before returning any key, value, count or iterator element. Enumeration
requires read permission even for keys-only results; a denied key aborts without
partial inventory disclosure. Bulk reads require read; bulk deletes require
delete; operations exposing values require read as well. Do not expose backend
iterators. Snapshot listings expose only opaque ids/minimal scope labels for
snapshots whose entire scope passes current `snapshot_capture` authorization;
no values, key inventories, unauthorized ids or global counts. Custodian listing
uses recovery scope, never implicit read access.

Strict `retire_if()` retains its admin gate and additionally preflights read and
delete for every scoped candidate before any callback; protected/class-denied
candidates abort rather than being disclosed or silently skipped. Its forensic
snapshot also requires `snapshot_capture` for the full candidate scope before
callbacks. Callbacks receive copied authorized pairs, cannot reenter or mutate
the coordinator, and all selection completes before deletion. Callback failure
aborts without deletion; audit records any authorized disclosure already made.
No recovery capability alone authorizes lifecycle callbacks.

Preflight all bulk keys under one revision before disclosure/mutation; no partial
success is returned. Unexpected mid-commit failure fences the entire coordinator,
including reads; it does not promise backend atomicity. Ephemeral restart discards
values, metadata, grants and snapshots together and requires fresh trusted
bootstrap. No persisted sidecar reconciliation/recovery is claimed for v1.0.0.
Adapters with raw search/read/fallback paths must refuse strict mode until certified.

## Audit protocol

Proposed `AuditSink.accept_intent(record) -> receipt` and
`AuditSink.accept_outcome(record) -> receipt` acknowledge durable acceptance
according to the deployment's sink contract or raise. Both are idempotent by
`(operation_id, phase, substep)`; conflicting retries fail. Records contain actor,
assurance, operation, owner, grant id, policy/grant revisions, value version,
decision/reason and outcome, without payloads or denied-key existence leakage.

Require accepted intent **before** every mutation (including grants, policy and
snapshot state) and cross-owner disclosure. Same-owner reads default to required
intent, with an explicit best-effort option. Required disclosure includes
callbacks and enumeration. Sink rejection/timeout before intent acceptance
returns an audit-unavailable error without mutation/disclosure; authorization
denials remain access-denied even if their best-effort denial record fails.

For mandatory audit, acknowledge outcome after commit or preparing the read
result but **before returning success or releasing that result**. Outcomes
identify committed, failed or uncertain mutation, or authorized read release;
read-release acceptance records permission to deliver, not proof the consumer
received it. No acknowledgement can prove delivery across a process crash.
On outcome timeout/failure after mutation, return an indeterminate-operation
error with operation id, fence the coordinator and never claim rollback.
For buffered reads, withhold data, return audit-unavailable and fence until the
pending outcome is accepted. Callbacks are already a disclosure: acknowledge
an authorized-release outcome before invoking them, then acknowledge a final
bulk completion outcome before reporting success. Later audit failure cannot
recall callback inputs; report indeterminate status and fence. Required intent
without any possible effect may report audit-unavailable; uncertain effects
must report indeterminate. Errors never include hidden keys/values. Best-effort
owner reads queue audit failures without fencing. Retries use operation id and
phase/substep to avoid conflicting callback-release/completion records; never
blindly repeat an indeterminate mutation. Unmatched intents remain visible for
audit reconciliation after process loss; restart cannot recover ephemeral data.
Existing `_emit()` notifications and `SecurityEvent.metadata` may mirror these
records but cannot substitute for acknowledged sink acceptance.

## Recommended decisions and implementation sequence

1. Policy-wide strictness, restricted disjoint grammar, explicit literal owner,
   owner-only selectors, independent delete/promote rights and `shareable` flag.
2. Coordinator-held revisioned grants; deployment authority only, no delegation.
3. Owner-scoped recovery plus scoped custodians; no admin data bypass.
4. Bound provenance/task, asserted/verified assurance and disabled ambient identity.
5. Acknowledged intent/outcome audit; required owner-read audit by default; global
   fencing on uncertain mutation or required outcome failure.
6. In-process ephemeral coordinator only; persistent/distributed work deferred.

First implementation PR should consolidate the existing evaluator with an
optional recorder and differential tests over **generated policies**, before
strict-mode code. Then schema/predicate, coordinator/audit/recovery and adapter
certification. Future tests build on #166 without changing that baseline PR:
forgery, grant lifecycle, closure precedence, poisoned shared writes, audit
failures and deterministic interleavings. Recovery tests must cover equal
value/class with altered writer, source class, task, assurance or receipt;
owner/class tampering; removed/insufficient historical identity bindings;
revoked recovery scope; denied class gates; metadata-only denial with no effects;
and fresh increasing versions across rollback with historical lineage preserved.
Also test empty suffix segments, bulk preflight with a denied last key and zero
callback calls/disclosure, callback failure before deletion, snapshot listing
leaks, direct/adapted source overrides, and intent/outcome timeouts before/after
effects. Assert no unauthorized partial disclosure or reported partial success.
Benchmark legacy and strict owner/grant/deny paths, tracing on/off, including
coordination/audit costs and tail latency; no measured strict overhead is claimed.
