# RFC: Cross-Agent Memory Isolation and Trust Boundaries

**Status:** Draft for Vaishnavi and Anshul; no implementation authorized.
**Target:** [v1.0.0 multi-agent security](https://github.com/OWASP/www-project-agent-memory-guard/blob/main/ROADMAP.md#v100--q4-2026).
**Baseline:** [PR #166](https://github.com/OWASP/www-project-agent-memory-guard/pull/166),
against main `d41ec3f12b78c96f15272392764ebca465509997`.

## Problem and existing boundary

Extend [phase one (#155)](https://github.com/OWASP/www-project-agent-memory-guard/pull/155),
not replace it. `AgentHandle` binds an asserted principal; `AccessPolicy`
validates the registry, applies first-matching `AccessRule`, defaults, and
class-writer gates. `MemoryGuard._enforce()` gates read/write/delete before
content inspection. Deletes use writers. Protected keys remain frozen.
Mutations hold a per-guard lock; access-controlled values are copied.

The [current limits](../getting-started/multi-agent.md#limits-to-know) are material:
`guard.py` keeps classifications, writers, integrity state and events locally.
Two guards sharing a backend agree on namespace rules but can disagree on
classes; rollback restores values without updating peers. Successful clean
reads need not emit `SecurityEvent`. Some framework reads bypass the guard.
These documented limits and intentional permissive policies are not evidence
of a vulnerability within the supported single-guard boundary.

This proposal covers opt-in isolation, controlled sharing, revocation and
auditable operations. Content detection remains an independent requirement.
Cryptographic identity verification and arbitrary malicious Python code in
the orchestrator process are outside scope.

## Trust, identity and ownership

Trust the orchestrator, policy authority, coordinator and audit sink. Treat
agents' text, model output, tool payloads and embedded identity fields as
untrusted. Keep raw guards, stores and handle factories out of agent reach;
handles are integration capabilities, not a Python sandbox.

A trusted integration maps its authenticated session or configured workflow
step to an existing principal, then supplies its `AgentHandle`. It binds
`source_class` independently from the input channel on **every write**; a tool
cannot request SYSTEM provenance. Record principal, establishment mechanism,
source class and optional receipt reference together with the committed value
version. A receipt URI alone proves nothing. Distinguish **asserted in-process**
identity from **externally authenticated** identity: the latter requires a
deployment verifier, not a string or model assertion. Roles still come only
from `AccessPolicy.principals`.

In strict mode require a declared, nonanonymous actor and known provenance
for writes. Missing/ambiguous identity, malformed metadata, unavailable state
or an insufficient identity assurance level deny access. A namespace's owner
is the validated `{owner}` segment, bound at creation and immutable thereafter;
it is not the last writer. Existing literal namespaces require an explicit
policy owner. There is no automatic "first writer owns it" rule. Store owner,
class, origin task, source provenance and last writer separately. Ownership
does not imply authority to edit policy or issue grants.

## Declarative policy and one predicate

Extend `Policy.with_access()`, `AccessPolicy` and `AccessRule`; avoid a second
identity registry or authorization API. The following schema is **PROPOSED,
NOT IMPLEMENTED**. Current YAML loaders deliberately reject access fields.
Field names and serialization require maintainer approval.

```yaml
access:
  isolation: strict
  default: deny
  principals: {alice: [], bob: [], supervisor: [lead]}
  admins: [supervisor]
  rules:
    - name: notebooks
      keys: ["notes.{owner}.*"]
      writers: ["{owner}"]
      readers: ["{owner}"]
  grants:
    - id: review-42
      owner: alice
      keys: ["notes.alice.review.*"]
      recipients: [bob]
      operations: [read]
      task: review-42
      expires_at: "2026-12-01T00:00:00Z"
```

Only the policy authority creates/removes grants. They select a bounded key
scope, owner, declared recipients, operations, optional trusted task context
and expiry. No delegation or wildcard recipients in strict grants. Write
sharing does not transfer ownership; delete requires an explicit delete grant.
Missing task context fails a task-scoped grant. Expiry uses coordinator time.

Define one pure predicate over actor/context, operation, key, current/target
metadata, immutable policy revision and coordinator time. Decision order:
validate identity/state; apply existing registry and first-match rules; require
owner rule permission or an active grant within the selected isolation scope; apply
class gates; otherwise deny. In strict scopes, rules' readers/writers provide
owner permissions, while cross-owner access additionally requires a grant.
A grant may satisfy a recipient's isolation/selector denial, but never an
unknown principal, explicit closed rule (empty selectors), uncovered key,
class gate or protected-key prohibition. Admin selectors authorize bulk
administration, not an implicit cross-owner read bypass. Retain legacy
first-match behavior outside strict mode; reject overlapping strict scopes
whose ownership cannot be resolved. No deny/allow merging algorithm is added.
Creation requires coordinator-verified absence and policy-derived ownership;
a missing record for an existing value is not a new-key permission.

`allows()`, `decide()`, `explain()` and read/write/delete must project this same
predicate. Diagnostic trace construction cannot contain a second security
rule implementation. Content rules may restrict an authorized operation but
cannot authorize a denied one. Promotion uses the same predicate with both
classes and cannot change ownership or establish grants.

## Consistency, revocation and storage compatibility

Keep the six-method `MemoryStore` protocol unchanged. Initially require a
single trusted coordinator owning the backend and all security metadata;
multiple guards must share that coordinator's policy revision, locking and
state. Independent processes use an authenticated coordinator service, not
independent local locks. Strict initialization must reject an uncoordinated
backend. Direct backend access remains outside the boundary.

The coordinator serializes authorization, version selection, value/metadata
commit and audit intent, including reads. Immutable policy replacement and
grant revocation use the same serialization point. An operation ordered before
revocation may finish; one ordered after must deny. Already returned data
cannot be recalled. Handles and cached decisions do not preserve revoked
grants. All guards observe the authoritative revision without a TTL grace
period. Reentrant callbacks must not mutate authorization state mid-operation;
run notifications after commit and prohibit recursive coordinator operations.

A generic store cannot atomically commit a value and a sidecar journal.
Therefore initial strict support should be ephemeral single-coordinator
state; persistent deployments need a validated transaction/recovery layer
before being enabled. On uncertain commit, fence the affected scope until
reconciliation; do not report success. Never place an unprotected metadata
sidecar in ordinary agent keys. This capability restriction preserves backend
implementations but limits strict availability: **maintainer compatibility
decision required**. Backend-specific transactions are a later optimization,
not a hidden new requirement on every MemoryStore.

## Snapshots, bulk operations and audit

Snapshot and rollback retain the admin gate and additionally evaluate the
predicate for every captured or changed key. Include ownership, provenance
and value versions in coordinated snapshots. Preflight the whole set under
one revision; any denial aborts the whole operation. Snapshot listing and
handle results must not expose unauthorized data or key inventories.
`retire_if()` requires delete authorization before exposing each candidate to
its trusted predicate. Bulk reads similarly preflight before returning data.
No partial success in strict mode. Rollback never restores policies or grants:
current authorization applies, so it cannot resurrect revoked access.
Legacy snapshots lacking authoritative metadata are denied in strict mode.

Extend `SecurityEvent.metadata` with owner, grant id, policy revision, identity
assurance, decision reason/stage, operation id and value version; retain its
principal and source_class fields. Emit cross-owner allows and denials even
without tracing, distinguishing authorization from commit outcome. Do not log
payloads or sensitive denied-key existence. Malformed identity attempts use a
sanitized identifier, not raw untrusted content. Strict operation requires
accepted audit intent before disclosure or mutation; audit unavailability
fails closed. Existing best-effort `_emit()` handlers are insufficient for
this guarantee. Record completion/recovery separately and deduplicate by
operation id. Audit transport failure may require fencing after uncertain
mutation, rather than pretending the mutation was rolled back.

## Migration, validation and decisions

Legacy policies and backends retain current behavior. Strict mode is explicit
and requires inventory, trusted ownership assignment and coordinated bootstrap
before serving traffic. Unknown legacy provenance is not silently upgraded.
Adapters must bind handles and route searches, enumeration, fallbacks,
write-through and deletion through the coordinator or refuse strict mode.
CrewAI search, LlamaIndex reads, LangChain index reads and OpenAI context
fallbacks need particular review. No adapter may advertise strict support
solely because its writes call the guard.

Adversarial validation extends #166: anonymous/invalid identity, supervisor
impersonation, forged tool provenance, conflicting scopes, revoked grants,
legacy restoration, bulk denial, adapter bypass, audit failure, crash recovery
and controlled concurrent read/write/delete/rollback/revocation interleavings.
Assert fast/diagnostic predicate equivalence and no unauthorized disclosure or
partial commit. Existing single-guard identity and class-gate tests stay intact.

Benchmark legacy, phase-one ACL and strict owner/grant/deny paths with tracing
off/on; vary payloads, rule counts, agents, key contention and backend latency.
Report warmup, repetitions, Python/backend versions, p50/p95/p99 latency,
throughput, allocations and audit/coordination costs separately. Include reads,
deletes, snapshots and revocation contention. Establish an agreed budget from
measurements; this RFC claims no measured overhead.

Separate stores offer simple deployment isolation but complicate sharing;
per-guard sidecars cannot supply consistency; changing MemoryStore would break
compatibility. Coordinator serialization costs throughput but gives a clear
security boundary. Review decisions: proposed grant precedence and separate
delete rights; literal-key ownership; identity assurance requirements; audit
durability/fencing; strict backend capability restrictions; and whether a
service coordinator belongs in v1.0.0 or a later milestone. Implement only
after approval, starting with the predicate/schema, then coordination/audit,
then adapter certification and measured optimization.
