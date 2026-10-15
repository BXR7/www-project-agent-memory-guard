"""Differential coverage for the single access-policy evaluator.

The oracle below intentionally uses policy inputs rather than calling either public
method, so the test cannot pass by comparing two wrappers around the evaluator.
"""
import random

import pytest

from agent_memory_guard import AccessPolicy, AccessRule, MemoryClass

PRINCIPALS = ("alice", "bob", "carol", "ops")
ROLES = ("reader", "writer", "admin")
OPS = ("read", "write", "delete", "promote", "snapshot", "rollback", "retire")
KEYS = ("notes.alice.x", "notes.bob.x", "team.x", "misc.x", "data.carol.y")
CLASSES = (None, *MemoryClass)


def oracle(policy, principal, operation, key, current_class=None, target_class=None):
    registry = dict(policy.principals)
    if principal is not None and registry and principal not in registry:
        return False
    roles = set(registry.get(principal, ())) if principal is not None else set()
    if operation in {"snapshot", "rollback", "retire"}:
        return any(sel.matches(principal, frozenset(roles), None) for sel in policy._admin_sel)
    writes = operation in {"write", "delete", "promote"}
    for rule in policy.rules:
        hit = rule.match(key)
        if hit is None:
            continue
        selectors = rule._writers if writes else rule._readers
        if not any(sel.matches(principal, frozenset(roles), hit[1]) for sel in selectors):
            return False
        break
    else:
        if policy.default != "allow":
            return False
    if writes:
        for cls in (current_class, target_class):
            selectors = policy._class_sel.get(cls)
            if selectors is not None and not any(
                sel.matches(principal, frozenset(roles), None) for sel in selectors
            ):
                return False
    return True


def generated_policy(rng):
    registry = {
        pid: tuple(rng.sample(ROLES, rng.randrange(0, len(ROLES) + 1)))
        for pid in PRINCIPALS
    }
    selectors = ["*", "{owner}", "role:reader", "role:writer", "alice", "bob", ""]
    rules = []
    for i in range(rng.randrange(0, 5)):
        def pick():
            return [s for s in rng.sample(selectors[:-1], rng.randrange(0, 3))]

        writers, readers = pick(), pick()
        pool = ("notes.{owner}.x", "data.{owner}.*") if "{owner}" in writers + readers else (
            "team.*", "misc.*"
        )
        patterns = rng.sample(pool, rng.randrange(1, len(pool) + 1))
        rules.append(AccessRule(f"rule-{i}", patterns, writers, readers))
    admins = rng.sample(("alice", "bob", "role:admin"), rng.randrange(0, 3))
    class_writers = {
        MemoryClass.POLICY: rng.sample(("*", "alice", "role:admin"), rng.randrange(0, 3)),
        MemoryClass.VERIFIED_PREFERENCE: rng.sample(("*", "bob", "role:writer"), rng.randrange(0, 3)),
    }
    return AccessPolicy(
        rules=rules,
        default=rng.choice(("allow", "deny")),
        admins=admins,
        principals=registry,
        class_writers=class_writers,
    )


@pytest.mark.parametrize("seed", [7, 23, 101, 404])
def test_generated_policies_match_independent_oracle(seed):
    rng = random.Random(seed)
    checked = 0
    for _ in range(125):
        policy = generated_policy(rng)
        for _ in range(25):
            principal = rng.choice((*PRINCIPALS, "ghost", None))
            operation = rng.choice(OPS)
            key = rng.choice(KEYS)
            current = rng.choice(CLASSES)
            target = rng.choice(CLASSES)
            expected = oracle(policy, principal, operation, key, current, target)
            assert policy.allows(
                principal, operation, key, current_class=current, target_class=target
            ) is expected
            decision = policy.decide(
                principal, operation, key, current_class=current, target_class=target
            )
            traced = policy.decide(
                principal, operation, key, current_class=current, target_class=target
            )
            assert decision.allowed is expected
            assert traced.allowed == decision.allowed
            assert isinstance(decision.steps, tuple)
            checked += 1
    assert checked == 125 * 25


def test_denial_does_not_expose_or_mutate_policy_state():
    rng = random.Random(8080)
    policy = generated_policy(rng)
    before = (policy.registry, policy.rules, policy.default)
    for principal in PRINCIPALS:
        assert policy.allows(principal, "read", "notes.bob.x") in (True, False)
    assert (policy.registry, policy.rules, policy.default) == before
