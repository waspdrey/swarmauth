import pytest

from swarmauth.crypto import KeyPair
from swarmauth.exceptions import ConstraintViolationError, DelegationError, UnknownIssuerError
from swarmauth.middleware import TokenIssuer, UsageTracker, verify_and_check
from swarmauth.registry import KeyRegistry
from swarmauth.token import CapabilityClaims, CapabilityToken, Constraints, _sign


def _chain():
    root = KeyPair.generate()
    worker = KeyPair.generate()
    registry = KeyRegistry()
    registry.register("agent:root", root.public_bytes)
    registry.register_holder("agent:worker-02", worker.public_bytes)
    parent = TokenIssuer(root).issue(
        iss="agent:root",
        sub="tool:process_payout",
        capabilities=["tool:*"],
        constraints=Constraints(max_calls=2, max_amount_usd=100.0, allowed_params={"destination_account": "acct_123"}),
        ttl_seconds=60,
        dlg="agent:worker-02",
    )
    child = TokenIssuer(worker).attenuate(
        parent,
        iss="agent:worker-02",
        capabilities=["tool:process_payout"],
        constraints=Constraints(max_calls=1, max_amount_usd=40.0, allowed_params={"destination_account": "acct_123"}),
        ttl_seconds=30,
    )
    return registry, parent, child


def test_attenuated_token_verifies_and_enforces_the_narrower_budget():
    registry, _parent, child = _chain()
    tracker = UsageTracker()
    claims = verify_and_check(
        child,
        key_registry=registry,
        audience="tool:process_payout",
        required_capability="tool:process_payout",
        amount=40.0,
        params={"destination_account": "acct_123"},
        tracker=tracker,
    )
    assert claims.iss == "agent:worker-02"
    assert claims.capabilities == ["tool:process_payout"]
    with pytest.raises(ConstraintViolationError):
        verify_and_check(
            child,
            key_registry=registry,
            audience="tool:process_payout",
            required_capability="tool:process_payout",
            amount=1.0,
            params={"destination_account": "acct_123"},
            tracker=tracker,
        )


def test_delegable_parent_cannot_be_presented_to_the_tool():
    registry, parent, _child = _chain()
    with pytest.raises(DelegationError):
        CapabilityToken.verify(parent, key_registry=registry, audience="tool:process_payout")


def test_holder_cannot_mint_a_fresh_root_token():
    registry, _parent, _child = _chain()
    worker_token = None
    # Rebuild a worker key is not available from _chain. Register a new holder and sign a root token.
    worker = KeyPair.generate()
    registry.register_holder("agent:worker-03", worker.public_bytes)
    worker_token = TokenIssuer(worker).issue(
        iss="agent:worker-03",
        sub="tool:process_payout",
        capabilities=["tool:process_payout"],
        ttl_seconds=30,
    )
    with pytest.raises(UnknownIssuerError):
        CapabilityToken.verify(worker_token, key_registry=registry, audience="tool:process_payout")


def test_attenuate_rejects_a_wider_capability_and_a_second_hop():
    root = KeyPair.generate()
    worker = KeyPair.generate()
    other = KeyPair.generate()
    parent = TokenIssuer(root).issue(
        iss="agent:root",
        sub="tool:process_payout",
        capabilities=["tool:process_payout"],
        constraints=Constraints(max_calls=1),
        ttl_seconds=60,
        dlg="agent:worker-02",
    )
    with pytest.raises(DelegationError):
        TokenIssuer(worker).attenuate(
            parent,
            iss="agent:worker-02",
            capabilities=["tool:*"],
            constraints=Constraints(max_calls=1),
            ttl_seconds=30,
        )
    child = TokenIssuer(worker).attenuate(
        parent,
        iss="agent:worker-02",
        capabilities=["tool:process_payout"],
        constraints=Constraints(max_calls=1),
        ttl_seconds=30,
    )
    with pytest.raises(DelegationError, match="one delegation hop"):
        TokenIssuer(other).attenuate(
            child,
            iss="agent:other",
            capabilities=["tool:process_payout"],
            constraints=Constraints(max_calls=1),
            ttl_seconds=20,
        )


def test_hand_widened_child_is_rejected_at_verification():
    root = KeyPair.generate()
    worker = KeyPair.generate()
    registry = KeyRegistry()
    registry.register("agent:root", root.public_bytes)
    registry.register_holder("agent:worker-02", worker.public_bytes)
    parent = TokenIssuer(root).issue(
        iss="agent:root",
        sub="tool:process_payout",
        capabilities=["tool:process_payout"],
        constraints=Constraints(max_calls=1),
        ttl_seconds=60,
        dlg="agent:worker-02",
    )
    _header, parent_claims, _signing = CapabilityToken.parse(parent)
    widened = _sign(
        worker,
        CapabilityClaims(
            iss="agent:worker-02",
            sub=parent_claims.sub,
            capabilities=["tool:process_payout", "tool:admin"],
            constraints=Constraints(max_calls=1),
            iat=parent_claims.iat,
            exp=parent_claims.exp,
            prf=parent,
        ),
    )
    with pytest.raises(DelegationError, match="tool:admin"):
        CapabilityToken.verify(widened, key_registry=registry)


def test_revoke_holder_stops_an_attenuated_token():
    registry, _parent, child = _chain()
    _header, claims, _signing = CapabilityToken.parse(child)
    worker_key = registry.holder_keys_for(claims.iss)[0]
    registry.revoke_holder(claims.iss, worker_key)
    with pytest.raises(UnknownIssuerError):
        CapabilityToken.verify(child, key_registry=registry)
