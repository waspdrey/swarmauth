"""Deployment shape for SwarmAuth.

The signing key and the grant stay in the issuer process. The tool holds
public keys and a usage tracker. The runtime attaches the token with
use_token; the model never sees it.

Run from a checkout with the package installed:

    python examples/execution_boundary.py
"""
from __future__ import annotations

import swarmauth
from swarmauth.exceptions import CapabilityViolationError, ConstraintViolationError, DelegationError, PolicyViolationError


def main() -> None:
    issuer_keys = swarmauth.KeyPair.generate()
    worker_keys = swarmauth.KeyPair.generate()
    policy = swarmauth.IssuerPolicy(
        [
            swarmauth.Grant(
                iss="agent:requester-01",
                sub="tool:process_payout",
                capabilities=("tool:process_payout",),
                max_ttl_seconds=60,
                max_calls=1,
                max_amount_usd=1000.0,
                delegates=("agent:worker-02",),
            )
        ]
    )
    issuer = swarmauth.TokenIssuer(issuer_keys, policy=policy)

    try:
        issuer.issue(
            iss="agent:requester-01",
            sub="tool:process_payout",
            capabilities=["tool:wire_funds"],
            constraints=swarmauth.Constraints(max_calls=1, max_amount_usd=10.0),
            ttl_seconds=60,
        )
        raise SystemExit("issuer signed a capability the grant does not allow")
    except PolicyViolationError:
        pass

    token = issuer.issue(
        iss="agent:requester-01",
        sub="tool:process_payout",
        capabilities=["tool:process_payout"],
        constraints=swarmauth.Constraints(max_calls=1, max_amount_usd=1000.0),
        ttl_seconds=60,
    )
    tracker = swarmauth.UsageTracker()
    executed: list[float] = []

    @swarmauth.guard(
        "tool:process_payout",
        issuer_public_key=issuer_keys.public_bytes,
        tracker=tracker,
        amount_kwarg="amount_usd",
    )
    def process_payout(destination_account: str, amount_usd: float) -> str:
        executed.append(amount_usd)
        return f"sent {amount_usd} to {destination_account}"

    with swarmauth.use_token(token):
        assert process_payout(destination_account="acct_123", amount_usd=50.0) == "sent 50.0 to acct_123"
    try:
        process_payout(destination_account="acct_123", amount_usd=50.0)
        raise SystemExit("call without a token reached the tool")
    except CapabilityViolationError:
        pass
    with swarmauth.use_token(token):
        try:
            process_payout(destination_account="acct_123", amount_usd=1.0)
            raise SystemExit("max_calls did not stop the second call")
        except ConstraintViolationError:
            pass

    parent = issuer.issue(
        iss="agent:requester-01",
        sub="tool:process_payout",
        capabilities=["tool:process_payout"],
        constraints=swarmauth.Constraints(max_calls=1, max_amount_usd=1000.0),
        ttl_seconds=60,
        dlg="agent:worker-02",
    )
    registry = swarmauth.registry.KeyRegistry()
    registry.register("agent:requester-01", issuer_keys.public_bytes)
    registry.register_holder("agent:worker-02", worker_keys.public_bytes)
    try:
        swarmauth.CapabilityToken.verify(parent, key_registry=registry, audience="tool:process_payout")
        raise SystemExit("delegable parent was accepted as an execution credential")
    except DelegationError:
        pass

    child = swarmauth.TokenIssuer(worker_keys).attenuate(
        parent,
        iss="agent:worker-02",
        capabilities=["tool:process_payout"],
        constraints=swarmauth.Constraints(max_calls=1, max_amount_usd=25.0),
        ttl_seconds=30,
    )
    child_tracker = swarmauth.UsageTracker()

    @swarmauth.guard(
        "tool:process_payout",
        key_registry=registry,
        tracker=child_tracker,
        amount_kwarg="amount_usd",
    )
    def process_delegated(destination_account: str, amount_usd: float) -> str:
        return f"delegated {amount_usd} to {destination_account}"

    with swarmauth.use_token(child):
        assert process_delegated(destination_account="acct_123", amount_usd=25.0).startswith("delegated 25.0")

    fresh = swarmauth.TokenIssuer(worker_keys).issue(
        iss="agent:worker-02",
        sub="tool:process_payout",
        capabilities=["tool:process_payout"],
        ttl_seconds=30,
    )
    try:
        swarmauth.CapabilityToken.verify(fresh, key_registry=registry, audience="tool:process_payout")
        raise SystemExit("holder key was accepted as a root issuer")
    except swarmauth.UnknownIssuerError:
        pass

    assert executed == [50.0]
    print("execution boundary example: ok")


if __name__ == "__main__":
    main()
