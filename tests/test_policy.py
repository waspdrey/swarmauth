import pytest

from swarmauth.crypto import KeyPair
from swarmauth.exceptions import PolicyViolationError
from swarmauth.middleware import TokenIssuer
from swarmauth.policy import Grant, IssuerPolicy
from swarmauth.token import Constraints


def _policy() -> IssuerPolicy:
    return IssuerPolicy(
        [
            Grant(
                iss="agent:requester-01",
                sub="tool:process_payout",
                capabilities=("tool:draft_payout",),
                max_ttl_seconds=60,
                max_calls=1,
                max_amount_usd=1000.0,
                delegates=("agent:worker-02",),
                pinned_params={"destination_account": "acct_123"},
            )
        ]
    )


def test_policy_allows_a_grant_inside_the_ceiling():
    kp = KeyPair.generate()
    issuer = TokenIssuer(kp, policy=_policy())
    token = issuer.issue(
        iss="agent:requester-01",
        sub="tool:process_payout",
        capabilities=["tool:draft_payout"],
        constraints=Constraints(
            max_calls=1,
            max_amount_usd=1000.0,
            allowed_params={"destination_account": "acct_123"},
        ),
        ttl_seconds=60,
        dlg="agent:worker-02",
    )
    assert token


def test_policy_rejects_a_capability_it_does_not_grant():
    kp = KeyPair.generate()
    issuer = TokenIssuer(kp, policy=_policy())
    with pytest.raises(PolicyViolationError, match="tool:process_payout"):
        issuer.issue(
            iss="agent:requester-01",
            sub="tool:process_payout",
            capabilities=["tool:process_payout"],
            constraints=Constraints(max_calls=1, max_amount_usd=10.0, allowed_params={"destination_account": "acct_123"}),
            ttl_seconds=60,
        )


def test_policy_rejects_an_omitted_ceiling_and_an_unknown_delegate():
    kp = KeyPair.generate()
    issuer = TokenIssuer(kp, policy=_policy())
    constraints = Constraints(max_amount_usd=10.0, allowed_params={"destination_account": "acct_123"})
    with pytest.raises(PolicyViolationError, match="max_calls"):
        issuer.issue(
            iss="agent:requester-01",
            sub="tool:process_payout",
            capabilities=["tool:draft_payout"],
            constraints=constraints,
            ttl_seconds=60,
        )
    with pytest.raises(PolicyViolationError, match="agent:other"):
        issuer.issue(
            iss="agent:requester-01",
            sub="tool:process_payout",
            capabilities=["tool:draft_payout"],
            constraints=Constraints(
                max_calls=1,
                max_amount_usd=10.0,
                allowed_params={"destination_account": "acct_123"},
            ),
            ttl_seconds=60,
            dlg="agent:other",
        )


def test_policy_rejects_an_unpinned_parameter_and_an_unknown_audience():
    kp = KeyPair.generate()
    issuer = TokenIssuer(kp, policy=_policy())
    with pytest.raises(PolicyViolationError, match="destination_account"):
        issuer.issue(
            iss="agent:requester-01",
            sub="tool:process_payout",
            capabilities=["tool:draft_payout"],
            constraints=Constraints(max_calls=1, max_amount_usd=10.0),
            ttl_seconds=60,
        )
    with pytest.raises(PolicyViolationError, match="No grant"):
        issuer.issue(
            iss="agent:someone-else",
            sub="tool:process_payout",
            capabilities=["tool:draft_payout"],
            ttl_seconds=60,
        )
