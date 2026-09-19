import pytest

from swarmauth.crypto import KeyPair
from swarmauth.exceptions import CapabilityViolationError, ConstraintViolationError
from swarmauth.middleware import TokenIssuer, UsageTracker, guard, verify_and_check
from swarmauth.token import Constraints


def test_verify_and_check_success():
    kp = KeyPair.generate()
    issuer = TokenIssuer(kp)
    token = issuer.issue(iss="a", sub="tool:b", capabilities=["tool:b"])
    claims = verify_and_check(token, issuer_public_key=kp.public_bytes, audience="tool:b", required_capability="tool:b")
    assert claims.sub == "tool:b"


def test_verify_and_check_missing_capability():
    kp = KeyPair.generate()
    issuer = TokenIssuer(kp)
    token = issuer.issue(iss="a", sub="tool:b", capabilities=["tool:read_invoice"])
    with pytest.raises(CapabilityViolationError):
        verify_and_check(token, issuer_public_key=kp.public_bytes, required_capability="tool:process_payout")


def test_usage_tracker_max_calls():
    kp = KeyPair.generate()
    issuer = TokenIssuer(kp)
    token = issuer.issue(iss="a", sub="tool:b", capabilities=["tool:b"], constraints=Constraints(max_calls=1))
    tracker = UsageTracker()

    verify_and_check(token, issuer_public_key=kp.public_bytes, required_capability="tool:b", tracker=tracker)
    with pytest.raises(ConstraintViolationError):
        verify_and_check(token, issuer_public_key=kp.public_bytes, required_capability="tool:b", tracker=tracker)


def test_usage_tracker_budget():
    kp = KeyPair.generate()
    issuer = TokenIssuer(kp)
    token = issuer.issue(iss="a", sub="tool:b", capabilities=["tool:b"], constraints=Constraints(max_amount_usd=100.0))
    tracker = UsageTracker()

    verify_and_check(token, issuer_public_key=kp.public_bytes, required_capability="tool:b", amount=60.0, tracker=tracker)
    with pytest.raises(ConstraintViolationError):
        verify_and_check(token, issuer_public_key=kp.public_bytes, required_capability="tool:b", amount=60.0, tracker=tracker)


def test_guard_decorator_blocks_without_token():
    kp = KeyPair.generate()

    @guard("tool:process_payout", issuer_public_key=kp.public_bytes)
    def process_payout(destination_account, amount_usd):
        return "executed"

    with pytest.raises(CapabilityViolationError):
        process_payout(destination_account="acct_1", amount_usd=10.0)


def test_guard_decorator_allows_with_valid_token():
    kp = KeyPair.generate()
    issuer = TokenIssuer(kp)
    token = issuer.issue(iss="a", sub="tool:process_payout", capabilities=["tool:process_payout"])

    @guard("tool:process_payout", issuer_public_key=kp.public_bytes, audience="tool:process_payout")
    def process_payout(destination_account, amount_usd):
        return "executed"

    result = process_payout(destination_account="acct_1", amount_usd=10.0, token=token)
    assert result == "executed"


def test_guard_decorator_enforces_allowed_params():
    kp = KeyPair.generate()
    issuer = TokenIssuer(kp)
    token = issuer.issue(
        iss="a",
        sub="tool:process_payout",
        capabilities=["tool:process_payout"],
        constraints=Constraints(allowed_params={"destination_account": "acct_1"}),
    )

    @guard("tool:process_payout", issuer_public_key=kp.public_bytes)
    def process_payout(destination_account, amount_usd):
        return "executed"

    with pytest.raises(ConstraintViolationError):
        process_payout(destination_account="acct_ATTACKER", amount_usd=10.0, token=token)
