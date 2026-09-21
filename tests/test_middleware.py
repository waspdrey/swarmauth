import pytest

from swarmauth.crypto import KeyPair
from swarmauth.exceptions import CapabilityViolationError, ConstraintViolationError
from swarmauth.middleware import TokenIssuer, UsageTracker, guard, secure_tool_call, verify_and_check
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


def test_guard_decorator_enforces_allowed_params_for_positional_arguments():
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
        process_payout("acct_ATTACKER", 10.0, token=token)


def test_verify_and_check_enforces_allowed_params_when_empty_mapping_is_supplied():
    kp = KeyPair.generate()
    issuer = TokenIssuer(kp)
    token = issuer.issue(
        iss="a",
        sub="tool:b",
        capabilities=["tool:b"],
        constraints=Constraints(allowed_params={"destination_account": "acct_1"}),
    )

    with pytest.raises(ConstraintViolationError):
        verify_and_check(
            token,
            issuer_public_key=kp.public_bytes,
            required_capability="tool:b",
            params={},
        )


def test_guard_decorator_amount_kwarg_enforces_budget():
    kp = KeyPair.generate()
    issuer = TokenIssuer(kp)
    token = issuer.issue(
        iss="a", sub="tool:process_payout", capabilities=["tool:process_payout"],
        constraints=Constraints(max_amount_usd=100.0),
    )
    tracker = UsageTracker()

    @guard("tool:process_payout", issuer_public_key=kp.public_bytes, tracker=tracker, amount_kwarg="amount_usd")
    def process_payout(destination_account, amount_usd):
        return "executed"

    assert process_payout(destination_account="acct_1", amount_usd=60.0, token=token) == "executed"
    with pytest.raises(ConstraintViolationError):
        process_payout(destination_account="acct_1", amount_usd=60.0, token=token)


@pytest.mark.parametrize("amount", [float("nan"), float("inf"), float("-inf"), -1.0, "not-a-number"])
def test_verify_and_check_rejects_invalid_budget_amounts(amount):
    kp = KeyPair.generate()
    issuer = TokenIssuer(kp)
    token = issuer.issue(
        iss="a",
        sub="tool:b",
        capabilities=["tool:b"],
        constraints=Constraints(max_amount_usd=100.0),
    )

    with pytest.raises(ConstraintViolationError, match="finite, non-negative"):
        verify_and_check(
            token,
            issuer_public_key=kp.public_bytes,
            required_capability="tool:b",
            amount=amount,
            tracker=UsageTracker(),
        )


def test_guard_decorator_rejects_nan_amount_before_tool_execution():
    kp = KeyPair.generate()
    issuer = TokenIssuer(kp)
    token = issuer.issue(
        iss="a",
        sub="tool:process_payout",
        capabilities=["tool:process_payout"],
        constraints=Constraints(max_amount_usd=100.0),
    )
    executed = False

    @guard("tool:process_payout", issuer_public_key=kp.public_bytes, tracker=UsageTracker(), amount_kwarg="amount_usd")
    def process_payout(destination_account, amount_usd):
        nonlocal executed
        executed = True
        return "executed"

    with pytest.raises(ConstraintViolationError, match="finite, non-negative"):
        process_payout("acct_1", float("nan"), token=token)
    assert executed is False


def test_secure_tool_call_forwards_amount_kwarg_to_budget_tracking():
    # Regression test: secure_tool_call (and therefore every framework
    # adapter built on it -- secure_langchain_tool, secure_crewai_tool,
    # secure_autogen_function, secure_mcp_tool) previously dropped
    # amount_kwarg entirely, so max_amount_usd constraints silently never
    # got charged for calls made through a framework integration.
    kp = KeyPair.generate()
    issuer = TokenIssuer(kp)
    token = issuer.issue(
        iss="a", sub="tool:process_payout", capabilities=["tool:process_payout"],
        constraints=Constraints(max_amount_usd=100.0),
    )
    tracker = UsageTracker()

    def process_payout(destination_account, amount_usd):
        return "executed"

    guarded = secure_tool_call(
        process_payout,
        capability="tool:process_payout",
        issuer_public_key=kp.public_bytes,
        tracker=tracker,
        amount_kwarg="amount_usd",
    )

    assert guarded(destination_account="acct_1", amount_usd=60.0, token=token) == "executed"
    with pytest.raises(ConstraintViolationError):
        guarded(destination_account="acct_1", amount_usd=60.0, token=token)
