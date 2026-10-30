"""Two procurement cells share one GHS task budget across fresh tokens.

No external tools run. Use RedisBudgetUsageTracker with identical rules/prefix
in production. Mint each short-lived token immediately before its tool call.
"""
import time

import swarmauth


def main() -> None:
    keys = swarmauth.KeyPair.generate()
    issuer = swarmauth.TokenIssuer(keys, swarmauth.IssuerPolicy([
        swarmauth.Grant("cell:procurement", "tool:reserve_stock", ("tool:reserve_stock",),
                        max_calls=1, pinned_params={"budget_id": "order-42"}),
    ]))
    tracker = swarmauth.BudgetUsageTracker([
        swarmauth.BudgetRule("order-42", ("cell:procurement",), "GHS", 10000, int(time.time()) + 3600),
    ])

    @swarmauth.guard("tool:reserve_stock", issuer_public_key=keys.public_bytes, tracker=tracker)
    def reserve_stock(budget_id: str, currency: str, amount_minor: int) -> int:
        return amount_minor

    def reserve(amount: int) -> int:
        params = {"budget_id": "order-42", "currency": "GHS", "amount_minor": amount}
        token = issuer.issue(iss="cell:procurement", sub="tool:reserve_stock", capabilities=["tool:reserve_stock"],
                             constraints=swarmauth.Constraints(max_calls=1, shared_budget="order-42", allowed_params=params))
        with swarmauth.use_token(token):
            return reserve_stock(**params)

    assert reserve(6000) == 6000
    try:
        reserve(5000)
    except swarmauth.ConstraintViolationError:
        pass
    else:
        raise AssertionError("Fresh token escaped the shared task budget")
    assert reserve(4000) == 4000
    print("Shared GHS task budget: 6000 + 4000 pesewas accepted; overspend blocked")


if __name__ == "__main__":
    main()
