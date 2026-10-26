"""A procurement cell may draft; a separate approval service authorizes a PO.

Run: python examples/marrow_procurement.py
The example simulates separate processes. In deployment, keep each private
key and policy in its owning service, outside the model's tools and context.
"""
from __future__ import annotations

import swarmauth
from swarmauth.middleware import AuthorizationEvent


def main() -> None:
    draft_keys = swarmauth.KeyPair.generate()
    approval_keys = swarmauth.KeyPair.generate()
    events: list[AuthorizationEvent] = []
    created_orders: list[str] = []
    draft_issuer = swarmauth.TokenIssuer(draft_keys, policy=swarmauth.IssuerPolicy([
        swarmauth.Grant(
            iss="cell:procurement", sub="tool:draft_proforma", capabilities=("tool:draft_proforma",),
            max_calls=1, pinned_params={"distributor_id": "distributor-1", "order_id": "order-42"},
        ),
    ]))
    approval_issuer = swarmauth.TokenIssuer(approval_keys, policy=swarmauth.IssuerPolicy([
        swarmauth.Grant(
            iss="service:approval", sub="tool:submit_purchase_order", capabilities=("tool:submit_purchase_order",),
            max_calls=1, pinned_params={"distributor_id": "distributor-1", "order_id": "order-42", "approval_id": "approval-7"},
        ),
    ]))
    registry = swarmauth.registry.KeyRegistry()
    registry.register("cell:procurement", draft_keys.public_bytes)
    registry.register("service:approval", approval_keys.public_bytes)
    tracker = swarmauth.UsageTracker()

    @swarmauth.guard("tool:draft_proforma", key_registry=registry, tracker=tracker, on_decision=events.append)
    def draft_proforma(distributor_id: str, order_id: str) -> dict[str, str]:
        return {"distributor_id": distributor_id, "order_id": order_id, "status": "draft"}

    @swarmauth.guard("tool:submit_purchase_order", key_registry=registry, tracker=tracker, on_decision=events.append)
    def submit_purchase_order(distributor_id: str, order_id: str, approval_id: str) -> str:
        created_orders.append(order_id)
        return f"PO created for {distributor_id}/{order_id} under {approval_id}"

    draft_token = draft_issuer.issue(
        iss="cell:procurement", sub="tool:draft_proforma", capabilities=["tool:draft_proforma"],
        constraints=swarmauth.Constraints(max_calls=1, allowed_params={"distributor_id": "distributor-1", "order_id": "order-42"}),
    )
    with swarmauth.use_token(draft_token):
        assert draft_proforma("distributor-1", "order-42")["status"] == "draft"
        try:
            submit_purchase_order("distributor-1", "order-42", "forged-approval")
        except swarmauth.AudienceMismatchError:
            pass
        else:
            raise AssertionError("A draft token authorized a purchase order")
    assert not created_orders

    # Only the approval service reaches this point after independently checking
    # a human approval persisted for this distributor and exact order. Approval
    # IDs and order IDs must be resolved from trusted service state, not the LLM.
    approved_token = approval_issuer.issue(
        iss="service:approval", sub="tool:submit_purchase_order", capabilities=["tool:submit_purchase_order"],
        constraints=swarmauth.Constraints(max_calls=1, allowed_params={
            "distributor_id": "distributor-1", "order_id": "order-42", "approval_id": "approval-7",
        }),
    )
    with swarmauth.use_token(approved_token):
        print(submit_purchase_order("distributor-1", "order-42", "approval-7"))
        try:
            submit_purchase_order("distributor-1", "order-42", "approval-7")
        except swarmauth.ConstraintViolationError:
            pass
        else:
            raise AssertionError("The single-use approval was replayed")
    assert created_orders == ["order-42"]
    assert [event.decision for event in events] == ["allowed", "denied", "allowed", "denied"]
    print("Marrow procurement boundary: ok; events contain metadata only")


if __name__ == "__main__":
    main()
