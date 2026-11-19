from __future__ import annotations

import json

import pytest

import swarmauth


def test_approval_evidence_binds_exact_reviewed_intent() -> None:
    gate = swarmauth.ApprovalGatekeeper(secret=b"x" * 32, base_url="https://review.example.com")
    request = gate.request(
        action="transfer",
        capability="payment:send",
        subject="tool:payments",
        requester="agent:treasury",
        summary="Send USD 25 to vendor 7",
        request_id="approval-1",
        now=100,
    )
    token = gate.links(request)["approve"].split("token=", 1)[1]
    gate.resolve(token, approver="finance@example.com", now=101)

    evidence = gate.evidence("approval-1")
    assert evidence.decision == "approved"
    assert len(evidence.request_hash) == 64
    assert len(evidence.decision_hash) == 64
    assert gate.verify_evidence(evidence)
    altered = evidence.model_copy(update={"capability": "payment:admin"})
    assert not gate.verify_evidence(altered)

    changed = request.__class__(**{**request.as_dict(), "summary": "Send USD 2,500 to vendor 7"})
    assert changed.intent_dict() != request.intent_dict()


def test_claims_round_trip_through_aae_envelope() -> None:
    keys = swarmauth.KeyPair.generate()
    token = swarmauth.TokenIssuer(keys).issue(
        iss="agent:buyer",
        sub="tool:payments",
        capabilities=["payment:send"],
        constraints=swarmauth.Constraints(max_calls=1, allowed_params={"vendor": "7"}),
    )
    _, claims, _ = swarmauth.CapabilityToken.parse(token)
    envelope = swarmauth.AuthorizationEnvelope.from_claims(
        claims,
        purpose="Pay an approved supplier invoice",
        exclusions=["payment:admin"],
        accountable_owner="role:finance-controller",
    )

    wire = envelope.to_aae()
    assert set(wire) >= {"MANDATE", "CONSTRAINTS", "VALIDITY"}
    assert wire["MANDATE"]["capabilities"] == ["payment:send"]
    assert wire["MANDATE"]["purpose"] == "Pay an approved supplier invoice"
    assert wire["MANDATE"]["exclusions"] == ["payment:admin"]
    assert wire["MANDATE"]["accountable_owner"] == "role:finance-controller"
    assert swarmauth.AuthorizationEnvelope.from_aae(wire) == envelope
    assert len(envelope.digest()) == 64

    with pytest.raises(ValueError):
        swarmauth.AuthorizationEnvelope.from_aae({**wire, "UNKNOWN": {}})


def test_signed_decision_and_outcome_receipts_are_linked_and_tamper_evident() -> None:
    signer = swarmauth.KeyPair.generate()
    decision = swarmauth.AuthorizationDecision.allowed(
        capability="payment:send",
        audience="tool:payments",
        issuer="agent:buyer",
        subject="tool:payments",
        jti="auth-1",
    )
    decision_receipt = swarmauth.issue_decision_receipt(
        decision,
        signer=signer,
        issuer="enforcer:payments",
        envelope_hash="a" * 64,
        approval_hash="b" * 64,
        purpose="Pay an approved supplier invoice",
        accountable_owner="role:finance-controller",
        evidence_kind="externally_verifiable",
        now=200,
    )
    decision_claims = swarmauth.SignedReceipt.verify(decision_receipt, signer_public_key=signer.public_bytes)
    assert decision_claims.receipt_type == "authorization_decision"
    assert decision_claims.approval_hash == "b" * 64
    assert decision_claims.evidence_kind == "externally_verifiable"
    assert decision_claims.accountable_owner == "role:finance-controller"

    outcome_receipt = swarmauth.issue_outcome_receipt(
        signer=signer,
        issuer="tool:payments",
        decision_receipt=decision_receipt,
        status="succeeded",
        metadata={"provider_reference": "safe-reference-only"},
        now=201,
    )
    outcome_claims = swarmauth.SignedReceipt.verify(outcome_receipt, signer_public_key=signer.public_bytes)
    assert outcome_claims.decision_receipt_hash == swarmauth.receipt_hash(decision_receipt)

    header, payload, signature = decision_receipt.split(".")
    decoded = json.loads(swarmauth.crypto.b64url_decode(payload))
    decoded["data"]["outcome"] = "deny"
    changed_payload = swarmauth.crypto.b64url_encode(
        json.dumps(decoded, sort_keys=True, separators=(",", ":")).encode("utf-8")
    )
    with pytest.raises(swarmauth.InvalidSignatureError):
        swarmauth.SignedReceipt.verify(
            f"{header}.{changed_payload}.{signature}", signer_public_key=signer.public_bytes
        )


def test_receipt_claims_reject_cross_type_and_unlinked_shapes() -> None:
    with pytest.raises(ValueError):
        swarmauth.ReceiptClaims(
            receipt_type="execution_outcome",
            issuer="tool:x",
            issued_at=1,
            data={"status": "succeeded"},
        )
    with pytest.raises(ValueError):
        swarmauth.ReceiptClaims(
            receipt_type="authorization_decision",
            issuer="enforcer:x",
            issued_at=1,
            decision_receipt_hash="a" * 64,
            data={"outcome": "allow"},
        )


def test_envelope_digest_rejects_non_standard_nan() -> None:
    with pytest.raises(ValueError):
        swarmauth.Constraints(allowed_params={"amount": float("nan")})
