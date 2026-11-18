from __future__ import annotations

import time

import pytest

import swarmauth


def _approved_envelope() -> tuple[swarmauth.AuthorizationEnvelope, swarmauth.ApprovalGatekeeper]:
    gate = swarmauth.ApprovalGatekeeper(secret=b"x" * 32, base_url="https://review.example.com")
    request = gate.request(
        action="send",
        capability="payment:send",
        subject="tool:payments",
        requester="agent:buyer",
        summary="Send to vendor 7",
    )
    token = gate.links(request)["approve"].split("token=", 1)[1]
    gate.resolve(token, approver="finance@example.com")
    now = int(time.time())
    claims = swarmauth.CapabilityClaims(
        iss="agent:buyer",
        sub="tool:payments",
        capabilities=["payment:send"],
        constraints=swarmauth.Constraints(max_calls=1, allowed_params={"vendor": "7"}),
        iat=now,
        exp=now + 30,
        jti="authorization-1",
    )
    return (
        swarmauth.AuthorizationEnvelope.from_claims(
            claims, approval_evidence=gate.evidence(request.request_id)
        ),
        gate,
    )


def test_final_consequence_checks_payload_version_identity_and_single_use() -> None:
    envelope, gate = _approved_envelope()
    evidence = swarmauth.ExecutionIdentityEvidence(
        format="test-tee",
        agent_id="agent:buyer",
        key_id="key-1",
        nonce="challenge-1",
        issued_at=int(time.time()),
        evidence={"quote": "opaque"},
    )
    verifier = swarmauth.CallbackIdentityVerifier(
        lambda item: {
            "agent_id": item.agent_id,
            "key_id": item.key_id,
            "environment": "confidential-vm",
        }
    )
    authorizer = swarmauth.FinalConsequenceAuthorizer(
        identity_verifier=verifier,
        approval_verifier=gate.verify_evidence,
    )
    decision = authorizer.authorize(
        envelope,
        capability="payment:send",
        target="tool:payments",
        payload={"vendor": "7", "amount": 25},
        challenge_nonce="challenge-1",
        identity_evidence=evidence,
        expected_resource_version="v4",
        actual_resource_version="v4",
        require_approval=True,
    )
    assert decision.execution_identity is not None
    assert decision.execution_identity.environment == "confidential-vm"

    with pytest.raises(swarmauth.ConstraintViolationError):
        authorizer.authorize(
            envelope,
            capability="payment:send",
            target="tool:payments",
            payload={"vendor": "7", "amount": 25},
            challenge_nonce="challenge-1",
            identity_evidence=evidence,
            require_approval=True,
        )


def test_descendant_revocation_cascades_from_parent() -> None:
    root_keys = swarmauth.KeyPair.generate()
    child_keys = swarmauth.KeyPair.generate()
    store = swarmauth.InMemoryDelegationRevocationStore()
    parent = swarmauth.TokenIssuer(root_keys).issue(
        iss="agent:root",
        sub="tool:x",
        capabilities=["tool:x"],
        dlg="agent:worker",
    )
    child = swarmauth.TokenIssuer(child_keys).attenuate(
        parent,
        iss="agent:worker",
        capabilities=["tool:x"],
        revocation_store=store,
    )
    _, parent_claims, _ = swarmauth.CapabilityToken.parse(parent)
    _, child_claims, _ = swarmauth.CapabilityToken.parse(child)
    store.revoke_tree(parent_claims.jti, expires_at=parent_claims.exp)
    assert store.is_revoked(parent_claims.jti)
    assert store.is_revoked(child_claims.jti)


def test_oauth_wimse_and_entra_adapters_map_only_validated_scopes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    now = int(time.time())
    monkeypatch.setattr("swarmauth.adapters.time.time", lambda: now)
    keys = swarmauth.KeyPair.generate()
    issuer = swarmauth.TokenIssuer(keys)

    oauth = swarmauth.OAuthDelegationAdapter(
        validate=lambda _: {
            "client_id": "agent:oauth",
            "sub": "user:1",
            "scope": "payments.send",
            "exp": now + 20,
        },
        token_issuer=issuer,
    )
    token = oauth.exchange(
        "validated-externally",
        target="tool:payments",
        scope_to_capability={"payments.send": "payment:send"},
    )
    _, claims, _ = swarmauth.CapabilityToken.parse(token)
    assert claims.iss == "agent:oauth"

    wimse = swarmauth.WIMSEClaimsAdapter(
        validate=lambda _: {
            "sub": "agent:wimse",
            "sponsor": "org:1",
            "scope": ["work.run"],
            "exp": now + 20,
        },
        token_issuer=issuer,
    )
    wimse_token = wimse.exchange(
        "assertion",
        target="tool:worker",
        scope_to_capability={"work.run": "work:run"},
    )
    assert swarmauth.CapabilityToken.parse(wimse_token)[1].iss == "agent:wimse"

    entra = swarmauth.EntraAgentAdapter(
        validate=lambda _: {
            "azp": "agent:entra",
            "sub": "user:1",
            "scp": "Mail.Read",
            "exp": now + 20,
        },
        token_issuer=issuer,
    )
    entra_token = entra.exchange(
        "entra-token",
        target="tool:mail",
        scope_to_capability={"Mail.Read": "mail:read"},
    )
    assert swarmauth.CapabilityToken.parse(entra_token)[1].capabilities == ["mail:read"]
