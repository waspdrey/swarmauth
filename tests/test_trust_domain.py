from __future__ import annotations

import time

import pytest

import swarmauth


def _evidence(*, agent_id: str = "agent:buyer", nonce: str = "challenge-1") -> swarmauth.ExecutionIdentityEvidence:
    return swarmauth.ExecutionIdentityEvidence(
        format="agentca-eat",
        agent_id=agent_id,
        key_id="key-1",
        nonce=nonce,
        issued_at=int(time.time()),
        evidence={
            "agent_certificate": {"compact": "certificate"},
            "entity_attestation_token": "signed-eat",
        },
    )


def _verifier(*, domain: str = "partner.example", eat_agent: str = "agent:buyer") -> swarmauth.AgentCAEATIdentityVerifier:
    return swarmauth.AgentCAEATIdentityVerifier(
        verify_agent_certificate=lambda _: {
            "agent_id": "agent:buyer",
            "key_id": "key-1",
            "trust_domain": domain,
        },
        verify_eat=lambda _token, nonce: {
            "agent_id": eat_agent,
            "key_id": "key-1",
            "nonce": nonce,
            "environment": "confidential-vm",
            "model_hash": "a" * 64,
            "tools_hash": "b" * 64,
            "system_prompt_hash": "c" * 64,
        },
        trusted_domains={"partner.example"},
    )


def test_agentca_eat_verifier_binds_domain_identity_nonce_and_components() -> None:
    verified = _verifier().verify(_evidence(), expected_nonce="challenge-1")
    assert verified.agent_id == "agent:buyer"
    assert verified.trust_domain == "partner.example"
    assert verified.environment == "confidential-vm"
    assert verified.attested_components == {
        "model_hash": "a" * 64,
        "tools_hash": "b" * 64,
        "system_prompt_hash": "c" * 64,
    }


def test_agentca_eat_verifier_rejects_untrusted_domain_and_identity_split() -> None:
    with pytest.raises(ValueError, match="not trusted"):
        _verifier(domain="attacker.example").verify(_evidence(), expected_nonce="challenge-1")
    with pytest.raises(ValueError, match="do not match"):
        _verifier(eat_agent="agent:other").verify(_evidence(), expected_nonce="challenge-1")


def test_agentca_eat_verifier_rejects_bad_nonce_and_component_digest() -> None:
    with pytest.raises(ValueError, match="nonce"):
        _verifier().verify(_evidence(nonce="wrong"), expected_nonce="challenge-1")

    verifier = swarmauth.AgentCAEATIdentityVerifier(
        verify_agent_certificate=lambda _: {
            "agent_id": "agent:buyer",
            "key_id": "key-1",
            "trust_domain": "partner.example",
        },
        verify_eat=lambda _token, nonce: {
            "agent_id": "agent:buyer",
            "key_id": "key-1",
            "nonce": nonce,
            "model_hash": "not-a-digest",
        },
        trusted_domains={"partner.example"},
    )
    with pytest.raises(ValueError, match="SHA-256"):
        verifier.verify(_evidence(), expected_nonce="challenge-1")
