"""AgentCA/EAT verification micro-benchmark.

This measures SwarmAuth's adapter with two real Ed25519 verifications: one
organization-issued AgentCA certificate and one Entity Attestation Token.
The paper-reported ATI result (174 microseconds/request, arXiv:2611.23202) is
printed only as a reference point; environments and workloads are not
identical: https://arxiv.org/abs/2611.23202

Run with:  python benchmarks/trust_domain_bench.py
"""
from __future__ import annotations

import json
import statistics
import time
from typing import Any, Mapping

from swarmauth.crypto import KeyPair, b64url_decode, b64url_encode, verify_signature
from swarmauth.identity import ExecutionIdentityEvidence
from swarmauth.trust import AgentCAEATIdentityVerifier

ATI_REPORTED_MICROSECONDS = 174.0


def _canonical_json(value: Mapping[str, Any]) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("utf-8")


def run_benchmark(iterations: int = 10_000) -> dict[str, float]:
    if iterations < 1:
        raise ValueError("iterations must be positive")
    organization_ca = KeyPair.generate()
    attestation_key = KeyPair.generate()
    nonce = "benchmark-challenge"
    now = int(time.time())

    certificate_claims = {
        "agent_id": "agent:bench",
        "key_id": attestation_key.public_key_id,
        "trust_domain": "bench.example",
    }
    certificate = {
        "claims": certificate_claims,
        "signature": b64url_encode(organization_ca.sign(_canonical_json(certificate_claims))),
    }
    eat_claims = {
        "agent_id": "agent:bench",
        "key_id": attestation_key.public_key_id,
        "nonce": nonce,
        "environment": "benchmark-tee",
        "model_hash": "a" * 64,
        "tools_hash": "b" * 64,
        "system_prompt_hash": "c" * 64,
    }
    encoded_eat = b64url_encode(_canonical_json(eat_claims))
    eat = f"{encoded_eat}.{b64url_encode(attestation_key.sign(encoded_eat.encode('ascii')))}"

    def verify_certificate(value: Mapping[str, Any]) -> Mapping[str, Any]:
        claims = value["claims"]
        signature = value["signature"]
        if not isinstance(claims, dict) or not isinstance(signature, str):
            raise ValueError("invalid benchmark certificate")
        verify_signature(organization_ca.public_bytes, _canonical_json(claims), b64url_decode(signature))
        return claims

    def verify_eat(token: str, expected_nonce: str) -> Mapping[str, Any]:
        payload, signature = token.split(".", 1)
        verify_signature(attestation_key.public_bytes, payload.encode("ascii"), b64url_decode(signature))
        claims = json.loads(b64url_decode(payload))
        if not isinstance(claims, dict) or claims.get("nonce") != expected_nonce:
            raise ValueError("invalid benchmark EAT")
        return claims

    verifier = AgentCAEATIdentityVerifier(
        verify_agent_certificate=verify_certificate,
        verify_eat=verify_eat,
        trusted_domains={"bench.example"},
    )
    evidence = ExecutionIdentityEvidence(
        format="agentca-eat",
        agent_id="agent:bench",
        key_id=attestation_key.public_key_id,
        nonce=nonce,
        issued_at=now,
        evidence={"agent_certificate": certificate, "entity_attestation_token": eat},
    )

    for _ in range(100):
        verifier.verify(evidence, expected_nonce=nonce)
    samples: list[float] = []
    for _ in range(iterations):
        started = time.perf_counter_ns()
        verifier.verify(evidence, expected_nonce=nonce)
        samples.append((time.perf_counter_ns() - started) / 1_000)
    ordered = sorted(samples)
    return {
        "median_us": statistics.median(ordered),
        "p95_us": ordered[int(0.95 * (len(ordered) - 1))],
        "ati_reported_reference_us": ATI_REPORTED_MICROSECONDS,
    }


def main() -> None:
    result = run_benchmark()
    print("SwarmAuth AgentCA/EAT trust-domain benchmark")
    print(f"median: {result['median_us']:.2f} us/request")
    print(f"p95:    {result['p95_us']:.2f} us/request")
    print(f"ATI paper reference: {result['ati_reported_reference_us']:.2f} us/request")
    print("Reference is directional only; benchmark environments are not identical.")


if __name__ == "__main__":
    main()
