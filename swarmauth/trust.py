"""Federated AgentCA and Entity Attestation Token trust-domain adapter."""
from __future__ import annotations

import re
import time
from typing import Any, Callable, Collection, Mapping

from swarmauth.identity import ExecutionIdentityEvidence, VerifiedExecutionIdentity

AgentCertificateVerifier = Callable[[Mapping[str, Any]], Mapping[str, Any]]
EntityAttestationTokenVerifier = Callable[[str, str], Mapping[str, Any]]

_SHA256_PATTERN = re.compile(r"^[0-9a-f]{64}$")
_COMPONENT_CLAIMS = ("model_hash", "tools_hash", "system_prompt_hash")


def _required_string(claims: Mapping[str, Any], name: str) -> str:
    value = claims.get(name)
    if not isinstance(value, str) or not value:
        raise ValueError(f"verified trust evidence is missing {name}")
    return value


class AgentCAEATIdentityVerifier:
    """Compose deployment-provided AgentCA and EAT cryptographic validators.

    The certificate callback must verify the certificate chain and return
    ``agent_id``, ``key_id``, and ``trust_domain``. The EAT callback must
    verify signature, freshness/status, and nonce, returning ``agent_id``,
    ``key_id``, ``nonce``, and optional component SHA-256 claims.
    """

    def __init__(
        self,
        *,
        verify_agent_certificate: AgentCertificateVerifier,
        verify_eat: EntityAttestationTokenVerifier,
        trusted_domains: Collection[str],
        max_age_seconds: int = 60,
        future_skew_seconds: int = 5,
    ) -> None:
        domains = frozenset(trusted_domains)
        if not domains or any(not isinstance(domain, str) or not domain for domain in domains):
            raise ValueError("at least one non-empty trusted domain is required")
        if max_age_seconds < 1 or future_skew_seconds < 0:
            raise ValueError("attestation freshness limits are invalid")
        self._verify_agent_certificate = verify_agent_certificate
        self._verify_eat = verify_eat
        self._trusted_domains = domains
        self._max_age_seconds = max_age_seconds
        self._future_skew_seconds = future_skew_seconds

    def verify(
        self, evidence: ExecutionIdentityEvidence, *, expected_nonce: str
    ) -> VerifiedExecutionIdentity:
        if evidence.format != "agentca-eat":
            raise ValueError("execution identity evidence is not AgentCA/EAT")
        if evidence.nonce != expected_nonce:
            raise ValueError("execution identity nonce does not match the authorization challenge")
        now = int(time.time())
        if evidence.issued_at > now + self._future_skew_seconds:
            raise ValueError("AgentCA/EAT evidence was issued in the future")
        if evidence.issued_at < now - self._max_age_seconds:
            raise ValueError("AgentCA/EAT evidence is stale")

        certificate = evidence.evidence.get("agent_certificate")
        eat = evidence.evidence.get("entity_attestation_token")
        if not isinstance(certificate, dict) or not isinstance(eat, str) or not eat:
            raise ValueError("AgentCA/EAT evidence requires a certificate and attestation token")
        certificate_claims = self._verify_agent_certificate(certificate)
        eat_claims = self._verify_eat(eat, expected_nonce)

        certificate_agent = _required_string(certificate_claims, "agent_id")
        certificate_key = _required_string(certificate_claims, "key_id")
        trust_domain = _required_string(certificate_claims, "trust_domain")
        eat_agent = _required_string(eat_claims, "agent_id")
        eat_key = _required_string(eat_claims, "key_id")
        eat_nonce = _required_string(eat_claims, "nonce")
        if trust_domain not in self._trusted_domains:
            raise ValueError(f"AgentCA trust domain '{trust_domain}' is not trusted")
        if eat_nonce != expected_nonce:
            raise ValueError("verified EAT nonce does not match the authorization challenge")
        if not (
            certificate_agent == eat_agent == evidence.agent_id
            and certificate_key == eat_key == evidence.key_id
        ):
            raise ValueError("AgentCA certificate, EAT, and execution identity do not match")

        components: dict[str, str] = {}
        for claim in _COMPONENT_CLAIMS:
            value = eat_claims.get(claim)
            if value is None:
                continue
            if not isinstance(value, str) or _SHA256_PATTERN.fullmatch(value) is None:
                raise ValueError(f"verified EAT {claim} must be a lowercase SHA-256 digest")
            components[claim] = value

        return VerifiedExecutionIdentity(
            agent_id=evidence.agent_id,
            key_id=evidence.key_id,
            attestation_format=evidence.format,
            environment=(
                str(eat_claims["environment"]) if eat_claims.get("environment") is not None else None
            ),
            trust_domain=trust_domain,
            attested_components=components,
            evidence_hash=evidence.digest(),
            verified_at=now,
        )
