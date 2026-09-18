"""Ed25519 key management, signing, and verification primitives for SwarmAuth.

SwarmAuth uses Ed25519 exclusively: fixed 32-byte keys and signatures, no
parameter choices to get wrong, and verification well under the <1ms target.
The only external dependency here is `cryptography`.
"""
from __future__ import annotations

import base64
import os
from dataclasses import dataclass
from typing import Union

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from swarmauth.exceptions import InvalidSignatureError


def b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def b64url_decode(data: str) -> bytes:
    padding = "=" * (-len(data) % 4)
    return base64.urlsafe_b64decode(data + padding)


@dataclass(frozen=True)
class KeyPair:
    """An Ed25519 identity for one agent, tool, or a SwarmAuth token issuer."""

    private_key: Ed25519PrivateKey
    public_key: Ed25519PublicKey

    @classmethod
    def generate(cls) -> "KeyPair":
        private_key = Ed25519PrivateKey.generate()
        return cls(private_key=private_key, public_key=private_key.public_key())

    @property
    def public_bytes(self) -> bytes:
        return self.public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )

    @property
    def private_bytes(self) -> bytes:
        return self.private_key.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption(),
        )

    @property
    def public_key_id(self) -> str:
        """Base64url-encoded public key, usable as a stable key identifier (`kid`)."""
        return b64url_encode(self.public_bytes)

    def sign(self, data: bytes) -> bytes:
        return self.private_key.sign(data)

    @classmethod
    def from_private_bytes(cls, raw: bytes) -> "KeyPair":
        private_key = Ed25519PrivateKey.from_private_bytes(raw)
        return cls(private_key=private_key, public_key=private_key.public_key())

    def export_private_pem(self) -> bytes:
        return self.private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )

    @classmethod
    def load_private_pem(cls, pem_data: bytes) -> "KeyPair":
        private_key = serialization.load_pem_private_key(pem_data, password=None)
        if not isinstance(private_key, Ed25519PrivateKey):
            raise ValueError("PEM does not contain an Ed25519 private key")
        return cls(private_key=private_key, public_key=private_key.public_key())


def public_key_from_bytes(raw: bytes) -> Ed25519PublicKey:
    return Ed25519PublicKey.from_public_bytes(raw)


def verify_signature(
    public_key: Union[bytes, Ed25519PublicKey], data: bytes, signature: bytes
) -> None:
    """Verify an Ed25519 signature. Raises InvalidSignatureError on failure."""
    key = (
        public_key_from_bytes(public_key)
        if isinstance(public_key, (bytes, bytearray))
        else public_key
    )
    try:
        key.verify(signature, data)
    except InvalidSignature as exc:
        raise InvalidSignatureError("Ed25519 signature verification failed") from exc


def generate_jti() -> str:
    """Generate a unique token identifier (128-bit, base64url)."""
    return b64url_encode(os.urandom(16))
