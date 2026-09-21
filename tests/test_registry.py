import pytest

from swarmauth.crypto import KeyPair
from swarmauth.exceptions import InvalidSignatureError, UnknownIssuerError
from swarmauth.registry import KeyRegistry
from swarmauth.token import CapabilityToken


def test_verify_requires_exactly_one_of_key_or_registry():
    kp = KeyPair.generate()
    token = CapabilityToken.issue(issuer_keypair=kp, iss="agent:a", sub="b", capabilities=["x"])

    with pytest.raises(ValueError):
        CapabilityToken.verify(token)  # neither given

    registry = KeyRegistry()
    registry.register("agent:a", kp.public_bytes)
    with pytest.raises(ValueError):
        CapabilityToken.verify(token, issuer_public_key=kp.public_bytes, key_registry=registry)  # both given


def test_registry_verifies_against_registered_key():
    kp = KeyPair.generate()
    registry = KeyRegistry()
    registry.register("agent:a", kp.public_bytes)

    token = CapabilityToken.issue(issuer_keypair=kp, iss="agent:a", sub="tool:b", capabilities=["tool:b"])
    claims = CapabilityToken.verify(token, key_registry=registry)
    assert claims.iss == "agent:a"


def test_unknown_issuer_raises_before_touching_signature():
    kp = KeyPair.generate()
    registry = KeyRegistry()  # empty -- no issuer registered at all

    token = CapabilityToken.issue(issuer_keypair=kp, iss="agent:unregistered", sub="tool:b", capabilities=["tool:b"])
    with pytest.raises(UnknownIssuerError):
        CapabilityToken.verify(token, key_registry=registry)


def test_multi_issuer_registry_isolates_keys_per_issuer():
    kp_a = KeyPair.generate()
    kp_b = KeyPair.generate()
    registry = KeyRegistry()
    registry.register("agent:a", kp_a.public_bytes)
    registry.register("agent:b", kp_b.public_bytes)

    token_a = CapabilityToken.issue(issuer_keypair=kp_a, iss="agent:a", sub="x", capabilities=["x"])
    assert CapabilityToken.verify(token_a, key_registry=registry).iss == "agent:a"

    # A token claiming to be from "agent:a" but actually signed by agent b's
    # key must fail: the registry only trusts a's own registered key for
    # that iss, and b's key was registered under a different issuer.
    forged = CapabilityToken.issue(issuer_keypair=kp_b, iss="agent:a", sub="x", capabilities=["x"])
    with pytest.raises(InvalidSignatureError):
        CapabilityToken.verify(forged, key_registry=registry)


def test_key_rotation_accepts_both_old_and_new_key_during_window():
    old_kp = KeyPair.generate()
    new_kp = KeyPair.generate()
    registry = KeyRegistry()
    registry.register("agent:a", old_kp.public_bytes)

    old_token = CapabilityToken.issue(issuer_keypair=old_kp, iss="agent:a", sub="x", capabilities=["x"])

    registry.register("agent:a", new_kp.public_bytes, rotate=True)
    new_token = CapabilityToken.issue(issuer_keypair=new_kp, iss="agent:a", sub="x", capabilities=["x"])

    # Both the pre-rotation and post-rotation key verify during the window.
    assert CapabilityToken.verify(old_token, key_registry=registry).iss == "agent:a"
    assert CapabilityToken.verify(new_token, key_registry=registry).iss == "agent:a"


def test_revoke_immediately_stops_trusting_a_key():
    old_kp = KeyPair.generate()
    new_kp = KeyPair.generate()
    registry = KeyRegistry()
    registry.register("agent:a", old_kp.public_bytes)
    registry.register("agent:a", new_kp.public_bytes, rotate=True)

    old_token = CapabilityToken.issue(issuer_keypair=old_kp, iss="agent:a", sub="x", capabilities=["x"])
    registry.revoke("agent:a", old_kp.public_bytes)

    with pytest.raises(InvalidSignatureError):
        CapabilityToken.verify(old_token, key_registry=registry)

    # The new key is unaffected by revoking the old one.
    new_token = CapabilityToken.issue(issuer_keypair=new_kp, iss="agent:a", sub="x", capabilities=["x"])
    assert CapabilityToken.verify(new_token, key_registry=registry).iss == "agent:a"


def test_register_without_rotate_replaces_key_outright():
    old_kp = KeyPair.generate()
    new_kp = KeyPair.generate()
    registry = KeyRegistry()
    registry.register("agent:a", old_kp.public_bytes)
    registry.register("agent:a", new_kp.public_bytes)  # rotate=False: hard replace

    old_token = CapabilityToken.issue(issuer_keypair=old_kp, iss="agent:a", sub="x", capabilities=["x"])
    with pytest.raises(InvalidSignatureError):
        CapabilityToken.verify(old_token, key_registry=registry)


def test_revoke_issuer_removes_all_keys():
    kp = KeyPair.generate()
    registry = KeyRegistry()
    registry.register("agent:a", kp.public_bytes)
    registry.revoke_issuer("agent:a")

    token = CapabilityToken.issue(issuer_keypair=kp, iss="agent:a", sub="x", capabilities=["x"])
    with pytest.raises(UnknownIssuerError):
        CapabilityToken.verify(token, key_registry=registry)


def test_is_known():
    kp = KeyPair.generate()
    registry = KeyRegistry()
    assert not registry.is_known("agent:a")
    registry.register("agent:a", kp.public_bytes)
    assert registry.is_known("agent:a")
