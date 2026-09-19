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
    registry.register("agent:sales", kp.public_bytes)

    token = CapabilityToken.issue(issuer_keypair=kp, iss="agent:sales", sub="tool:b", capabilities=["tool:b"])
    claims = CapabilityToken.verify(token, key_registry=registry)
    assert claims.iss == "agent:sales"


def test_unknown_issuer_raises_before_touching_signature():
    kp = KeyPair.generate()
    registry = KeyRegistry()  # empty -- no issuer registered at all

    token = CapabilityToken.issue(issuer_keypair=kp, iss="agent:unregistered", sub="tool:b", capabilities=["tool:b"])
    with pytest.raises(UnknownIssuerError):
        CapabilityToken.verify(token, key_registry=registry)


def test_multi_issuer_registry_isolates_keys_per_issuer():
    kp_sales = KeyPair.generate()
    kp_finance = KeyPair.generate()
    registry = KeyRegistry()
    registry.register("agent:sales", kp_sales.public_bytes)
    registry.register("agent:finance", kp_finance.public_bytes)

    sales_token = CapabilityToken.issue(issuer_keypair=kp_sales, iss="agent:sales", sub="x", capabilities=["x"])
    assert CapabilityToken.verify(sales_token, key_registry=registry).iss == "agent:sales"

    # A token claiming to be from "agent:sales" but actually signed by finance's
    # key must fail: the registry only trusts sales's own registered key for
    # that iss, and finance's key was registered under a different issuer.
    forged = CapabilityToken.issue(issuer_keypair=kp_finance, iss="agent:sales", sub="x", capabilities=["x"])
    with pytest.raises(InvalidSignatureError):
        CapabilityToken.verify(forged, key_registry=registry)


def test_key_rotation_accepts_both_old_and_new_key_during_window():
    old_kp = KeyPair.generate()
    new_kp = KeyPair.generate()
    registry = KeyRegistry()
    registry.register("agent:sales", old_kp.public_bytes)

    old_token = CapabilityToken.issue(issuer_keypair=old_kp, iss="agent:sales", sub="x", capabilities=["x"])

    registry.register("agent:sales", new_kp.public_bytes, rotate=True)
    new_token = CapabilityToken.issue(issuer_keypair=new_kp, iss="agent:sales", sub="x", capabilities=["x"])

    # Both the pre-rotation and post-rotation key verify during the window.
    assert CapabilityToken.verify(old_token, key_registry=registry).iss == "agent:sales"
    assert CapabilityToken.verify(new_token, key_registry=registry).iss == "agent:sales"


def test_revoke_immediately_stops_trusting_a_key():
    old_kp = KeyPair.generate()
    new_kp = KeyPair.generate()
    registry = KeyRegistry()
    registry.register("agent:sales", old_kp.public_bytes)
    registry.register("agent:sales", new_kp.public_bytes, rotate=True)

    old_token = CapabilityToken.issue(issuer_keypair=old_kp, iss="agent:sales", sub="x", capabilities=["x"])
    registry.revoke("agent:sales", old_kp.public_bytes)

    with pytest.raises(InvalidSignatureError):
        CapabilityToken.verify(old_token, key_registry=registry)

    # The new key is unaffected by revoking the old one.
    new_token = CapabilityToken.issue(issuer_keypair=new_kp, iss="agent:sales", sub="x", capabilities=["x"])
    assert CapabilityToken.verify(new_token, key_registry=registry).iss == "agent:sales"


def test_register_without_rotate_replaces_key_outright():
    old_kp = KeyPair.generate()
    new_kp = KeyPair.generate()
    registry = KeyRegistry()
    registry.register("agent:sales", old_kp.public_bytes)
    registry.register("agent:sales", new_kp.public_bytes)  # rotate=False: hard replace

    old_token = CapabilityToken.issue(issuer_keypair=old_kp, iss="agent:sales", sub="x", capabilities=["x"])
    with pytest.raises(InvalidSignatureError):
        CapabilityToken.verify(old_token, key_registry=registry)


def test_revoke_issuer_removes_all_keys():
    kp = KeyPair.generate()
    registry = KeyRegistry()
    registry.register("agent:sales", kp.public_bytes)
    registry.revoke_issuer("agent:sales")

    token = CapabilityToken.issue(issuer_keypair=kp, iss="agent:sales", sub="x", capabilities=["x"])
    with pytest.raises(UnknownIssuerError):
        CapabilityToken.verify(token, key_registry=registry)


def test_is_known():
    kp = KeyPair.generate()
    registry = KeyRegistry()
    assert not registry.is_known("agent:sales")
    registry.register("agent:sales", kp.public_bytes)
    assert registry.is_known("agent:sales")
