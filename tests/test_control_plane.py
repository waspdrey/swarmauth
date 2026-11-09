from __future__ import annotations

import pytest

import swarmauth


def test_control_plane_registers_revokes_and_queries_without_storing_tokens() -> None:
    plane = swarmauth.ControlPlane()
    keys = swarmauth.KeyPair.generate()
    agent = plane.register_agent("agent:billing", owner="team-finance", public_key=keys.public_bytes)
    tool = plane.register_tool("tool:refund", owner="team-finance", capabilities=("tool:refund",))
    assert agent.active and tool.active

    allowed = swarmauth.AuthorizationDecision.allowed(
        capability="tool:refund", audience="tool:refund", issuer="agent:billing", subject="tool:refund", jti="jti-1"
    )
    denied = swarmauth.AuthorizationDecision.denied(
        capability="tool:refund", audience="tool:refund", reason="CapabilityViolationError"
    )
    plane.record_decision(allowed)
    plane.record_decision(denied)
    assert plane.decisions(outcome="allow") == [allowed]
    assert plane.decisions(issuer="agent:billing") == [allowed]

    plane.revoke_agent("agent:billing")
    assert plane.agent("agent:billing").active is False
    with pytest.raises(swarmauth.UnknownIssuerError):
        plane.registry.keys_for("agent:billing")


def test_sqlite_control_plane_survives_restart(tmp_path) -> None:
    database = tmp_path / "control-plane.db"
    keys = swarmauth.KeyPair.generate()
    first = swarmauth.SQLiteControlPlane(str(database))
    first.register_agent("agent:billing", owner="team-finance", public_key=keys.public_bytes)
    first.register_tool("tool:refund", owner="team-finance", capabilities=("tool:refund",))
    decision = swarmauth.AuthorizationDecision.allowed(
        capability="tool:refund", audience="tool:refund", issuer="agent:billing", subject="tool:refund", jti="jti-2"
    )
    first.record_decision(decision)
    first.close()

    second = swarmauth.SQLiteControlPlane(str(database))
    assert second.agent("agent:billing").owner == "team-finance"
    assert second.tool("tool:refund").capabilities == ("tool:refund",)
    assert second.decisions() == [decision]
    assert second.registry.keys_for("agent:billing") == [keys.public_bytes]
    second.close()


def test_sqlite_control_plane_reports_schema_integrity_and_supports_backup(tmp_path) -> None:
    source_path = tmp_path / "source.db"
    backup_path = tmp_path / "backup.db"
    first = swarmauth.SQLiteControlPlane(str(source_path))
    assert first.schema_version() == 1
    assert first.integrity_check() is True
    first.backup(str(backup_path))
    first.close()

    backup = swarmauth.SQLiteControlPlane(str(backup_path))
    assert backup.schema_version() == 1
    assert backup.integrity_check() is True
    backup.close()


def test_tenant_control_plane_enforces_tenant_and_roles() -> None:
    store = swarmauth.ControlPlane()
    tenant = swarmauth.TenantControlPlane("tenant-a", store)
    operator = swarmauth.Principal.from_roles("user-1", "tenant-a", ["operator"])
    viewer = swarmauth.Principal.from_roles("user-2", "tenant-a", ["viewer"])
    other_tenant = swarmauth.Principal.from_roles("user-3", "tenant-b", ["admin"])
    keys = swarmauth.KeyPair.generate()

    tenant.register_agent(operator, "agent:a", owner="team-a", public_key=keys.public_bytes)
    assert len(tenant.agents(viewer)) == 1
    with pytest.raises(swarmauth.ControlPlaneAccessError):
        tenant.register_tool(viewer, "tool:x", owner="team-a", capabilities=("tool:x",))
    with pytest.raises(swarmauth.ControlPlaneAccessError):
        tenant.agents(other_tenant)


def test_re_registering_agent_replaces_root_and_holder_trust(tmp_path) -> None:
    database = tmp_path / "trust-role.db"
    root = swarmauth.KeyPair.generate()
    holder = swarmauth.KeyPair.generate()
    plane = swarmauth.SQLiteControlPlane(str(database))
    plane.register_agent("agent:x", owner="team", public_key=root.public_bytes, holder=False)
    plane.register_agent("agent:x", owner="team", public_key=holder.public_bytes, holder=True)
    with pytest.raises(swarmauth.UnknownIssuerError):
        plane.registry.keys_for("agent:x")
    assert plane.registry.holder_keys_for("agent:x") == [holder.public_bytes]
    plane.close()
    restarted = swarmauth.SQLiteControlPlane(str(database))
    with pytest.raises(swarmauth.UnknownIssuerError):
        restarted.registry.keys_for("agent:x")
    assert restarted.registry.holder_keys_for("agent:x") == [holder.public_bytes]
    restarted.close()
