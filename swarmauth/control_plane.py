"""Small, dependency-free governance core for a SwarmAuth control plane.

This module intentionally owns metadata and trust state, not private keys or
bearer tokens. It is suitable for a local pilot and provides the seam for a
hosted API/database implementation later.
"""
from __future__ import annotations

import json
import sqlite3
import threading
from dataclasses import dataclass
from typing import Literal, Optional, Sequence

from swarmauth.events import AuthorizationDecision
from swarmauth.exceptions import ControlPlaneAccessError
from swarmauth.registry import KeyRegistry


@dataclass(frozen=True)
class Principal:
    """Authenticated control-plane caller supplied by OAuth/OIDC middleware."""

    subject: str
    tenant_id: str
    roles: frozenset[str]

    @classmethod
    def from_roles(cls, subject: str, tenant_id: str, roles: Sequence[str]) -> "Principal":
        if not subject or not tenant_id:
            raise ValueError("subject and tenant_id are required")
        return cls(subject, tenant_id, frozenset(roles))


class TenantControlPlane:
    """Authenticated, tenant-scoped facade over a control-plane store.

    The underlying store should be provisioned per tenant until the hosted
    service adds row-level tenant partitioning. Every operation checks both
    tenant identity and role before reaching the store.
    """

    def __init__(self, tenant_id: str, store: "ControlPlane") -> None:
        if not tenant_id:
            raise ValueError("tenant_id is required")
        self.tenant_id = tenant_id
        self.store = store

    def _require(self, principal: Principal, *allowed_roles: str) -> None:
        if principal.tenant_id != self.tenant_id:
            raise ControlPlaneAccessError("principal is not a member of this tenant")
        if not principal.roles.intersection(allowed_roles) and "admin" not in principal.roles:
            raise ControlPlaneAccessError("principal lacks the required control-plane role")

    def register_agent(self, principal: Principal, agent_id: str, **kwargs: object) -> AgentRecord:
        self._require(principal, "operator")
        return self.store.register_agent(agent_id, **kwargs)  # type: ignore[arg-type]

    def register_tool(self, principal: Principal, tool_id: str, **kwargs: object) -> ToolRecord:
        self._require(principal, "operator")
        return self.store.register_tool(tool_id, **kwargs)  # type: ignore[arg-type]

    def revoke_agent(self, principal: Principal, agent_id: str) -> None:
        self._require(principal, "operator")
        self.store.revoke_agent(agent_id)

    def agents(self, principal: Principal) -> list[AgentRecord]:
        self._require(principal, "viewer", "operator")
        return self.store.agents()

    def tools(self, principal: Principal) -> list[ToolRecord]:
        self._require(principal, "viewer", "operator")
        return self.store.tools()

    def decisions(self, principal: Principal, **kwargs: object) -> list[AuthorizationDecision]:
        self._require(principal, "auditor")
        return self.store.decisions(**kwargs)  # type: ignore[arg-type]


@dataclass(frozen=True)
class AgentRecord:
    agent_id: str
    owner: str
    active: bool = True


@dataclass(frozen=True)
class ToolRecord:
    tool_id: str
    owner: str
    capabilities: tuple[str, ...]
    active: bool = True


class ControlPlane:
    """In-memory registry, revocation authority, and decision evidence store."""

    def __init__(self) -> None:
        self.registry = KeyRegistry()
        self._agents: dict[str, AgentRecord] = {}
        self._tools: dict[str, ToolRecord] = {}
        self._decisions: list[AuthorizationDecision] = []
        self._lock = threading.RLock()

    def register_agent(self, agent_id: str, *, owner: str, public_key: bytes, holder: bool = False) -> AgentRecord:
        if not agent_id or not owner:
            raise ValueError("agent_id and owner are required")
        with self._lock:
            if holder:
                self.registry.register_holder(agent_id, public_key)
            else:
                self.registry.register(agent_id, public_key)
            record = AgentRecord(agent_id, owner)
            self._agents[agent_id] = record
            return record

    def register_tool(self, tool_id: str, *, owner: str, capabilities: tuple[str, ...]) -> ToolRecord:
        if not tool_id or not owner or not capabilities or any(not item for item in capabilities):
            raise ValueError("tool_id, owner, and non-empty capabilities are required")
        with self._lock:
            record = ToolRecord(tool_id, owner, tuple(capabilities))
            self._tools[tool_id] = record
            return record

    def revoke_agent(self, agent_id: str) -> None:
        with self._lock:
            record = self._agents.get(agent_id)
            if record is None:
                return
            self.registry.revoke_issuer(agent_id)
            self._agents[agent_id] = AgentRecord(record.agent_id, record.owner, active=False)

    def agent(self, agent_id: str) -> AgentRecord:
        with self._lock:
            record = self._agents.get(agent_id)
            if record is None:
                raise KeyError(agent_id)
            return record

    def tool(self, tool_id: str) -> ToolRecord:
        with self._lock:
            record = self._tools.get(tool_id)
            if record is None:
                raise KeyError(tool_id)
            return record

    def agents(self) -> list[AgentRecord]:
        with self._lock:
            return list(self._agents.values())

    def tools(self) -> list[ToolRecord]:
        with self._lock:
            return list(self._tools.values())

    def record_decision(self, decision: AuthorizationDecision) -> None:
        with self._lock:
            self._decisions.append(decision)

    def decisions(
        self,
        *,
        outcome: Optional[Literal["allow", "deny"]] = None,
        capability: Optional[str] = None,
        issuer: Optional[str] = None,
    ) -> list[AuthorizationDecision]:
        with self._lock:
            return [
                decision
                for decision in self._decisions
                if (outcome is None or decision.outcome == outcome)
                and (capability is None or decision.capability == capability)
                and (issuer is None or decision.issuer == issuer)
            ]


class SQLiteControlPlane(ControlPlane):
    """Durable single-process control plane backed by SQLite.

    SQLite is appropriate for a pilot and local deployment. A hosted service
    should replace this with a transactional database and tenant-scoped auth.
    Only public keys, governance metadata, and decision metadata are stored.
    """

    def __init__(self, path: str) -> None:
        super().__init__()
        self._database = sqlite3.connect(path, check_same_thread=False)
        self._database.row_factory = sqlite3.Row
        self._database.execute("PRAGMA journal_mode=WAL")
        self._database.executescript(
            """
            CREATE TABLE IF NOT EXISTS schema_meta (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS agents (
                agent_id TEXT PRIMARY KEY,
                owner TEXT NOT NULL,
                active INTEGER NOT NULL,
                public_key BLOB NOT NULL,
                holder INTEGER NOT NULL
            );
            CREATE TABLE IF NOT EXISTS tools (
                tool_id TEXT PRIMARY KEY,
                owner TEXT NOT NULL,
                capabilities TEXT NOT NULL,
                active INTEGER NOT NULL
            );
            CREATE TABLE IF NOT EXISTS decisions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp REAL NOT NULL,
                outcome TEXT NOT NULL,
                capability TEXT,
                audience TEXT,
                issuer TEXT,
                subject TEXT,
                jti TEXT,
                reason TEXT
            );
            """
        )
        current_version = self._database.execute("SELECT value FROM schema_meta WHERE key='schema_version'").fetchone()
        if current_version is None:
            self._database.execute("INSERT INTO schema_meta (key, value) VALUES ('schema_version', '1')")
        elif current_version[0] != "1":
            raise RuntimeError(f"unsupported control-plane schema version: {current_version[0]}")
        self._database.commit()
        self._load()

    def _load(self) -> None:
        for row in self._database.execute("SELECT * FROM agents"):
            agent_record = AgentRecord(row["agent_id"], row["owner"], bool(row["active"]))
            self._agents[agent_record.agent_id] = agent_record
            if agent_record.active:
                if row["holder"]:
                    self.registry.register_holder(agent_record.agent_id, bytes(row["public_key"]))
                else:
                    self.registry.register(agent_record.agent_id, bytes(row["public_key"]))
        for row in self._database.execute("SELECT * FROM tools"):
            tool_record = ToolRecord(row["tool_id"], row["owner"], tuple(json.loads(row["capabilities"])), bool(row["active"]))
            self._tools[tool_record.tool_id] = tool_record
        for row in self._database.execute("SELECT * FROM decisions ORDER BY id"):
            self._decisions.append(
                AuthorizationDecision(
                    row["timestamp"], row["outcome"], row["capability"], row["audience"],
                    row["issuer"], row["subject"], row["jti"], row["reason"]
                )
            )

    def register_agent(self, agent_id: str, *, owner: str, public_key: bytes, holder: bool = False) -> AgentRecord:
        record = super().register_agent(agent_id, owner=owner, public_key=public_key, holder=holder)
        self._database.execute(
            "INSERT INTO agents VALUES (?, ?, ?, ?, ?) "
            "ON CONFLICT(agent_id) DO UPDATE SET owner=excluded.owner, "
            "active=excluded.active, public_key=excluded.public_key, holder=excluded.holder",
            (agent_id, owner, int(record.active), bytes(public_key), int(holder)),
        )
        self._database.commit()
        return record

    def register_tool(self, tool_id: str, *, owner: str, capabilities: tuple[str, ...]) -> ToolRecord:
        record = super().register_tool(tool_id, owner=owner, capabilities=capabilities)
        self._database.execute(
            "INSERT INTO tools VALUES (?, ?, ?, ?) "
            "ON CONFLICT(tool_id) DO UPDATE SET owner=excluded.owner, "
            "capabilities=excluded.capabilities, active=excluded.active",
            (tool_id, owner, json.dumps(list(capabilities)), int(record.active)),
        )
        self._database.commit()
        return record

    def revoke_agent(self, agent_id: str) -> None:
        super().revoke_agent(agent_id)
        self._database.execute("UPDATE agents SET active=0 WHERE agent_id=?", (agent_id,))
        self._database.commit()

    def record_decision(self, decision: AuthorizationDecision) -> None:
        super().record_decision(decision)
        self._database.execute(
            "INSERT INTO decisions (timestamp, outcome, capability, audience, issuer, subject, jti, reason) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (
                decision.timestamp,
                decision.outcome,
                decision.capability,
                decision.audience,
                decision.issuer,
                decision.subject,
                decision.jti,
                decision.reason,
            ),
        )
        self._database.commit()

    def decisions(
        self,
        *,
        outcome: Optional[Literal["allow", "deny"]] = None,
        capability: Optional[str] = None,
        issuer: Optional[str] = None,
    ) -> list[AuthorizationDecision]:
        clauses: list[str] = []
        values: list[str] = []
        for column, value in (("outcome", outcome), ("capability", capability), ("issuer", issuer)):
            if value is not None:
                clauses.append(f"{column}=?")
                values.append(value)
        where = f" WHERE {' AND '.join(clauses)}" if clauses else ""
        rows = self._database.execute(f"SELECT * FROM decisions{where} ORDER BY id", values)
        return [
                AuthorizationDecision(
                    row["timestamp"],
                    row["outcome"],
                    row["capability"],
                    row["audience"],
                    row["issuer"],
                    row["subject"],
                    row["jti"],
                    row["reason"],
                )
            for row in rows
        ]

    def close(self) -> None:
        self._database.close()

    def schema_version(self) -> int:
        row = self._database.execute("SELECT value FROM schema_meta WHERE key='schema_version'").fetchone()
        if row is None:
            raise RuntimeError("control-plane schema metadata is missing")
        return int(row[0])

    def integrity_check(self) -> bool:
        row = self._database.execute("PRAGMA integrity_check").fetchone()
        return row is not None and row[0] == "ok"

    def backup(self, destination: str) -> None:
        """Create a consistent SQLite backup while the service remains online."""
        target = sqlite3.connect(destination)
        try:
            with self._lock:
                self._database.backup(target)
        finally:
            target.close()
