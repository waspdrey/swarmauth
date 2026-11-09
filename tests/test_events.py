from __future__ import annotations

import swarmauth


def test_execution_boundary_emits_safe_allow_and_deny_decisions() -> None:
    keys = swarmauth.KeyPair.generate()
    issuer = swarmauth.TokenIssuer(keys)
    token = issuer.issue(iss="agent:a", sub="tool:x", capabilities=["tool:x"])
    decisions: list[swarmauth.AuthorizationDecision] = []

    @swarmauth.guard("tool:x", issuer_public_key=keys.public_bytes, on_decision=decisions.append)
    def tool() -> str:
        return "ok"

    assert tool(token=token) == "ok"
    assert decisions[-1].outcome == "allow"
    assert decisions[-1].jti is not None
    assert not hasattr(decisions[-1], "token")

    decisions.clear()
    try:
        tool(token="not-a-token")
    except swarmauth.SwarmAuthError:
        pass
    assert decisions[-1].outcome == "deny"
    assert decisions[-1].reason is not None
