import io
import json
import sys

from swarmauth import CapabilityToken, Constraints, KeyPair, guard
from swarmauth.cli import main
from swarmauth.events import JsonlDecisionSink


def test_inspection_is_unverified_and_omits_credentials_and_pinned_values(monkeypatch, capsys):
    keys = KeyPair.generate()
    token = CapabilityToken.issue(issuer_keypair=keys, iss="issuer", sub="tool:x", capabilities=["tool:x"],
                                 constraints=Constraints(allowed_params={"account": "private-account"}))
    monkeypatch.setattr(sys, "stdin", io.StringIO(token))
    assert main(["inspect"]) == 0
    result = capsys.readouterr().out
    assert json.loads(result)["verified"] is False
    assert token not in result and "private-account" not in result


def test_policy_check_fails_closed_without_signing(tmp_path, capsys):
    policy = tmp_path / "policy.json"
    request = tmp_path / "request.json"
    policy.write_text(json.dumps({"grants": [{"iss": "issuer", "sub": "tool:x", "capabilities": ["tool:read"]}]}))
    request.write_text(json.dumps({"iss": "issuer", "sub": "tool:x", "capabilities": ["tool:write"]}))
    assert main(["policy-check", "--policy-file", str(policy), "--request-file", str(request)]) == 1
    assert json.loads(capsys.readouterr().err)["code"] == "POLICY_VIOLATION"


def test_jsonl_export_contains_metadata_only():
    output = io.StringIO()
    keys = KeyPair.generate()
    token = CapabilityToken.issue(issuer_keypair=keys, iss="issuer", sub="tool:x", capabilities=["tool:x"])

    @guard("tool:x", issuer_public_key=keys.public_bytes, on_decision=JsonlDecisionSink(output))
    def tool(private_value):
        return private_value
    assert tool("sensitive", token=token) == "sensitive"
    assert json.loads(output.getvalue())["decision"] == "allowed"
    assert token not in output.getvalue() and "sensitive" not in output.getvalue()
