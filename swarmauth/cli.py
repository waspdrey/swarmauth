"""Offline inspection and policy diagnostics. Read credentials from stdin."""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any, Optional, Sequence

from swarmauth.exceptions import SwarmAuthError
from swarmauth.policy import IssuerPolicy
from swarmauth.token import CapabilityToken, Constraints, _require_ttl, check_capability, check_params


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="SwarmAuth offline diagnostics; tokens are read from stdin")
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("inspect", help="Inspect unverified metadata; parameter values and parent tokens are omitted")
    verify = sub.add_parser("verify", help="Check crypto and action pins without reserving usage or checking revocation")
    verify.add_argument("--public-key-hex", required=True)
    verify.add_argument("--audience", required=True)
    verify.add_argument("--capability", required=True)
    verify.add_argument("--params-file", type=Path)
    policy = sub.add_parser("policy-check", help="Explain whether a configured issuer grant covers a request")
    policy.add_argument("--policy-file", required=True, type=Path)
    policy.add_argument("--request-file", required=True, type=Path)
    args = parser.parse_args(argv)
    try:
        if args.command == "policy-check":
            configured = IssuerPolicy.from_dict(json.loads(args.policy_file.read_text()))
            request = json.loads(args.request_file.read_text())
            if not isinstance(request, dict):
                raise ValueError("Request must be an object")
            ttl = request.setdefault("ttl_seconds", 10)
            _require_ttl(ttl)
            request["constraints"] = Constraints.model_validate(request.get("constraints", {}))
            configured.check(**request)
            result: dict[str, Any] = {"decision": "allowed", "signed": False}
        else:
            token = sys.stdin.read(65537).strip()
            if len(token) > 65536:
                raise ValueError("Token exceeds inspection limit")
            if args.command == "inspect":
                _header, claims, _input = CapabilityToken.parse(token)
                result = {"verified": False, "issuer": claims.iss, "audience": claims.sub,
                          "capabilities": claims.capabilities, "token_id": claims.jti,
                          "iat": claims.iat, "exp": claims.exp, "delegated": bool(claims.prf),
                          "pinned_parameter_names": sorted(claims.constraints.allowed_params)}
            else:
                key = bytes.fromhex(args.public_key_hex)
                if len(key) != 32:
                    raise ValueError("Expected a 32-byte public key")
                claims = CapabilityToken.verify(token, issuer_public_key=key, audience=args.audience)
                check_capability(claims, args.capability)
                params = json.loads(args.params_file.read_text()) if args.params_file else {}
                check_params(claims, params)
                result = {"signature_and_pins_valid": True, "usage_reserved": False,
                          "revocation_checked": False, "execution_authorized": False,
                          "note": "Offline diagnostic only; use guard/async_guard at execution"}
        print(json.dumps(result, sort_keys=True))
        return 0
    except SwarmAuthError as exc:
        print(json.dumps({"decision": "denied", "code": exc.code}), file=sys.stderr)
        return 1
    except (ValueError, TypeError, OSError, KeyError):
        print(json.dumps({"decision": "denied", "code": "INVALID_INPUT"}), file=sys.stderr)
        return 2
