"""Loopback-only control-plane pilot API.

This is intentionally a local integration harness, not a production service:
it has no authentication, tenancy, or RBAC. Set ``SWARMAUTH_CONTROL_PLANE_DB``
to a SQLite path when you want state to survive restarts; omit it for memory.

    python examples/control_plane_server.py
"""
from __future__ import annotations

import json
import os
from dataclasses import asdict
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any
from urllib.parse import urlparse

import swarmauth

database_path = os.environ.get("SWARMAUTH_CONTROL_PLANE_DB")
plane = swarmauth.SQLiteControlPlane(database_path) if database_path else swarmauth.ControlPlane()


def payload(handler: BaseHTTPRequestHandler) -> dict[str, Any]:
    length = int(handler.headers.get("Content-Length", "0"))
    value = json.loads(handler.rfile.read(length))
    if not isinstance(value, dict):
        raise ValueError("JSON body must be an object")
    return value


class Handler(BaseHTTPRequestHandler):
    def send_json(self, status: int, value: Any) -> None:
        encoded = json.dumps(value, sort_keys=True).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(encoded)))
        self.end_headers()
        self.wfile.write(encoded)

    def do_GET(self) -> None:  # noqa: N802
        path = urlparse(self.path).path
        if path == "/health":
            self.send_json(200, {"ok": True})
        elif path == "/agents":
            self.send_json(200, [asdict(agent) for agent in plane.agents()])
        elif path == "/tools":
            self.send_json(200, [asdict(tool) for tool in plane.tools()])
        elif path == "/decisions":
            self.send_json(200, [decision.as_dict() for decision in plane.decisions()])
        else:
            self.send_json(404, {"error": "not_found"})

    def do_POST(self) -> None:  # noqa: N802
        try:
            body = payload(self)
            path = urlparse(self.path).path
            if path == "/agents":
                record = plane.register_agent(
                    body["agent_id"],
                    owner=body["owner"],
                    public_key=bytes.fromhex(body["public_key_hex"]),
                    holder=bool(body.get("holder", False)),
                )
                self.send_json(201, asdict(record))
            elif path == "/tools":
                record = plane.register_tool(
                    body["tool_id"], owner=body["owner"], capabilities=tuple(body["capabilities"])
                )
                self.send_json(201, asdict(record))
            else:
                self.send_json(404, {"error": "not_found"})
        except (KeyError, TypeError, ValueError) as exc:
            self.send_json(400, {"error": str(exc)})

    def log_message(self, *_: object) -> None:
        return


def main() -> None:
    print("Control-plane pilot listening on http://127.0.0.1:8787")
    ThreadingHTTPServer(("127.0.0.1", 8787), Handler).serve_forever()


if __name__ == "__main__":
    main()
