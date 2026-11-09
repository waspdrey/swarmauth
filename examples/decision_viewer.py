"""Tiny local viewer for JSONL authorization decisions.

    python examples/decision_viewer.py .local/decisions.jsonl
    open http://127.0.0.1:8765

This is a pilot/debugging tool, not the production control plane.
"""
from __future__ import annotations

import html
import json
import sys
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path


def render(path: Path) -> str:
    rows = []
    if path.exists():
        for line in path.read_text(encoding="utf-8").splitlines()[-200:]:
            try:
                rows.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    columns = ("timestamp", "outcome", "capability", "issuer", "subject", "jti", "reason")
    body = "".join(
        "<tr>"
        + "".join(f'<td>{html.escape(str(item.get(key, "")))}</td>' for key in columns)
        + "</tr>"
        for item in reversed(rows)
    )
    return (
        "<html><meta http-equiv='refresh' content='3'>"
        "<style>body{font:14px system-ui;margin:2rem}"
        "table{border-collapse:collapse;width:100%}"
        "td,th{border:1px solid #ddd;padding:.5rem;text-align:left}"
        ".allow{color:green}.deny{color:#b00}</style>"
        "<h1>SwarmAuth decisions</h1><table>"
        "<tr><th>Time</th><th>Outcome</th><th>Capability</th><th>Issuer</th>"
        "<th>Subject</th><th>JTI</th><th>Reason</th></tr>"
        + body
        + "</table></html>"
    )


def main() -> None:
    path = Path(sys.argv[1] if len(sys.argv) > 1 else ".local/decisions.jsonl")

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:  # noqa: N802
            content = render(path).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(content)))
            self.end_headers()
            self.wfile.write(content)

        def log_message(self, *_: object) -> None:
            return

    print(f"Viewing {path} at http://127.0.0.1:8765")
    HTTPServer(("127.0.0.1", 8765), Handler).serve_forever()


if __name__ == "__main__":
    main()
