"""Credential-free decision events for JSONL ingestion and log collectors."""
from __future__ import annotations

import json
import threading
from dataclasses import asdict
from typing import TextIO

from swarmauth.middleware import AuthorizationEvent


class JsonlDecisionSink:
    """Pass as on_decision. Write/flush failures prevent execution.

    The caller owns and closes the stream. The sink never receives raw tokens
    or tool arguments. Authorization events do not report side-effect success.
    """

    def __init__(self, stream: TextIO) -> None:
        self.stream, self._lock = stream, threading.Lock()

    def __call__(self, event: AuthorizationEvent) -> None:
        line = json.dumps(asdict(event), sort_keys=True, separators=(",", ":")) + "\n"
        with self._lock:
            self.stream.write(line)
            self.stream.flush()
