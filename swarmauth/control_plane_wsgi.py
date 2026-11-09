"""Installed-package OIDC-backed control-plane WSGI entrypoint."""
from __future__ import annotations

import hashlib
import os
import threading
from pathlib import Path

from swarmauth.control_plane import SQLiteControlPlane
from swarmauth.control_plane_http import ControlPlaneHTTPApp
from swarmauth.oidc import OIDCPrincipalResolver

issuer = os.environ["SWARMAUTH_OIDC_ISSUER"]
audience = os.environ["SWARMAUTH_OIDC_AUDIENCE"]
jwks_url = os.environ["SWARMAUTH_OIDC_JWKS_URL"]
database_dir = Path(os.environ["SWARMAUTH_CONTROL_PLANE_DB_DIR"])
database_dir.mkdir(parents=True, exist_ok=True)

resolver = OIDCPrincipalResolver(issuer=issuer, audience=audience, jwks_url=jwks_url)
stores: dict[str, SQLiteControlPlane] = {}
stores_lock = threading.Lock()


def store_for_tenant(tenant_id: str) -> SQLiteControlPlane:
    """Open one durable database per tenant; tenant IDs never become filenames."""
    with stores_lock:
        if tenant_id not in stores:
            digest = hashlib.sha256(tenant_id.encode("utf-8")).hexdigest()
            stores[tenant_id] = SQLiteControlPlane(str(database_dir / f"tenant-{digest}.db"))
        return stores[tenant_id]


application = ControlPlaneHTTPApp(resolver, store_for_tenant)
