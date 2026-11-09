"""Deployable OIDC-backed control-plane WSGI application.

Required environment:

    SWARMAUTH_OIDC_ISSUER=https://idp.example.com/
    SWARMAUTH_OIDC_AUDIENCE=swarmauth-control-plane
    SWARMAUTH_OIDC_JWKS_URL=https://idp.example.com/.well-known/jwks.json
    SWARMAUTH_CONTROL_PLANE_DB_DIR=/var/lib/swarmauth

Run behind a TLS-terminating WSGI deployment, for example:

    gunicorn examples.control_plane_oidc_wsgi:application
"""
from swarmauth.control_plane_wsgi import application  # noqa: F401
