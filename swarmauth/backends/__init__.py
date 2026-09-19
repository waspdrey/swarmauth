"""Optional distributed backends for usage tracking.

Nothing in this package is imported by `swarmauth.middleware` at module load
time -- `UsageTracker` (in-memory) remains the zero-dependency default.
Import from `swarmauth.backends.redis_backend` directly if you need a
distributed one; it requires the optional `redis` extra
(`pip install swarmauth[redis]`).
"""
