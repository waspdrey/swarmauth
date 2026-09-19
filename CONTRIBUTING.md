# Contributing to SwarmAuth

Thanks for considering a contribution. SwarmAuth is early (`0.1.x`) — the
token format and verification algorithm in [SPEC.md](SPEC.md) are meant to
be stable; everything else (framework adapters, distributed usage tracking)
is expected to evolve with real integration feedback.

## Development setup

```bash
git clone <this repo>
cd swarmauth
python -m venv .venv
source .venv/bin/activate  # .venv\Scripts\activate on Windows

pip install -e ".[dev]"
```

## Running the test suite

```bash
pytest
```

The core suite (`tests/test_token.py`, `tests/test_middleware.py`) has no
dependencies beyond `cryptography` and `pydantic` and should always pass.

`tests/test_framework_adapters.py` exercises the LangChain and AutoGen/ag2
adapters against real installs of those frameworks (not mocks). It's skipped
automatically if they aren't installed; to run it:

```bash
pip install -e ".[dev,frameworks]"
pytest tests/test_framework_adapters.py
```

CrewAI is intentionally not part of the `frameworks` extra — its dependency
chain (chromadb, onnxruntime, embedchain, ...) is heavy enough to noticeably
slow CI for one adapter. `secure_crewai_tool` is a direct delegation to
`secure_langchain_tool`, covered by the same test since CrewAI's `Tool`/
`BaseTool` classes expose the same `.func`/`._run` shape.

## Running the benchmark

```bash
python benchmarks/swarmbench.py
```

This should always show the unprotected scenario executing the unauthorized
payout and the protected scenario blocking it — if you change token
verification or constraint logic, re-run this and confirm both assertions at
the bottom of `main()` still hold.

## Making changes

- **Protocol changes** (anything touching the claims schema, canonicalization,
  or verification algorithm in `swarmauth/token.py`) must be reflected in
  [SPEC.md](SPEC.md) in the same PR — the spec is the source of truth, not
  the code's docstrings.
- **New framework adapters** should ship with a real-install integration
  test in `tests/test_framework_adapters.py` (or a new file, if the
  dependency is heavy enough to warrant its own opt-in extra), not a mock of
  the framework's API — framework APIs change (see the AutoGen-family churn
  documented in `swarmauth/middleware.py`), and mocked tests won't catch it.
- **Security-relevant changes** — anything affecting signature verification,
  expiry, capability checks, or constraint enforcement — should call that
  out explicitly in the PR description, since these are the properties the
  whole project exists to guarantee.
- Keep the zero-exotic-dependency principle: `cryptography` and `pydantic`
  are the only hard runtime dependencies. If a change seems to need
  something else, that's worth discussing in an issue first.

## Reporting a vulnerability

See [SECURITY.md](SECURITY.md) — please don't open a public issue for a
suspected security vulnerability in the protocol or SDK.
