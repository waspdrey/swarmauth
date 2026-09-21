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

The core suite (`tests/test_token.py`, `tests/test_middleware.py`,
`tests/test_registry.py`) has no dependencies beyond `cryptography` and
`pydantic` and should always pass.

`tests/test_redis_backend.py` runs against `fakeredis` by default (in
the `dev` extra, since `fakeredis` depends on `redis` itself, so `pip
install -e ".[dev]"` is enough). Set `SWARMAUTH_TEST_REDIS_URL` (e.g.
`redis://localhost:6379/0`) to run the identical tests against a real
server instead -- CI's `redis-backend-live` job does this against a real
`redis:7` container.

`tests/test_framework_adapters.py` exercises the LangChain, AutoGen/ag2, and
MCP adapters against real installs of those frameworks (not mocks). It's
skipped automatically if they aren't installed; to run it:

```bash
pip install -e ".[dev,frameworks]"
pytest tests/test_framework_adapters.py
```

CrewAI is intentionally not part of the `frameworks` extra — its dependency
chain (chromadb, onnxruntime, embedchain, ...) is heavy enough to noticeably
slow CI for one adapter. `secure_crewai_tool` is a direct delegation to
`secure_langchain_tool`, covered by the same test since CrewAI's `Tool`/
`BaseTool` classes expose the same `.func`/`._run` shape.

### Running everything locally across Python versions (`tox`)

`tox.ini` mirrors every CI job so you can reproduce a failure locally
without waiting on a push:

```bash
pip install tox
tox                  # py310, py311, py312, py313 (each core suite) + lint
tox -e py312         # just one Python version
tox -e frameworks    # tests/test_framework_adapters.py, real installs
tox -e redis-live    # tests/test_redis_backend.py against a real server
                      # (set SWARMAUTH_TEST_REDIS_URL first)
tox -e lint           # ruff + mypy --strict + dependency audit
```

`tox` only runs the Python versions actually installed on your machine
(`skip_missing_interpreters = true`) — CI's matrix is still the source of
truth for all four versions; `pyenv install 3.10 3.11 3.12 3.13` gets you
full local coverage if you want it.

## Linting, typing, and dependency audit

```bash
ruff check swarmauth tests
mypy swarmauth
python scripts/audit_deps.py
```

All three run in CI's `lint` job (and `tox -e lint`) and must pass. `mypy`
runs in `--strict` mode against `swarmauth/` only (not `tests/`) — the
library ships `Typing :: Typed` (`py.typed`), so its public surface must
actually be fully typed. `scripts/audit_deps.py` wraps `pip-audit --strict`
against the resolved dependency tree, excluding `swarmauth` itself (auditing
your own in-development package by name against PyPI fails before it's
released, which isn't a real finding — see the script's docstring); if it
flags something in a real dependency, that blocks merge until resolved
(bump the pin, or open an issue if no fix exists yet).

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

## Versioning and releases

This project follows [Semantic Versioning](https://semver.org/) once
released to PyPI; pre-1.0, a minor bump (`0.x.0`) signals a new capability
and a patch bump (`0.1.x`) signals a fix, same as post-1.0 discipline, just
without the API-stability guarantee `1.0.0` will carry.

- Every change that affects behavior gets an entry under `## [Unreleased]`
  in `CHANGELOG.md` in the same PR that makes the change — not retroactively
  when cutting a release. See the PR template checklist.
- The version number itself is chosen once, at release time, by whoever cuts
  the release — not earlier, and not as a placeholder "let's call it 0.2.0
  for now" bump in an unrelated PR. `pyproject.toml`'s `version` and
  `swarmauth/__init__.py`'s `__version__` must always match; CI's `lint` job
  enforces this and fails the build on a mismatch.
- Releasing: retitle `[Unreleased]` to `[x.y.z] - YYYY-MM-DD`, bump both
  version strings to match, add a fresh empty `[Unreleased]` above it, open
  a GitHub Release with that tag — `publish.yml` builds and publishes to
  PyPI via trusted publishing (OIDC) on release, no manual `twine upload`.
- Before tagging a release, build and sanity-check the actual artifact
  locally, since CI testing an editable install (`pip install -e .`) can
  miss packaging bugs an installed wheel would hit:

  ```bash
  rm -rf dist build
  python -m build
  twine check dist/*
  python -m venv /tmp/swarmauth-release-check
  /tmp/swarmauth-release-check/bin/pip install dist/*.whl
  /tmp/swarmauth-release-check/bin/python -c "import swarmauth; print(swarmauth.__version__)"
  ```

## Reporting a vulnerability

See [SECURITY.md](SECURITY.md) — please don't open a public issue for a
suspected security vulnerability in the protocol or SDK.
