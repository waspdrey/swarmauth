# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

Nothing yet. Add entries here as changes land, under `### Added` /
`### Changed` / `### Fixed` / `### Security` as appropriate — move this
section under a new `## [x.y.z] - YYYY-MM-DD` heading only at release time,
choosing the version number then, not before.

## [0.1.5] - 2026-09-21

### Added

- **Token revocation**: `CapabilityToken.verify`, `verify_and_check`, and
  `guard()` all accept an optional `revocation_store`, letting a verifier
  reject a specific, otherwise-valid token before its signed expiry —
  needed for incident response and agent/session offboarding.
  `InMemoryRevocationStore` covers a single process; `RedisRevocationStore`
  (`swarmauth.backends.redis_backend`) shares revocations across every
  verifier process and expires its keys automatically, so no cleanup job
  is required.
- New `TokenRevokedError` exception, raised by `CapabilityToken.verify` when
  a presented token's `jti` has been revoked.

## [0.1.3] - 2026-09-20

### Fixed

- **Security**: `@guard()` now binds positional and keyword arguments to the
  protected callable's real signature before evaluating `allowed_params`.
  Parameter constraints can no longer be bypassed by invoking a tool with
  positional arguments.
- **Security**: budget accounting now rejects non-finite (`NaN`, infinity),
  negative, and non-numeric amounts before they reach either usage tracker.
  This prevents `NaN` from bypassing a `max_amount_usd` ceiling and poisoning
  subsequent in-memory accounting.

## [0.1.2] - 2026-09-19

### Fixed

- **Bug**: `secure_tool_call` (and therefore every framework adapter built on
  it — `secure_langchain_tool`, `secure_crewai_tool`, `secure_autogen_function`,
  `secure_mcp_tool`) silently dropped `amount_kwarg`, raising `TypeError` for
  anyone combining a framework adapter with `max_amount_usd` budget
  constraints. Only the raw `@guard()` decorator ever supported it. `0.1.1`
  is yanked on PyPI because of this; upgrade to `0.1.2`.

## [0.1.1] - 2026-09-19

### Changed

- Switched `license` to an SPDX expression (`MIT`) instead of a deprecated
  TOML table, and added PyPI classifiers and `project.urls` (Homepage,
  Repository, Issues, Documentation, Changelog) so the package page shows
  proper metadata and links.
- Added PyPI/CI/license/Python-version badges to the README.

## [0.1.0] - 2026-09-19

Initial release.

### Added

- Ed25519-signed, short-lived (≤300s) capability tokens (`CapabilityToken`,
  `TokenIssuer`) scoping exactly what an agent-to-agent or agent-to-tool call
  is authorized to do.
- `Constraints`: rate limits, call caps, budget caps, and parameter
  allowlists enforced at verification time.
- `KeyRegistry` for multi-issuer trust and key rotation without a hard
  cutover.
- `UsageTracker` (in-memory) and `RedisUsageTracker` (opt-in `redis` extra)
  for atomic constraint enforcement, the latter across every verifier
  process in a swarm.
- `guard` decorator and `secure_tool_call` for gating a plain Python
  callable on a valid token before it executes.
- Framework adapters: `secure_langchain_tool`, `secure_crewai_tool`,
  `secure_autogen_function`, `secure_mcp_tool` — each a thin, dependency-free
  wrapper tested against real LangChain, ag2, and MCP installs.

[0.1.5]: https://github.com/waspdrey/swarmauth/releases/tag/v0.1.5
[0.1.3]: https://github.com/waspdrey/swarmauth/releases/tag/v0.1.3
[0.1.2]: https://github.com/waspdrey/swarmauth/releases/tag/v0.1.2
[0.1.1]: https://github.com/waspdrey/swarmauth/releases/tag/v0.1.1
[0.1.0]: https://github.com/waspdrey/swarmauth/releases/tag/v0.1.0
