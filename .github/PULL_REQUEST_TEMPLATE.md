<!--
Thanks for contributing to SwarmAuth. This is a security-critical library --
please fill this in even for small changes. See CONTRIBUTING.md for the full
guide.
-->

## What does this change, and why?

## Checklist

- [ ] Tests added/updated for this change (`pytest -v`)
- [ ] `ruff check swarmauth tests` passes
- [ ] `mypy swarmauth` passes
- [ ] `CHANGELOG.md` updated under `[Unreleased]` (or this PR intentionally
      needs no changelog entry -- e.g. docs-only, CI-only)
- [ ] If this PR is the one cutting a release: version bumped in
      `pyproject.toml` **and** `swarmauth/__init__.py` (must match), and the
      `[Unreleased]` section retitled to that version + today's date
- [ ] If this changes the wire protocol, verification algorithm, or claims
      schema: `SPEC.md` updated to match
- [ ] If this adds/changes public API: `README.md` updated to match

## Security-relevant?

If this touches `swarmauth/crypto.py`, `swarmauth/token.py`,
`swarmauth/middleware.py`, or the protocol in `SPEC.md`, say so explicitly
and describe the threat-model impact (see `SECURITY.md` scope).
