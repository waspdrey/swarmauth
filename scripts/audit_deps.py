"""Run pip-audit against the resolved dependency tree, excluding swarmauth itself.

pip-audit's default "audit the whole environment" mode looks up every
installed distribution on PyPI -- including swarmauth, since it's installed
too (editable in a dev checkout, or from the built sdist in CI/tox). Before
the current version has been released, that lookup fails with "not found on
PyPI", which is not a real vulnerability finding, just an artifact of
auditing your own in-development package by name. Excluding it via
`pip freeze --exclude` and auditing the resulting requirements list
(`--no-deps`, since `pip freeze` already resolved everything) avoids that
false failure while still catching real vulnerabilities in every dependency.

Used by CI's `lint` job and `tox -e lint`; not part of the published
package.
"""
from __future__ import annotations

import subprocess
import sys
import tempfile


def main() -> int:
    freeze = subprocess.run(
        [sys.executable, "-m", "pip", "freeze", "--exclude", "swarmauth"],
        capture_output=True,
        text=True,
        check=True,
    ).stdout

    with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
        f.write(freeze)
        requirements_path = f.name

    return subprocess.run(
        [sys.executable, "-m", "pip_audit", "--strict", "-r", requirements_path, "--no-deps"]
    ).returncode


if __name__ == "__main__":
    raise SystemExit(main())
