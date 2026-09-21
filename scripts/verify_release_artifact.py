"""Run the full test suite against a BUILT WHEEL, before it ever reaches PyPI.

This is the gate that would have caught the UnknownIssuerError export bug
that shipped in 0.1.5: CI runs against an editable install (`pip install
-e .`), which reads swarmauth/__init__.py from the repo directly and
happens to behave identically to a real install for that particular bug --
but nothing had ever installed the actual built *artifact* and run the
suite against it before this script existed.

It does three things a quick `import swarmauth; print(__version__)` check
does not:
  1. Installs from the wheel in dist/, not the repo -- catches packaging
     bugs (files missing from the wheel, stale metadata).
  2. Runs in a venv with no editable install and no repo directory on
     sys.path at all -- catches the "it works because Python silently
     resolved the import back to the local source tree" trap.
  3. Runs the REAL test suite (tests/), not a hand-picked smoke subset --
     every existing test becomes a release gate for free.

Usage:
    rm -rf dist build swarmauth.egg-info && python -m build
    python scripts/verify_release_artifact.py
"""
from __future__ import annotations

import shutil
import subprocess
import sys
import tempfile
import venv
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent


def latest_wheel() -> Path:
    wheels = sorted((REPO_ROOT / "dist").glob("*.whl"))
    if not wheels:
        sys.exit("No wheel in dist/ -- run `python -m build` first.")
    return wheels[-1]


def main() -> int:
    wheel = latest_wheel()
    print(f"Verifying {wheel.name} ...")

    with tempfile.TemporaryDirectory(prefix="swarmauth-release-check-") as tmp:
        tmp_path = Path(tmp)
        venv_dir = tmp_path / "venv"
        venv.create(venv_dir, with_pip=True)
        python = venv_dir / "Scripts" / "python.exe" if sys.platform == "win32" else venv_dir / "bin" / "python"

        # tests/ physically copied OUTSIDE the repo so pytest's rootdir/sys.path
        # insertion can never resolve `import swarmauth` back to the repo's own
        # swarmauth/ source directory instead of the installed wheel.
        tests_copy = tmp_path / "tests"
        shutil.copytree(REPO_ROOT / "tests", tests_copy)

        subprocess.run([str(python), "-m", "pip", "install", "-q", "--upgrade", "pip"], check=True)
        subprocess.run(
            [str(python), "-m", "pip", "install", "-q", f"{wheel}[redis]", "pytest>=8.0", "fakeredis>=2.20"],
            check=True,
        )

        # test_framework_adapters.py self-skips via pytest.importorskip when
        # the (heavy, opt-in) `frameworks` extra isn't installed -- not
        # installed here, so it'll show as skipped rather than failed.
        result = subprocess.run([str(python), "-m", "pytest", "-v"], cwd=tests_copy)
        if result.returncode != 0:
            print("\nRELEASE ARTIFACT VERIFICATION FAILED -- do not publish this build.")
            return result.returncode

        origin_check = subprocess.run(
            [str(python), "-c", "import swarmauth, os; print(os.path.dirname(swarmauth.__file__))"],
            cwd=tmp_path,
            capture_output=True,
            text=True,
            check=True,
        )
        origin = origin_check.stdout.strip()
        if str(REPO_ROOT) in origin:
            print(f"\nRELEASE ARTIFACT VERIFICATION FAILED -- swarmauth resolved back to the repo, not the wheel: {origin}")
            return 1
        print(f"\nConfirmed installed from wheel, not repo: {origin}")

    print("RELEASE ARTIFACT VERIFICATION PASSED")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
