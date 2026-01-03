import os
import subprocess
import sys

import pytest

from py_landlock import is_supported


def _run_child(code: str, *args: str) -> subprocess.CompletedProcess[str]:
    env = os.environ.copy()
    env["PYTHONPATH"] = os.pathsep.join(
        [os.getcwd(), env.get("PYTHONPATH", "")]
    ).strip(os.pathsep)
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    return subprocess.run(
        [sys.executable, "-c", code, *args],
        env=env,
        text=True,
        capture_output=True,
        check=False,
    )


def test_sandbox_denies_write_outside_allowed(tmp_path) -> None:
    if not is_supported():
        pytest.skip("Landlock not supported on this kernel")

    allowed = tmp_path / "allowed"
    blocked = tmp_path / "blocked"
    allowed.mkdir()
    blocked.mkdir()

    code = """
import os
import sys

from py_landlock import Sandbox

allowed = sys.argv[1]
blocked = sys.argv[2]

Sandbox(write_paths=[allowed]).apply()

with open(os.path.join(allowed, "ok.txt"), "w", encoding="utf-8") as handle:
    handle.write("ok")

try:
    with open(os.path.join(blocked, "no.txt"), "w", encoding="utf-8") as handle:
        handle.write("no")
except PermissionError:
    sys.exit(0)
except OSError as exc:
    if exc.errno in (1, 13):
        sys.exit(0)
    raise
else:
    sys.exit(2)
"""

    result = _run_child(code, str(allowed), str(blocked))
    if result.returncode != 0:
        raise AssertionError(
            f"unexpected return code {result.returncode}\\n"
            f"stdout:\\n{result.stdout}\\n"
            f"stderr:\\n{result.stderr}"
        )
