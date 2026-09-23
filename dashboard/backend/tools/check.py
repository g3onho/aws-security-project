"""Reproducible local/CI checks. Requires development dependencies and Node.js."""
from pathlib import Path
import shutil
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]


def main():
    node = shutil.which("node")
    if not node:
        raise SystemExit("Node.js is required for compatibility Store tests; the app itself needs only Python.")
    for command in ([sys.executable, "-m", "pytest", "tests", "-q"],
                    [node, "--test", "tests/test_compat_store.mjs"]):
        result = subprocess.run(command, cwd=ROOT, check=False)
        if result.returncode:
            raise SystemExit(result.returncode)


if __name__ == "__main__":
    main()
