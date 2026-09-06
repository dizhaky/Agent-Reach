"""Start pytest with deterministic interpreter state."""

import os
import subprocess
import sys

env = dict(os.environ)
env["PYTHONHASHSEED"] = "0"
result = subprocess.run(
    [sys.executable, "-m", "pytest", *sys.argv[1:]],
    env=env,
    check=False,
)
raise SystemExit(result.returncode)
