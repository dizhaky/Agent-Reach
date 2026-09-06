"""Start pytest with deterministic interpreter state."""

import os
import sys

env = dict(os.environ)
env["PYTHONHASHSEED"] = "0"
os.execvpe(
    sys.executable,
    [sys.executable, "-m", "pytest", *sys.argv[1:]],
    env,
)
