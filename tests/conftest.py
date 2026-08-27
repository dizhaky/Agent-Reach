# -*- coding: utf-8 -*-
"""Suite-wide containment and test isolation for Agent Reach."""

from __future__ import annotations

import atexit
import os
import shutil
import subprocess
import tempfile
from pathlib import Path

import pytest

# ── Import-Time Sandbox Isolation ──────────────────────────────────────────
# Module collection and top-level module imports must never bind to the
# operator's live Home, live config, or live runtime state.
#
# These MUST be plain assignment, never setdefault. setdefault defers to an
# already-exported value, which makes the guard a no-op on a developer machine.
_SESSION_SANDBOX = tempfile.TemporaryDirectory(prefix="agent-reach-test-sandbox-")
atexit.register(_SESSION_SANDBOX.cleanup)
_SANDBOX_PATH = _SESSION_SANDBOX.name

os.environ["HOME"] = _SANDBOX_PATH
os.environ["USERPROFILE"] = _SANDBOX_PATH
os.environ["XDG_CONFIG_HOME"] = str(Path(_SANDBOX_PATH) / ".config")
os.environ["APPDATA"] = str(Path(_SANDBOX_PATH) / "AppData" / "Roaming")
os.environ["LOCALAPPDATA"] = str(Path(_SANDBOX_PATH) / "AppData" / "Local")
os.environ.pop("OPENCLAW_HOME", None)

HOME_AT_CONFTEST_IMPORT = os.environ.get("HOME")
USERPROFILE_AT_CONFTEST_IMPORT = os.environ.get("USERPROFILE")
XDG_CONFIG_HOME_AT_CONFTEST_IMPORT = os.environ.get("XDG_CONFIG_HOME")
APPDATA_AT_CONFTEST_IMPORT = os.environ.get("APPDATA")
LOCALAPPDATA_AT_CONFTEST_IMPORT = os.environ.get("LOCALAPPDATA")

# ── Credential env-var filter ──────────────────────────────────────────────
_CREDENTIAL_SUFFIXES = (
    "_API_KEY",
    "_TOKEN",
    "_SECRET",
    "_PASSWORD",
    "_CREDENTIALS",
    "_ACCESS_KEY",
    "_PRIVATE_KEY",
    "_OAUTH_TOKEN",
    "_WEBHOOK_SECRET",
    "_CLIENT_SECRET",
)

_CREDENTIAL_NAMES = frozenset({
    "EXA_API_KEY",
    "OPENAI_API_KEY",
    "GROQ_API_KEY",
    "GITHUB_TOKEN",
    "TWITTER_AUTH_TOKEN",
    "TWITTER_CT0",
    "LINEAR_API_KEY",
    "ANTHROPIC_API_KEY",
    "GEMINI_API_KEY",
    "MISTRAL_API_KEY",
    "DEEPSEEK_API_KEY",
    "OPENROUTER_API_KEY",
    "SLACK_BOT_TOKEN",
    "SLACK_USER_TOKEN",
    "SLACK_APP_TOKEN",
})


def _is_credential(name: str) -> bool:
    """True if name matches a credential pattern or explicit name."""
    if name in _CREDENTIAL_NAMES:
        return True
    return any(name.endswith(suf) for suf in _CREDENTIAL_SUFFIXES)


_is_credential_var = _is_credential


# Scrub all credentials immediately at import time
for _key in list(os.environ.keys()):
    if _is_credential(_key):
        os.environ.pop(_key, None)

# ── Deterministic Runtime Variables ────────────────────────────────────────
os.environ["AWS_EC2_METADATA_DISABLED"] = "true"
os.environ["AWS_METADATA_SERVICE_TIMEOUT"] = "1"
os.environ["AWS_METADATA_SERVICE_NUM_ATTEMPTS"] = "1"
os.environ["TZ"] = "UTC"
os.environ["LANG"] = "C.UTF-8"
os.environ["LC_ALL"] = "C.UTF-8"
os.environ["PYTHONHASHSEED"] = "0"

# ── Module-Level macOS Security CLI Interceptor ─────────────────────────────
_ORIG_WHICH = shutil.which
_orig_subprocess_run = subprocess.run


def _guarded_subprocess_run(args, *pargs, **kwargs):
    cmd0 = ""
    if isinstance(args, (list, tuple)) and args:
        cmd0 = str(args[0])
    elif isinstance(args, (str, bytes, os.PathLike)):
        parts = str(args).split()
        cmd0 = parts[0] if parts else ""

    if Path(cmd0).name == "security":
        check = kwargs.get("check", False)
        is_text = kwargs.get("text") or kwargs.get("universal_newlines")
        out = "" if is_text else b""
        err = (
            "Keychain access disabled in test suite"
            if is_text
            else b"Keychain access disabled in test suite"
        )
        if check:
            raise subprocess.CalledProcessError(
                returncode=1,
                cmd=args,
                output=out,
                stderr=err,
            )
        return subprocess.CompletedProcess(
            args=args,
            returncode=1,
            stdout=out,
            stderr=err,
        )
    return _orig_subprocess_run(args, *pargs, **kwargs)


subprocess.run = _guarded_subprocess_run

from agent_reach.config import Config  # noqa: E402


@pytest.fixture(autouse=True)
def _clean_test_env(monkeypatch):
    """Re-scrub credential environment variables before every single test."""
    for key in list(os.environ.keys()):
        if _is_credential(key):
            monkeypatch.delenv(key, raising=False)


@pytest.fixture(scope="session")
def bash_executable() -> str:
    """Return a real GNU Bash, avoiding Windows' WSL launcher stub."""
    candidates: list[Path] = []
    override = os.environ.get("AGENT_REACH_TEST_BASH")
    if override:
        candidates.append(Path(override))

    if os.name == "nt":
        for env_name in ("PROGRAMFILES", "PROGRAMFILES(X86)"):
            program_files = os.environ.get(env_name)
            if program_files:
                git_root = Path(program_files) / "Git"
                candidates.extend(
                    (git_root / "bin" / "bash.exe", git_root / "usr" / "bin" / "bash.exe")
                )

        local_app_data = os.environ.get("LOCALAPPDATA")
        if local_app_data:
            git_root = Path(local_app_data) / "Programs" / "Git"
            candidates.extend(
                (git_root / "bin" / "bash.exe", git_root / "usr" / "bin" / "bash.exe")
            )

        git = _ORIG_WHICH("git")
        if git:
            git_parent = Path(git).resolve().parent
            if git_parent.name.lower() in {"bin", "cmd"}:
                git_root = git_parent.parent
                candidates.extend(
                    (git_root / "bin" / "bash.exe", git_root / "usr" / "bin" / "bash.exe")
                )

    discovered = _ORIG_WHICH("bash")
    if discovered:
        candidates.append(Path(discovered))

    seen: set[str] = set()
    for candidate in candidates:
        key = os.path.normcase(os.fspath(candidate))
        if key in seen or not candidate.is_file():
            continue
        seen.add(key)
        try:
            result = subprocess.run(
                [os.fspath(candidate), "--version"],
                capture_output=True,
                encoding="utf-8",
                errors="replace",
                timeout=5,
            )
        except (OSError, subprocess.TimeoutExpired):
            continue
        if result.returncode == 0 and "GNU bash" in result.stdout:
            return os.fspath(candidate)

    pytest.fail("GNU Bash is required for shell-script tests")


@pytest.fixture(autouse=True)
def isolated_home(tmp_path, monkeypatch):
    """Redirect every common home/config root before each test runs."""
    home = tmp_path / "home"
    home.mkdir(mode=0o700)
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("USERPROFILE", str(home))
    monkeypatch.setenv("XDG_CONFIG_HOME", str(home / ".config"))
    monkeypatch.setenv("APPDATA", str(home / "AppData" / "Roaming"))
    monkeypatch.setenv("LOCALAPPDATA", str(home / "AppData" / "Local"))
    monkeypatch.delenv("OPENCLAW_HOME", raising=False)

    config_dir = home / ".agent-reach"
    monkeypatch.setattr(Config, "CONFIG_DIR", config_dir)
    monkeypatch.setattr(Config, "CONFIG_FILE", config_dir / "config.yaml")
    return home


@pytest.fixture(autouse=True)
def isolated_xueqiu_cookie_jar(monkeypatch):
    """Prevent the module-level Xueqiu session from leaking between tests."""
    from agent_reach.channels import xueqiu

    xueqiu._cookie_jar.clear()
    monkeypatch.setattr(xueqiu, "_cookies_initialized", False)
    yield
    xueqiu._cookie_jar.clear()
