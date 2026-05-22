#!/usr/bin/env python3
"""EnvShield PreToolUse hook.

Blocks Claude Code from reading secret material (.env, SSH keys, AWS
credentials, etc.) and from running bash commands that would exfiltrate
secrets via stdout (printenv, docker compose config, cat .env, …).

Every block is appended as a JSON line to ~/.claude/envshield/audit.log.

Escape hatches (in order of precedence):
  1. ENVSHIELD_DISABLE=1 — fully off for this session.
  2. ENVSHIELD_AUDIT_ONLY=1 — log but never deny.
  3. A literal "# envshield:allow" anywhere in a Bash command — per-call override.
"""

from __future__ import annotations

import json
import os
import re
import sys
import time
from pathlib import Path

PLUGIN_ROOT = Path(__file__).resolve().parent.parent
CONFIG_PATH = PLUGIN_ROOT / "config" / "default-patterns.json"
USER_CONFIG_PATH = Path.home() / ".claude" / "envshield" / "patterns.json"
AUDIT_DIR = Path.home() / ".claude" / "envshield"
AUDIT_PATH = AUDIT_DIR / "audit.log"

FILE_TOOLS = {"Read", "Edit", "Write", "Glob", "Grep"}


def load_config() -> dict:
    """Load default patterns, then merge user overrides if present."""
    with CONFIG_PATH.open("r", encoding="utf-8") as f:
        cfg = json.load(f)
    if USER_CONFIG_PATH.is_file():
        try:
            with USER_CONFIG_PATH.open("r", encoding="utf-8") as f:
                user = json.load(f)
            for key in ("secret_file_patterns", "secret_file_allowlist", "dangerous_bash_patterns"):
                if isinstance(user.get(key), list):
                    cfg[key] = user[key] + cfg.get(key, [])
        except (OSError, json.JSONDecodeError):
            pass
    return cfg


def compile_rules(items: list[dict]) -> list[tuple[re.Pattern, str]]:
    out = []
    for item in items or []:
        try:
            out.append((re.compile(item["regex"], re.IGNORECASE), item.get("reason", "")))
        except re.error:
            continue
    return out


def compile_simple(items: list[dict]) -> list[re.Pattern]:
    out = []
    for item in items or []:
        try:
            out.append(re.compile(item["regex"], re.IGNORECASE))
        except (re.error, KeyError):
            continue
    return out


def first_match(rules: list[tuple[re.Pattern, str]], text: str):
    for pat, reason in rules:
        if pat.search(text):
            return pat.pattern, reason
    return None


def any_match(pats: list[re.Pattern], text: str) -> bool:
    return any(p.search(text) for p in pats)


def write_audit(record: dict) -> None:
    try:
        AUDIT_DIR.mkdir(parents=True, exist_ok=True)
        with AUDIT_PATH.open("a", encoding="utf-8") as f:
            f.write(json.dumps(record, ensure_ascii=False) + "\n")
    except OSError:
        pass


def deny(reason: str, audit: dict) -> None:
    """Print a deny decision to stdout and exit 0 (Claude handles the message)."""
    audit["decision"] = "deny"
    audit["reason"] = reason
    write_audit(audit)
    payload = {
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": "deny",
            "permissionDecisionReason": (
                f"[EnvShield] {reason}\n\n"
                "If you intend to access this on purpose, ask the user to "
                "confirm in plain text before retrying. To allow once for "
                "a Bash call, append `# envshield:allow` to the command. "
                "To disable EnvShield for the whole session, run with "
                "`ENVSHIELD_DISABLE=1`."
            ),
        }
    }
    sys.stdout.write(json.dumps(payload))
    sys.exit(0)


def main() -> None:
    if os.environ.get("ENVSHIELD_DISABLE") == "1":
        sys.exit(0)

    audit_only = os.environ.get("ENVSHIELD_AUDIT_ONLY") == "1"

    try:
        event = json.loads(sys.stdin.read() or "{}")
    except json.JSONDecodeError:
        sys.exit(0)

    tool_name = event.get("tool_name", "")
    tool_input = event.get("tool_input", {}) or {}
    if not tool_name:
        sys.exit(0)

    cfg = load_config()
    file_rules = compile_rules(cfg.get("secret_file_patterns", []))
    file_allow = compile_simple([{"regex": x["regex"]} for x in cfg.get("secret_file_allowlist", [])])
    bash_rules = compile_rules(cfg.get("dangerous_bash_patterns", []))

    base_audit = {
        "ts": time.strftime("%Y-%m-%dT%H:%M:%S%z", time.localtime()),
        "session_id": event.get("session_id"),
        "cwd": event.get("cwd"),
        "tool_name": tool_name,
    }

    # --- File-based tools -------------------------------------------------
    if tool_name in FILE_TOOLS:
        candidate_paths: list[str] = []
        for key in ("file_path", "path", "pattern"):
            val = tool_input.get(key)
            if isinstance(val, str):
                candidate_paths.append(val)

        for path in candidate_paths:
            if any_match(file_allow, path):
                continue
            match = first_match(file_rules, path)
            if match:
                _, reason = match
                base_audit["target"] = path
                if audit_only:
                    base_audit["decision"] = "audit_only"
                    base_audit["reason"] = reason
                    write_audit(base_audit)
                    sys.exit(0)
                deny(f"Blocked {tool_name} on {path!r} — {reason}.", base_audit)

    # --- Bash --------------------------------------------------------------
    if tool_name == "Bash":
        command = tool_input.get("command", "")
        if not isinstance(command, str) or not command:
            sys.exit(0)
        if "# envshield:allow" in command or "#envshield:allow" in command:
            sys.exit(0)

        match = first_match(bash_rules, command)
        if match:
            pattern, reason = match
            base_audit["target"] = command
            base_audit["matched_pattern"] = pattern
            if audit_only:
                base_audit["decision"] = "audit_only"
                base_audit["reason"] = reason
                write_audit(base_audit)
                sys.exit(0)
            deny(f"Blocked bash command — {reason}.", base_audit)

    sys.exit(0)


if __name__ == "__main__":
    main()
