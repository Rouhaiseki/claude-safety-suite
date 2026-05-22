#!/usr/bin/env python3
"""NoNuke PreToolUse hook.

Blocks Claude Code from running destructive commands (rm -rf, prisma migrate
reset, DROP TABLE, git push --force, kubectl delete, terraform destroy, …)
unless the call is explicitly approved.

Every block is appended as a JSON line to ~/.claude/nonuke/audit.log.

Approve a single call by appending ` # nonuke:approve` to the command.
Disable for a whole session with NONUKE_DISABLE=1.
"""

from __future__ import annotations

import json
import os
import re
import sys
import time
from pathlib import Path

PLUGIN_ROOT = Path(__file__).resolve().parent.parent
CONFIG_PATH = PLUGIN_ROOT / "config" / "destructive-patterns.json"
USER_CONFIG_PATH = Path.home() / ".claude" / "nonuke" / "patterns.json"
AUDIT_DIR = Path.home() / ".claude" / "nonuke"
AUDIT_PATH = AUDIT_DIR / "audit.log"


def load_config() -> dict:
    with CONFIG_PATH.open("r", encoding="utf-8") as f:
        cfg = json.load(f)
    if USER_CONFIG_PATH.is_file():
        try:
            with USER_CONFIG_PATH.open("r", encoding="utf-8") as f:
                user = json.load(f)
            if isinstance(user.get("patterns"), list):
                cfg["patterns"] = user["patterns"] + cfg.get("patterns", [])
        except (OSError, json.JSONDecodeError):
            pass
    return cfg


def compile_patterns(items: list[dict]):
    out = []
    for item in items or []:
        try:
            out.append(
                (
                    re.compile(item["regex"]),
                    item.get("reason", ""),
                    item.get("severity", "medium"),
                )
            )
        except (re.error, KeyError):
            continue
    return out


def first_match(rules, text: str):
    for pat, reason, severity in rules:
        if pat.search(text):
            return pat.pattern, reason, severity
    return None


def write_audit(record: dict) -> None:
    try:
        AUDIT_DIR.mkdir(parents=True, exist_ok=True)
        with AUDIT_PATH.open("a", encoding="utf-8") as f:
            f.write(json.dumps(record, ensure_ascii=False) + "\n")
    except OSError:
        pass


def main() -> None:
    if os.environ.get("NONUKE_DISABLE") == "1":
        sys.exit(0)

    audit_only = os.environ.get("NONUKE_AUDIT_ONLY") == "1"

    try:
        event = json.loads(sys.stdin.read() or "{}")
    except json.JSONDecodeError:
        sys.exit(0)

    if event.get("tool_name") != "Bash":
        sys.exit(0)

    tool_input = event.get("tool_input", {}) or {}
    command = tool_input.get("command", "")
    if not isinstance(command, str) or not command:
        sys.exit(0)

    # Per-call escape hatch.
    if "# nonuke:approve" in command or "#nonuke:approve" in command:
        sys.exit(0)

    cfg = load_config()
    rules = compile_patterns(cfg.get("patterns", []))
    match = first_match(rules, command)
    if not match:
        sys.exit(0)

    pattern, reason, severity = match
    audit = {
        "ts": time.strftime("%Y-%m-%dT%H:%M:%S%z", time.localtime()),
        "session_id": event.get("session_id"),
        "cwd": event.get("cwd"),
        "command": command,
        "matched_pattern": pattern,
        "reason": reason,
        "severity": severity,
    }

    if audit_only:
        audit["decision"] = "audit_only"
        write_audit(audit)
        sys.exit(0)

    audit["decision"] = "deny"
    write_audit(audit)

    payload = {
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": "deny",
            "permissionDecisionReason": (
                f"[NoNuke] Refusing destructive command — {reason}.\n\n"
                "Ask the user to confirm in plain text before retrying. "
                "If the user explicitly approves, append ` # nonuke:approve` "
                "to the command (a comment shell will ignore). "
                "To disable NoNuke for the whole session, run with "
                "`NONUKE_DISABLE=1`."
            ),
        }
    }
    sys.stdout.write(json.dumps(payload))
    sys.exit(0)


if __name__ == "__main__":
    main()
