# Security Policy

Claude Safety Suite is itself a security tool, so it has a higher bar than
most plugins to take reports seriously.

## Supported versions

Only the latest tagged release receives security fixes. Older versions are
not maintained.

| Version | Supported |
| ------- | --------- |
| `0.1.x` | ✅        |

## Reporting a vulnerability

Please **do not** open a public GitHub issue for a security report. Instead:

1. Open a private [Security Advisory](https://github.com/Rouhaiseki/claude-safety-suite/security/advisories/new)
   on the repository, or
2. Email the maintainer (contact link in the repo profile).

I aim to acknowledge reports within 72 hours and ship a patched release
within 7 days for confirmed high-severity issues.

## What counts as a vulnerability

In scope:

- **Bypass of EnvShield or NoNuke.** A bash command or tool input that should
  be blocked under the default config but is not. Please include the exact
  command/path and the version you tested.
- **False-positive that blocks legitimate work** (e.g., a common safe command
  that gets caught). These aren't "security" issues strictly, but they erode
  trust in the tool; report them via normal issues.
- **Audit-log integrity issues** — log corruption, missing entries, races
  that drop entries.
- **Hook process safety issues** — a way to crash the hook (forcing fail-open)
  via a crafted input.

Out of scope:

- The fact that `ENVSHIELD_DISABLE=1` / `NONUKE_DISABLE=1` exists. Documented
  escape hatches for explicit, intentional override are not a vulnerability.
- The fact that a user with explicit override (`# envshield:allow` /
  `# nonuke:approve`) can bypass the block. Same reason.
- Configuration mistakes (custom patterns that allow too much).
- Bypasses requiring shell-level access the user already has — these plugins
  are not a sandbox; they constrain Claude, not the user.

## Threat model in one sentence

Claude Safety Suite assumes Claude Code is a trusted-but-fallible agent that
will sometimes attempt to read secrets or run destructive commands by
mistake, prompt injection, or model error. Its job is to interrupt the
attempt and surface a clear deny reason so a human can decide. It does **not**
protect against a malicious user, a malicious shell, or a malicious system.

## Fail-open behavior

If the hook itself crashes (Python error, JSON decode failure, etc.), the
tool call is allowed to proceed. This is intentional: a crashed hook should
not freeze the user's session. The trade-off is that a determined attacker
who can crash the hook can also bypass it. We log every crash where possible
and accept this as the right default for a developer tool.
