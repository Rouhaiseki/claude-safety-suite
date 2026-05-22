# Changelog

All notable changes to Claude Safety Suite. Format roughly follows
[Keep a Changelog](https://keepachangelog.com/). Versions follow [SemVer](https://semver.org/).

## [0.1.2] – 2026-05-22

### Fixed
- **MultiEdit / NotebookEdit weren't covered.** EnvShield's hook matcher and
  `FILE_TOOLS` set now include both. Previously a `MultiEdit` call on a `.env`
  file would slip past unchecked.
- **Glob `**/.env*` was not blocked.** Secret-file regex now also matches when
  the path contains a glob wildcard (`*`, `?`, `[`) immediately before or after
  `.env`. So `**/.env*`, `**/.env?`, `*.env`, `**/*.env` all block; innocent
  globs like `src/**/*.ts` and ordinary file `foo.env` are unaffected.
- **Audit logs were world-readable.** Both plugins now `chmod 0600` the audit
  log on first write so it can't be read by other local users.
- **`docker compose -f override.yml down -v` was not blocked.** The NoNuke
  regex required `compose` to be immediately followed by `down`; now it
  tolerates `-f`/`--file`/`-p`/`--project-name` and other flags interleaved.
- **`secret_env_var_patterns` was dead config** loaded but never used. Removed
  to reduce surface area and confusion; the targeted `printenv VAR_TOKEN`
  pattern in `dangerous_bash_patterns` covers the use case.
- Removed a duplicate `(^|/)\.env$` regex that was already subsumed by the
  primary `(^|/)\.env(\.|$)` entry.

### Added
- **NoNuke** now blocks a broader set of cloud destruction commands:
  - AWS: `cloudformation delete-stack`, `lambda delete-function`,
    `iam delete-{role,user,policy,group,access-key}`, `ecs delete-{cluster,service}`,
    `dynamodb delete-table`, `ec2 terminate-instances`.
  - GCP: `projects delete`, `compute instances delete`,
    `functions/run/container clusters delete`.
  - Azure: `group delete`, `vm delete`, `functionapp delete`.
- **NoNuke** also catches `docker rmi -f`, `podman rmi -f`, and
  `docker image prune -a`.
- Test suite grew from 93 → 123 cases (regression + new bypass coverage).

### Documentation
- Added this CHANGELOG.
- Added `SECURITY.md` with a disclosure policy (security plugin should have one).

## [0.1.1] – 2026-05-22

### Added
- 30+ new EnvShield patterns closing subshell, language-eval, cloud-secret-CLI,
  and exfiltration bypasses.
- 10+ new NoNuke patterns: UPDATE-without-WHERE, rm with subshell args,
  xargs rm -rf, git push :branch, git remote remove, podman variants.
- `tests/test_patterns.py` permanent regression suite (93 cases).

### Fixed
- `printenv VAR` (e.g. `printenv PATH`) was over-blocking; now only no-args or
  shell-connector forms (`printenv | tee`) match.
- `python -c "..."` patterns no longer require `.env` to be inside the first
  quoted span (real commands use nested quotes).
- SQL DELETE/UPDATE WHERE detection rewritten using a tempered greedy token;
  previous lookahead was incorrect and could either over- or under-block.

## [0.1.0] – 2026-05-22

Initial release. EnvShield (18 secret-file patterns, 12 bash patterns) and
NoNuke (~50 destructive-command patterns). Audit log to
`~/.claude/<plugin>/audit.log`. Per-call override comments and session-level
disable / audit-only env vars.
