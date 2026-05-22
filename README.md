# Claude Safety Suite

[![Tests](https://github.com/Rouhaiseki/claude-safety-suite/actions/workflows/test.yml/badge.svg)](https://github.com/Rouhaiseki/claude-safety-suite/actions/workflows/test.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Plugin: Claude Code](https://img.shields.io/badge/Claude%20Code-plugin-orange)](https://code.claude.com)

> 📝 **Featured on dev.to:** [I built two Claude Code hooks to stop it from leaking my .env files and wiping my dev DB](https://dev.to/rouhaiseki/i-built-two-claude-code-hooks-to-stop-it-from-leaking-my-env-files-and-wiping-my-dev-db-3a29)

Two PreToolUse guardrails for [Claude Code](https://code.claude.com):

- **EnvShield** — blocks reads of `.env`, SSH keys, AWS credentials, `.npmrc`, and ~15 other secret files. Also blocks bash workarounds (`printenv`, `docker compose config`, `cat .env`, …) that would dump secrets via stdout.
- **NoNuke** — blocks ~60 destructive command patterns (`rm -rf`, `prisma migrate reset`, `DROP TABLE`, `git push --force`, `terraform destroy`, `kubectl delete`, …) unless explicitly approved.

Both plugins write a structured JSON audit log of every block to `~/.claude/<plugin>/audit.log`.

Built because Claude Code can — and routinely does — read `.env` files and wipe dev databases despite memory rules telling it not to. See the open GitHub issues: [#25053](https://github.com/anthropics/claude-code/issues/25053), [#58173](https://github.com/anthropics/claude-code/issues/58173), [#34729](https://github.com/anthropics/claude-code/issues/34729).

## Install

```bash
# Add this marketplace
claude plugin marketplace add Rouhaiseki/claude-safety-suite

# Install one or both plugins
claude plugin install envshield@claude-safety-suite
claude plugin install nonuke@claude-safety-suite
```

Or test locally without installing:

```bash
git clone https://github.com/Rouhaiseki/claude-safety-suite.git
claude --plugin-dir ./claude-safety-suite/envshield --plugin-dir ./claude-safety-suite/nonuke
```

## Examples

Real input → output shown below. The "message Claude sees" is the literal
text returned to Claude — Claude reads this and (correctly) asks you for
confirmation before retrying.

### EnvShield in action

**❶ Claude tries to read `.env`**

```
Tool:   Read { file_path: "/Users/me/app/.env" }
Result: ⛔ BLOCKED

Message Claude sees:
  [EnvShield] Blocked Read on '/Users/me/app/.env' — .env file (likely contains secrets).
  If you intend to access this on purpose, ask the user to confirm in plain
  text before retrying. To allow once for a Bash call, append `# envshield:allow`
  to the command. To disable EnvShield for the whole session, run with
  `ENVSHIELD_DISABLE=1`.
```

**❷ Claude tries to dump env vars via bash**

```
Tool:   Bash { command: "cat .env | grep STRIPE" }
Result: ⛔ BLOCKED — reads a .env file.

Tool:   Bash { command: "docker compose config" }
Result: ⛔ BLOCKED — `docker compose config` resolves all .env values into stdout.

Tool:   Bash { command: "printenv" }
Result: ⛔ BLOCKED — `printenv` dumps every env var (including secrets).
```

**❸ Templates and overrides are allowed**

```
Tool:   Read { file_path: "/Users/me/app/.env.example" }
Result: ✅ ALLOWED — .env.example is on the template allowlist.

Tool:   Bash { command: "cat .env # envshield:allow" }
Result: ✅ ALLOWED — per-call user override.
```

**❹ Audit log line**

```jsonl
{"ts":"2026-05-22T19:28:18+0800","session_id":"abc123","cwd":"/Users/me/app","tool_name":"Bash","target":"docker compose config","matched_pattern":"docker(-|\\s)compose\\s+config","decision":"deny","reason":"Blocked bash command — `docker compose config` resolves all .env values into stdout."}
```

### NoNuke in action

**❶ Reproduces issue #34729 (the Prisma data-loss incident)**

```
Tool:   Bash { command: "npx prisma migrate reset --force" }
Result: ⛔ BLOCKED

Message Claude sees:
  [NoNuke] Refusing destructive command — prisma migrate reset (drops dev DB).
  Ask the user to confirm in plain text before retrying. If the user explicitly
  approves, append ` # nonuke:approve` to the command (a comment shell will
  ignore). To disable NoNuke for the whole session, run with `NONUKE_DISABLE=1`.
```

**❷ Catches the obvious foot-guns**

```
Tool:   Bash { command: "rm -rf node_modules/../old-app" }
Result: ⛔ BLOCKED — rm -rf / rm -fr (recursive force delete).

Tool:   Bash { command: "git push origin main --force" }
Result: ⛔ BLOCKED — git push --force (overwrites remote history; --force-with-lease is safer).

Tool:   Bash { command: "terraform destroy --auto-approve" }
Result: ⛔ BLOCKED — terraform destroy.

Tool:   Bash { command: "kubectl delete namespace prod" }
Result: ⛔ BLOCKED — kubectl delete on namespace/pvc/pv/crd/all.
```

**❸ Knows when to step aside**

```
Tool:   Bash { command: "git push origin feature --force-with-lease" }
Result: ✅ ALLOWED — lease-based force push is safer; not blocked.

Tool:   Bash { command: "ls -la" }
Result: ✅ ALLOWED — not destructive.

Tool:   Bash { command: "rm -rf /tmp/scratch # nonuke:approve" }
Result: ✅ ALLOWED — per-call user override.
```

**❹ Audit log line**

```jsonl
{"ts":"2026-05-22T19:28:19+0800","session_id":"abc123","cwd":"/Users/me/app","command":"npx prisma migrate reset --force","matched_pattern":"(^|[\\s;|&])prisma\\s+migrate\\s+reset","reason":"prisma migrate reset (drops dev DB)","severity":"high","decision":"deny"}
```

### What this means in practice

When EnvShield/NoNuke blocks a tool call, Claude doesn't crash or silently fail.
It reads the deny reason as a normal tool-result message and almost always does
the right thing: it stops, summarizes what it was about to do, and asks you to
confirm in plain English. You can approve in two ways — by appending the
per-call override comment, or by replying in plain text ("yes, go ahead with
the migration reset on the dev database").

---

## EnvShield — quick reference

**What it blocks**

- Reads (`Read`/`Edit`/`Write`/`Glob`/`Grep`) on `.env`, `.envrc`, `id_rsa*`, `*.pem`, `*.p12`, `.aws/credentials`, `.netrc`, `.npmrc`, `.pypirc`, `.git-credentials`, `.docker/config.json`, `.kube/config`, `credentials.json`, `service-account*.json`, `secrets.{json,yaml,yml,toml}`, `wallet.{dat,json}`, `*.kdbx`.
- Bash commands that exfiltrate env vars to stdout: `printenv`, `env` (alone), `set` (alone), `docker compose config`, `docker-compose config`, `cat`/`less`/`more`/`head`/`tail`/`bat`/`grep`/`rg` on `.env`/`.pem`/`id_rsa`/`.aws/credentials`/`.netrc`/`.npmrc`, `echo $*_TOKEN`/`*_KEY`/`*_SECRET`/`*_PASSWORD`, `git config --get credential`.

**What it doesn't block**

- `.env.example`, `.env.sample`, `.env.template`, `.env.dist`, `.env.test` (templates, allowlisted).
- Reads of regular code or config files.

**Escape hatches**

| How | Scope |
| --- | --- |
| Append `# envshield:allow` to a bash command | One call |
| `ENVSHIELD_AUDIT_ONLY=1` | One session — logs but never denies |
| `ENVSHIELD_DISABLE=1` | One session — fully off |

**Custom patterns**

Drop a JSON file at `~/.claude/envshield/patterns.json` with the same shape as `envshield/config/default-patterns.json`. User patterns are merged into the defaults.

## NoNuke — quick reference

**What it blocks**

- Filesystem: `rm -rf`, `sudo rm`, `rm … /`, `find … -delete`, `find … -exec rm`, `dd of=/dev/`, `mkfs.*`, `fdisk`, `parted`, `chmod 777 /`, `chown -R … /`, `> /dev/sdX`.
- Git: `push --force` (but **not** `--force-with-lease`), `reset --hard`, `clean -fd`, `checkout .`, `restore .`, `branch -D`, `stash drop`/`clear`, `tag -d`, `filter-branch`, `update-ref -d`.
- SQL: `DROP TABLE/DATABASE/SCHEMA/INDEX/VIEW`, `TRUNCATE TABLE`, `DELETE FROM` without `WHERE`.
- Migration tools: `prisma migrate reset`, `prisma db push --accept-data-loss`, `rails db:reset/drop`, `sequelize/knex db:drop`, `alembic downgrade base`, `dropdb`, `mongosh db.drop()`.
- Docker / k8s: `docker system prune -a`, `docker volume prune/rm`, `docker compose down -v`, `docker rm -f`, `kubectl delete namespace/ns/pvc/pv/crd/all`, `kubectl drain`, `helm uninstall`.
- Cloud: `terraform destroy`, `terraform apply --auto-approve`, `pulumi destroy`, `aws s3 rm --recursive`, `aws s3 rb --force`, `aws rds delete-db-instance`, `gcloud sql instances delete`, `az sql delete`.
- System: `shutdown`, `reboot`, `kill -9 -1`, `killall`, fork bombs.

**Escape hatches**

| How | Scope |
| --- | --- |
| Append `# nonuke:approve` to a command | One call |
| `NONUKE_AUDIT_ONLY=1` | One session — logs but never denies |
| `NONUKE_DISABLE=1` | One session — fully off |

**Custom patterns**

Drop a JSON file at `~/.claude/nonuke/patterns.json` with the same shape as `nonuke/config/destructive-patterns.json`. User patterns are merged into the defaults.

## Audit logs

Both plugins append one JSON line per block to:

- `~/.claude/envshield/audit.log`
- `~/.claude/nonuke/audit.log`

Each line includes timestamp, session_id, cwd, tool_name, the matched pattern, and the reason. Tail it in real time:

```bash
tail -F ~/.claude/envshield/audit.log ~/.claude/nonuke/audit.log
```

## License

MIT
