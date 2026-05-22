# Claude Safety Suite

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
