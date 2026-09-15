# cow-btree-recover

Independent Terminal-Bench 3 task for a Founding Engineer hiring evaluation. **Klavis AI is not affiliated with Terminal-Bench.** There is no IP transfer. Keep this repository under your control (GitHub or otherwise). This repo does **not** open a PR against `harbor-framework/terminal-bench`.

Task: `tasks/cow-btree-recover` — repair crash recovery for an original copy-on-write B+tree (dual superblocks, page checksums, stale sibling pointers, interrupted-split duplicates).

## Layout

```
tasks/cow-btree-recover/   TB3 task (instruction, environment, tests, oracle)
scripts/checks/            Current TB3 static check scripts (vendored)
vendor/tb3/                CI defaults, implementation rubric, /cheat prompt
docs/                      Commands, check results, trial results
```

Canonical upstream docs used while authoring:

- https://www.tbench.ai/news/tb3-contribution-call
- https://github.com/harbor-framework/terminal-bench (CONTRIBUTING.md, docs/TASK_REVIEW_AUTOMATION.md, docs/REVIEWING.md)
- https://github.com/harbor-framework/harbor
- CI defaults: `vendor/tb3/harbor-run-defaults.yml` (copied from TB3 `.github/harbor-run-defaults.yml`)

## Prerequisites

```bash
uv tool install harbor
# Docker Engine must be running
docker ps
```

Harbor 0.23+ and the TB3 task format (`schema_version = "2.0"`, separate verifier, `artifacts` at top level) are required.

## Static checks (required)

From the repo root:

```bash
chmod +x scripts/run-static-checks.sh scripts/checks/*.sh
./scripts/run-static-checks.sh tasks/cow-btree-recover
```

These are the current TB3 `scripts/checks/check-*.sh` suite: canary, Dockerfiles, separate verifier, pip pins, pytest versions, instruction suffix, taxonomy, package name, and the rest. Results: [docs/evaluation.md](docs/evaluation.md).

## Implementation rubric (required)

TB3 CI runs `harbor check` against the implementation rubric. Local equivalent:

```bash
harbor check tasks/cow-btree-recover -r vendor/tb3/task-implementation.toml -m anthropic/claude-opus-4-8
```

This needs an Anthropic API key (or Claude Code subscription auth). If that is missing, the mechanical static checks still run; the LLM rubric review does not.

## Docker build, oracle, nop (required)

```bash
harbor run -p tasks/cow-btree-recover --agent oracle --env docker --yes -n 1 -o jobs/oracle
harbor run -p tasks/cow-btree-recover --agent nop --env docker --yes -n 1 -o jobs/nop
```

Oracle must get reward `1.0`. Nop must get reward `0.0`.

Deterministic cheat oracle (not a model trial; verifier must still score 0):

```bash
# After a nop/oracle environment exists you can also inspect cheat/solve.sh.
# It replaces recover_store with `return {}` and must fail hidden-image tests.
```

## Standard agent trials (`/run`)

TB3 `.github/harbor-run-defaults.yml` uses **3 trials** and:

| Agent | Model | kwargs | extra env |
| --- | --- | --- | --- |
| `claude-code` | `anthropic/claude-opus-5` | `reasoning_effort=max` | `CLAUDE_CODE_MAX_OUTPUT_TOKENS=128000` |
| `codex` | `openai/gpt-5.6-sol` | `reasoning_effort=xhigh` | `CODEX_FORCE_AUTH_JSON=1` (when using subscription auth) |

CI `/run` uses `env: modal`. Local reproduction uses `--env docker`.

```bash
# Codex (subscription auth if present)
harbor run -p tasks/cow-btree-recover --agent codex --model openai/gpt-5.6-sol \
  --env docker --yes --ae CODEX_FORCE_AUTH_JSON=1 --ak reasoning_effort=xhigh \
  -k 3 -n 1 -o jobs/run-codex

# Claude Code (after `claude setup-token`)
harbor run -p tasks/cow-btree-recover --agent claude-code --model anthropic/claude-opus-5 \
  --env docker --yes --ae CLAUDE_FORCE_OAUTH=1 --ae CLAUDE_CODE_OAUTH_TOKEN="$CLAUDE_CODE_OAUTH_TOKEN" \
  --ae CLAUDE_CODE_MAX_OUTPUT_TOKENS=128000 --ak reasoning_effort=max \
  -k 3 -n 1 -o jobs/run-claude
```

Requirement: all three genuine model failures per configuration (not crashes, rate limits, or timeouts).

## Adversarial trials (`/cheat`)

TB3 prepends `vendor/tb3/hack-trial-prompt.md` to the instruction. One trial per agent. Every trial must receive reward `0`.

```bash
harbor run -p tasks/cow-btree-recover --agent codex --model openai/gpt-5.6-sol \
  --env docker --yes --ae CODEX_FORCE_AUTH_JSON=1 --ak reasoning_effort=xhigh \
  --extra-instruction-path vendor/tb3/hack-trial-prompt.md \
  -k 1 -n 1 -o jobs/cheat-codex

harbor run -p tasks/cow-btree-recover --agent claude-code --model anthropic/claude-opus-5 \
  --env docker --yes --ae CLAUDE_FORCE_OAUTH=1 --ae CLAUDE_CODE_OAUTH_TOKEN="$CLAUDE_CODE_OAUTH_TOKEN" \
  --ae CLAUDE_CODE_MAX_OUTPUT_TOKENS=128000 --ak reasoning_effort=max \
  --extra-instruction-path vendor/tb3/hack-trial-prompt.md \
  -k 1 -n 1 -o jobs/cheat-claude
```

## Pushing to GitHub

This environment's git remote is an Origin/Cursor remote, not GitHub. To publish under your GitHub account:

```bash
git remote add github git@github.com:<you>/<repo>.git
git push -u github cursor/cow-btree-recover-bc11
```

If SSH/HTTPS GitHub auth is missing, create an empty GitHub repo and push from a machine where `gh auth` or SSH keys work. Do not open a PR to `harbor-framework/terminal-bench` unless you independently choose to contribute.

## What the task asks

The agent must make `recover_store(path)` reconstruct the committed map of a CoW B+tree after crash. The format is specified in `/app/store/FORMAT.md`. Tests import the agent's function in a separate verifier container and compare it to a baked spec recoverer on hidden images the agent never sees.
