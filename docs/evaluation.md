# Evaluation log

Task: `tasks/cow-btree-recover`  
Harbor: 0.23.0  
GitHub: https://github.com/sandeep1995/tb3-cow-btree-recover  
TB3 CI snapshot: `vendor/tb3/harbor-run-defaults.yml` (3 trials; `claude-code` + `anthropic/claude-opus-5` `reasoning_effort=max` + `CLAUDE_CODE_MAX_OUTPUT_TOKENS=128000`; `codex` + `openai/gpt-5.6-sol` `reasoning_effort=xhigh`; `/run` and `/cheat` default `env: modal`). Local validation uses `--env docker`.

## Why the first revision was too easy

Codex `openai/gpt-5.6-sol` `reasoning_effort=xhigh` passed two genuine `/run` trials on the CBT1 revision (reward 1.0, 8/8 hidden tests). The agent rewrote `/app/store/recover.py` from `FORMAT.md`, which listed dual-superblock selection, child walks, checksum rules, duplicate LSN, and torn-write fallback as a compact implementable spec. Remaining CBT1 `/run` and `/cheat` trials were stopped after the second pass. Agent sources: `docs/results/run-codex-1/agent-store/`, `docs/results/run-codex-2/agent-store/`.

The task was then hardened to CBT2: prefix-compressed leaves, overflow chains, freelist page reuse, unlinked extra leaves, and interacting torn writes. `FORMAT.md` documents layout and commit invariants without a short recovery cookbook. The public stub still follows sibling links and ignores overflow assembly.

## Static checks — PASS (hardened)

```bash
./scripts/run-static-checks.sh tasks/cow-btree-recover
```

All 22 TB3 `scripts/checks/check-*.sh` scripts passed (Python 3.13+; the macOS CLT `python3` 3.9 lacks `tomllib`).

## Implementation rubric — not run (Claude OAuth)

```bash
harbor check tasks/cow-btree-recover -r vendor/tb3/task-implementation.toml -m anthropic/claude-opus-4-8
```

Claude Code reports logged in, but `claude -p` fails with `OAuth session expired and could not be refreshed`. A desktop `claude auth login --claudeai` prompt was left waiting; it was not restarted. No Console API billing.

## Docker build / oracle / nop — PASS (hardened)

```bash
harbor run -p tasks/cow-btree-recover --agent oracle --env docker --yes -k 1 -n 1 -o jobs/oracle
harbor run -p tasks/cow-btree-recover --agent nop --env docker --yes -k 1 -n 1 -o jobs/nop
```

| Run | Job | Reward |
| --- | --- | --- |
| oracle | `jobs/oracle/2026-09-17__00-26-39` | 1.0 |
| nop | `jobs/nop/2026-09-17__00-27-21` | 0.0 |

## Deterministic cheat oracle — PASS (reward 0)

Replaced `solution/solve.sh` with `cheat/solve.sh` (`return {}`) for one oracle run, then restored the real solution:

```bash
harbor run -p tasks/cow-btree-recover --agent oracle --env docker --yes -k 1 -n 1 -o jobs/cheat-oracle
```

Reward 0.0 (`jobs/cheat-oracle/2026-09-17__00-27-38`).

## Standard trials (`/run`)

```bash
harbor run -p tasks/cow-btree-recover --agent codex --model openai/gpt-5.6-sol \
  --env docker --yes --ae CODEX_FORCE_AUTH_JSON=1 --ak reasoning_effort=xhigh \
  -k 3 -n 1 -o jobs/run-codex

harbor run -p tasks/cow-btree-recover --agent claude-code --model anthropic/claude-opus-5 \
  --env docker --yes --ae CLAUDE_FORCE_OAUTH=1 --ae CLAUDE_CODE_OAUTH_TOKEN="$CLAUDE_CODE_OAUTH_TOKEN" \
  --ae CLAUDE_CODE_MAX_OUTPUT_TOKENS=128000 --ak reasoning_effort=max \
  -k 3 -n 1 -o jobs/run-claude
```

| Config | Trial | Reward | Notes |
| --- | --- | --- | --- |
| Codex CBT1 | 1 `jobs/run-codex-1/2026-09-16__23-53-56` | 1.0 | Genuine pass; 8/8; task too easy |
| Codex CBT1 | 2 `jobs/run-codex-2/2026-09-17__00-02-36` | 1.0 | Genuine pass; stopped further CBT1 trials |
| Codex CBT2 | 1–3 | pending | Hardened task |
| Claude CBT2 | 1–3 | blocked | OAuth refresh expired |

## Adversarial trials (`/cheat`)

```bash
harbor run -p tasks/cow-btree-recover --agent codex --model openai/gpt-5.6-sol \
  --env docker --yes --ae CODEX_FORCE_AUTH_JSON=1 --ak reasoning_effort=xhigh \
  --extra-instruction-path vendor/tb3/hack-trial-prompt.md -k 1 -n 1 -o jobs/cheat-codex

harbor run -p tasks/cow-btree-recover --agent claude-code --model anthropic/claude-opus-5 \
  --env docker --yes --ae CLAUDE_FORCE_OAUTH=1 --ae CLAUDE_CODE_OAUTH_TOKEN="$CLAUDE_CODE_OAUTH_TOKEN" \
  --ae CLAUDE_CODE_MAX_OUTPUT_TOKENS=128000 --ak reasoning_effort=max \
  --extra-instruction-path vendor/tb3/hack-trial-prompt.md -k 1 -n 1 -o jobs/cheat-claude
```

| Config | Reward | Notes |
| --- | --- | --- |
| Deterministic empty recover | 0.0 | Verifier not fooled by `return {}` |
| Codex CBT2 `/cheat` | pending | |
| Claude CBT2 `/cheat` | blocked | Same OAuth expiry |

## Failure analysis

Nop and empty-recover fail because recovery must select a checksum-valid superblock by LSN, walk interior children (not stale `right_sibling`), reconstitute prefix-compressed keys, assemble overflow chains, reject a torn newer root or torn overflow, ignore unlinked extra leaves, and keep the higher-LSN value on duplicate keys. Hidden images in `/tests/images/` are not in the agent container. Protected `format.py` / `FORMAT.md` are restored from the verifier image. Reward is written only by root into `chmod 700 /logs/verifier`. Hardcoding `/app/data/crashed.db` cannot pass the baked hidden set.

The CBT1 pass shows a frontier agent can transcribe a complete recovery recipe from a 60-line FORMAT.md. CBT2 keeps the instruction fair for an expert who can read the writer and the layout, but the hidden tests require composing overflow, prefix, reuse, and tear interactions rather than copying a short procedure.
