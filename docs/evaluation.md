# Evaluation log

Task: `tasks/cow-btree-recover`  
Harbor: 0.23.0  
GitHub: https://github.com/sandeep1995/tb3-cow-btree-recover  
TB3 CI snapshot: `vendor/tb3/harbor-run-defaults.yml` (3 trials; `claude-code` + `anthropic/claude-opus-5` `reasoning_effort=max` + `CLAUDE_CODE_MAX_OUTPUT_TOKENS=128000`; `codex` + `openai/gpt-5.6-sol` `reasoning_effort=xhigh`; `/run` and `/cheat` default `env: modal`). Local validation uses `--env docker`.

## Why the first revision was too easy

Codex `openai/gpt-5.6-sol` `reasoning_effort=xhigh` passed two genuine `/run` trials on the CBT1 revision (reward 1.0, 8/8 hidden tests). The agent rewrote `/app/store/recover.py` from `FORMAT.md`, which listed dual-superblock selection, child walks, checksum rules, duplicate LSN, and torn-write fallback as a compact implementable spec. Remaining CBT1 `/run` and `/cheat` trials were stopped after the second pass. Agent sources: `docs/results/run-codex-1/agent-store/`, `docs/results/run-codex-2/agent-store/`.

The task was then hardened to CBT2: prefix-compressed leaves, overflow chains, freelist page reuse, unlinked extra leaves, and interacting torn writes. Codex still passed two genuine `/run` trials (reward 1.0). Remaining CBT2 `/run` trial 3 was an infra `apt-get` kill, not a model failure.

The task was hardened again to CBT3: delta-coded subsequent leaf keys (`FLAG_DELTA`), overflow LSN at most the owning leaf LSN, shared overflow DAGs, and kind-1 values that must be longer than the inline cap. Hidden tests grew from 14 to 17. Codex `/run` trial 1 passed 17/17; trial 2 was aborted.

The task was hardened again to CBT4: overflow `child0` is a consecutive chunk index, and the superblock stores `root_lsn` that must match the root page. Hidden tests grew from 17 to 19. Codex `/run` trial 1 passed 19/19; trial 2 was aborted.

The task was hardened again to CBT5: leaf kind `2` tombstones persist after delete. Hidden tests grew from 19 to 21. Codex `/run` trial 1 passed 21/21; the suite stopped.

The task was hardened again to CBT6: `/app/store/codec.py` is encode-only. Agents must parse `FORMAT.md` themselves. The oracle decoder lives under `/solution` only.

CBT1–CBT6 all failed that strategy. The task was rebuilt around a multi-package engine: pager, freelist, WAL intent log (BEGIN / PAGES / COMMIT), path-copying B+tree, and a shipped recoverer that looks almost right. FORMAT.md is layout only. Hidden images come from crashing the real writer. The agent patches `/app/store/recovery/` rather than transcribing a checklist.

## Static checks — PASS (engine rewrite)

```bash
./scripts/run-static-checks.sh tasks/cow-btree-recover
```

All 22 TB3 `scripts/checks/check-*.sh` scripts passed (Python 3.13+; the macOS CLT `python3` 3.9 lacks `tomllib`).

## Implementation rubric — not run (Codex first)

Claude `/run`, `/cheat`, and `harbor check` wait until Codex `/run` is 3/3 fail and Codex `/cheat` is 0.

## Docker build / oracle / nop — PASS (CBT3)

```bash
harbor run -p tasks/cow-btree-recover --agent oracle --env docker --yes -k 1 -n 1 -o jobs/h3-oracle
harbor run -p tasks/cow-btree-recover --agent nop --env docker --yes -k 1 -n 1 -o jobs/h3-nop
```

| Run | Job | Reward |
| --- | --- | --- |
| oracle CBT2 | `jobs/oracle/2026-09-17__00-26-39` | 1.0 |
| nop CBT2 | `jobs/nop/2026-09-17__00-27-21` | 0.0 |
| oracle CBT3 | `jobs/h3-oracle/2026-09-17__01-09-55` | 1.0 |
| nop CBT3 | `jobs/h3-nop/2026-09-17__01-10-41` | 0.0 |
| oracle CBT4 | `jobs/h4-oracle/2026-09-17__01-33-20` | 1.0 (19/19) |
| nop CBT4 | `jobs/h4-nop/2026-09-17__01-34-01` | 0.0 |
| oracle CBT5 | `jobs/h5-oracle/2026-09-17__01-53-12` | 1.0 (21/21) |
| nop CBT5 | `jobs/h5-nop/2026-09-17__01-53-26` | 0.0 |
| oracle CBT6 | `jobs/h6-oracle/2026-09-17__02-12-30` | 1.0 (21/21) |
| nop CBT6 | `jobs/h6-nop/2026-09-17__02-12-44` | 0.0 |
| oracle engine | `jobs/e7-oracle/2026-09-17__03-01-07` | 1.0 (16/16) |
| nop engine | `jobs/e7-nop/2026-09-17__03-02-02` | 0.0 |

## Deterministic cheat oracle — PASS (reward 0)

Replaced `solution/solve.sh` with `cheat/solve.sh` (`return {}`) for one oracle run, then restored the real solution:

```bash
harbor run -p tasks/cow-btree-recover --agent oracle --env docker --yes -k 1 -n 1 -o jobs/h3-cheat-oracle
```

Reward 0.0 (`jobs/h3-cheat-oracle/2026-09-17__01-11-08`). CBT4 repeat: `jobs/h4-cheat-oracle/2026-09-17__01-34-21` also 0.0.

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
| Codex CBT2 | 1 `jobs/h-run-codex-1/2026-09-17__00-30-58` | 1.0 | Genuine pass; 14/14 |
| Codex CBT2 | 2 `jobs/h-run-codex-2/2026-09-17__00-42-38` | 1.0 | Genuine pass |
| Codex CBT3 | 1 `jobs/c3-run-codex-1/2026-09-17__01-14-45` | 1.0 | Genuine pass; 17/17; trial 2 aborted |
| Codex CBT4 | 1 `jobs/c4-run-codex-1/2026-09-17__01-36-42` | 1.0 | Genuine pass; 19/19; trial 2 aborted |
| Codex CBT5 | 1 `jobs/c5-run-codex-1/2026-09-17__01-54-55` | 1.0 | Genuine pass; 21/21; suite stopped |
| Codex CBT6 | 1 `jobs/c6-run-codex-1/2026-09-17__02-14-31` | 1.0 | Genuine pass; 21/21; wrote its own decoder; suite stopped |
| Claude | 1–3 | not started | Codex first |

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
| Deterministic empty recover CBT6 | 0.0 | `jobs/h6-cheat-oracle/2026-09-17__02-13-14` |
| Deterministic empty recover engine | 0.0 | `jobs/e7-cheat-oracle/2026-09-17__03-02-20` |
| Codex engine `/run` | pending | first probe after engine rewrite |
| Codex CBT6 `/cheat` | not started | `/run` still passing on CBT6 |
| Claude `/cheat` | not started | Codex first |

## Failure analysis

Nop and empty-recover fail because recovery must honor the writer's WAL commit protocol, ignore uncommitted pages, walk children rather than stale siblings, omit tombstones, and assemble shared overflow chains. Hidden images in `/tests/images/` are not in the agent container. Protected `format.py` / `FORMAT.md` are restored from the verifier image. Reward is written only by root into `chmod 700 /logs/verifier`. Hardcoding `/app/data/crashed.db` cannot pass the baked hidden set.

Codex `openai/gpt-5.6-sol` `reasoning_effort=xhigh` passed genuine `/run` trial 1 on every FORMAT-checklist revision (CBT1–CBT6). The engine rewrite drops that strategy. Claude `/run` and `/cheat` stay blocked until Codex `/run` is 3/3 fail and Codex `/cheat` is 0.
