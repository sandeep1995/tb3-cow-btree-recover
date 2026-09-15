# Evaluation log

Task: `tasks/cow-btree-recover`  
Harbor: 0.23.0  
TB3 CI snapshot: `vendor/tb3/harbor-run-defaults.yml` (3 trials; `claude-code` + `anthropic/claude-opus-5` `reasoning_effort=max` + `CLAUDE_CODE_MAX_OUTPUT_TOKENS=128000`; `codex` + `openai/gpt-5.6-sol` `reasoning_effort=xhigh`; `/run` and `/cheat` default `env: modal`). Local validation used `--env docker`.

Logs: `docs/results/oracle/`, `docs/results/nop/`, `docs/results/cheat-oracle/`.

## Static checks — PASS

```bash
./scripts/run-static-checks.sh tasks/cow-btree-recover
```

All 22 TB3 `scripts/checks/check-*.sh` scripts passed.

## Implementation rubric — not run (auth)

```bash
harbor check tasks/cow-btree-recover -r vendor/tb3/task-implementation.toml -m anthropic/claude-opus-4-8
```

No `ANTHROPIC_API_KEY` and no Claude OAuth token on this machine. Mechanical static checks still passed.

## Docker build / oracle / nop — PASS

```bash
harbor run -p tasks/cow-btree-recover --agent oracle --env docker --yes -n 1 -o jobs/oracle
harbor run -p tasks/cow-btree-recover --agent nop --env docker --yes -n 1 -o jobs/nop
```

| Run | Job | Reward | Verifier |
| --- | --- | --- | --- |
| oracle | `jobs/oracle/2026-09-15__19-59-12` | **1.0** | 8/8 pytest passed (`docs/results/oracle/test-stdout.txt`) |
| nop | `jobs/nop/2026-09-15__20-00-18` | **0.0** | 4 failed (hidden images), 4 passed (`docs/results/nop/test-stdout.txt`) |

First oracle attempt failed with Docker BuildKit overlayfs `invalid argument` on this nested VM. Workaround (host only, not part of the task): `"storage-driver": "vfs"` in `/etc/docker/daemon.json`. After that, oracle and nop completed.

## Deterministic cheat oracle — PASS (reward 0)

Ran `tasks/cow-btree-recover/cheat/solve.sh` in place of `solution/solve.sh` via the oracle agent (then restored the real solution):

```bash
harbor run -p tasks/cow-btree-recover --agent oracle --env docker --yes -n 1 -o jobs/cheat-oracle
```

Reward **0.0**. Empty `recover_store` cannot match hidden images.

## Standard trials (`/run`) — blocked on auth

Attempted TB3-default configs. These are **not** counted as model failures.

### Codex `openai/gpt-5.6-sol` `reasoning_effort=xhigh`

```bash
harbor run -p tasks/cow-btree-recover --agent codex --model openai/gpt-5.6-sol \
  --env docker --yes --ae CODEX_FORCE_AUTH_JSON=1 --ak reasoning_effort=xhigh \
  -n 1 -o jobs/run-codex-probe3
```

Harbor installed Codex inside the trial container, then raised:

```
ValueError: CODEX_FORCE_AUTH_JSON is set but /home/ubuntu/.codex/auth.json does not exist
```

No `OPENAI_API_KEY` either. Earlier probes failed with `NetworkConnectionError` until host `iptables-legacy` MASQUERADE was enabled for user-defined Docker bridges (compose NAT). After that, install succeeded and the blocker was auth.

### Claude Code `anthropic/claude-opus-5` `reasoning_effort=max`

```bash
harbor run -p tasks/cow-btree-recover --agent claude-code --model anthropic/claude-opus-5 \
  --env docker --yes --ak reasoning_effort=max --ae CLAUDE_CODE_MAX_OUTPUT_TOKENS=128000 \
  -n 1 -o jobs/run-claude-probe
```

Exception: `AgentAuthenticationError`. Agent stdout: `Not logged in · Please run /login` (`apiKeySource":"none"`). No `CLAUDE_CODE_OAUTH_TOKEN`. Verifier still scored the untouched store (reward 0); that is an auth abort, not a genuine three-trial model failure.

## Adversarial trials (`/cheat`) — blocked on the same auth

Required command shape (not executed as a logged-in model):

```bash
harbor run -p tasks/cow-btree-recover --agent codex --model openai/gpt-5.6-sol \
  --env docker --yes --ae CODEX_FORCE_AUTH_JSON=1 --ak reasoning_effort=xhigh \
  --extra-instruction-path vendor/tb3/hack-trial-prompt.md -k 1 -o jobs/cheat-codex

harbor run -p tasks/cow-btree-recover --agent claude-code --model anthropic/claude-opus-5 \
  --env docker --yes --ae CLAUDE_FORCE_OAUTH=1 --ae CLAUDE_CODE_OAUTH_TOKEN="$CLAUDE_CODE_OAUTH_TOKEN" \
  --ae CLAUDE_CODE_MAX_OUTPUT_TOKENS=128000 --ak reasoning_effort=max \
  --extra-instruction-path vendor/tb3/hack-trial-prompt.md -k 1 -o jobs/cheat-claude
```

The deterministic cheat oracle above is the anti-cheat evidence available without subscription auth.

## Failure analysis

Nop and the empty-recover cheat fail because recovery must (1) select a checksum-valid superblock by LSN, (2) walk interior children rather than stale `right_sibling` links, (3) reject a torn newer root and fall back, and (4) keep the higher-LSN value on duplicate keys. Hidden images in `/tests/images/` are not in the agent container. Protected `format.py` / `FORMAT.md` are restored from the verifier image. Reward is written only by root into `chmod 700 /logs/verifier`. Hardcoding `/app/data/crashed.db` cannot pass the baked hidden set.

Model `/run` and `/cheat` remain unmeasured until Codex `~/.codex/auth.json` or `OPENAI_API_KEY` and Claude `claude setup-token` / `CLAUDE_CODE_OAUTH_TOKEN` are provided. Do not treat auth or container-install exceptions as model failures.
