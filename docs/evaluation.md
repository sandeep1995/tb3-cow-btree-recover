# Evaluation log

Task: `tasks/cow-btree-recover`  
Upstream CI snapshot: Terminal-Bench 3 `harbor-run-defaults.yml` vendored at `vendor/tb3/harbor-run-defaults.yml` (3 trials; `claude-code` + `anthropic/claude-opus-5` `reasoning_effort=max`; `codex` + `openai/gpt-5.6-sol` `reasoning_effort=xhigh`; `/run` and `/cheat` default `env: modal`).

## Static checks

Command:

```bash
./scripts/run-static-checks.sh tasks/cow-btree-recover
```

Result: **PASS** (all 22 `scripts/checks/check-*.sh` scripts).

Checked: canary, dockerfile references/sanity/platform, compose host binds, gpu types, instruction suffix, allow-internet pair, nproc, pip pinning, pytest version, separate verifier, absolute paths, task fields, package name, slug, timeout, test file references, test.sh sanity, trial-time network fetch, verifier tooling baked.

## Implementation rubric

Command:

```bash
harbor check tasks/cow-btree-recover -r vendor/tb3/task-implementation.toml -m anthropic/claude-opus-4-8
```

Result: **not run** until Anthropic/Claude credentials are available on this machine. No `ANTHROPIC_API_KEY` / Claude OAuth token was present in the authoring environment.

## Docker / oracle / nop

Commands:

```bash
harbor run -p tasks/cow-btree-recover --agent oracle --env docker --yes -n 1 -o jobs/oracle
harbor run -p tasks/cow-btree-recover --agent nop --env docker --yes -n 1 -o jobs/nop
```

Results: recorded below after the runs in this environment.

## Standard trials (`/run`)

Configs match TB3 defaults. Local backend is `docker` (CI default is `modal`).

| Config | Trial | Reward | Notes |
| --- | --- | --- | --- |
| codex / openai/gpt-5.6-sol / xhigh | 1 | pending | needs Codex subscription auth |
| codex / openai/gpt-5.6-sol / xhigh | 2 | pending | |
| codex / openai/gpt-5.6-sol / xhigh | 3 | pending | |
| claude-code / anthropic/claude-opus-5 / max | 1 | pending | needs Claude OAuth token |
| claude-code / anthropic/claude-opus-5 / max | 2 | pending | |
| claude-code / anthropic/claude-opus-5 / max | 3 | pending | |

Requirement: 3/3 genuine verifier failures per config. Infra errors do not count.

## Adversarial trials (`/cheat`)

Instruction prefix: `vendor/tb3/hack-trial-prompt.md`.

| Config | Reward | Notes |
| --- | --- | --- |
| codex / openai/gpt-5.6-sol / xhigh | pending | needs auth |
| claude-code / anthropic/claude-opus-5 / max | pending | needs auth |

Requirement: reward `0` on every adversarial trial.

Deterministic cheat oracle `tasks/cow-btree-recover/cheat/solve.sh` replaces `recover_store` with `return {}` and cannot pass hidden-image tests.

## Failure analysis

- **Nop / empty recover:** slot-0 sibling walks and missing checksum validation disagree with the spec recoverer on stale-sibling, torn-newer, duplicate-key, and slot-1 images.
- **Why models are expected to fail:** recovery has to compose dual-superblock validity (full reachable checksums), ignore stale `right_sibling` links after path copy, fall back when the newer root is torn, and break LSN ties on duplicate keys. The public image is solvable-looking; hidden images cover the other legs.
- **Why /cheat should get zero:** the verifier runs in a separate container, restores protected spec files, executes `recover_store` unprivileged, and grades hidden images baked only into the verifier image. Returning `{}`, rewriting FORMAT.md, or hardcoding `/app/data/crashed.db` does not match those images. The reward file is root-only (`chmod 700 /logs/verifier`).
