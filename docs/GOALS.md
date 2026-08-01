# Goals vs CodeGuard

**Goals** describe *what this evaluation must attempt* (Foundry coverage intent).  
**CodeGuard** is a *detector rule pack* that always runs — it is not itself a goal.

Each goal in the standard pack maps to CWEs, OWASP Top 10:2025 categories, and related CodeGuard rule IDs so Antares localization and coverage tracking stay aligned.

## Default behavior

You only need a repo path. If the target has no local goals file, acyl uses the bundled baseline:

```bash
acyl scan /path/to/any-repo --no-antares
# → using goals: …/goals/standard.md
```

### Resolution order

1. Explicit `--goals FILE` (CLI / dashboard / API)
2. Target-local `goals.md`, `.acyl/goals.md`, or `goals.yml`
3. Environment `ACYL_GOALS_FILE`
4. Bundled [`goals/standard.md`](../goals/standard.md)
5. Error only if the bundled default is missing from the install

## Packs shipped with acyl

| File | Use |
|---|---|
| [`goals/standard.md`](../goals/standard.md) | **Default** — full personal baseline (~12 goals) |
| [`goals/minimal.md`](../goals/minimal.md) | Fast preset: secrets + supply-chain + injection |

```bash
# Opt into the slim pack for one run
acyl scan /path/to/repo --goals goals/minimal.md

# Or pin via env (overrides bundled default, not --goals / local goals.md)
export ACYL_GOALS_FILE=/path/to/acyl-app-sec/goals/minimal.md
```

## When to add a repo-local `goals.md`

Only when this project needs a *different* intent than the baseline (replace, not merge). Examples: a pure IaC repo, or a narrow audit focused on one CWE.

## Docker

The image includes `/app/goals/standard.md`. Scanning `/targets/app` with no local goals file automatically uses that bundled default.
