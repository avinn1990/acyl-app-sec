# acyl-app-sec

Personal / local AppSec platform — scan your own repositories on your machine (air-gapped OK), triage findings with a Foundry-lite harness, and open reviewable fix PRs.

Inspired by the Aikido-style scan → denoise → fix loop, but fully local:

| Capability | Implementation |
|---|---|
| SAST-ish rules | Project CodeGuard v1.4.0 presence sweeps (+ optional LLM rule eval) |
| Localization | Cisco Antares-350M terminal agent (localhost) |
| Secrets | `gitleaks` when installed, else regex fallback |
| SCA | `osv-scanner` when installed, else manifest heuristic |
| Triage | Foundry evidence gate (presence carve-out for secrets/creds) |
| Reports | Markdown + SARIF under `~/.cache/acyl/runs/<id>/reports/` |
| Autofix | Gated on confirmed true-positives → patch or draft PR |

## Quick start

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"

# Deterministic scan of the intentional fixture (no GPU required)
ACYL_MODEL_MOCK=1 acyl serve-model --mock --port 8080 &
acyl scan fixtures/vulnerable-app --no-docker
acyl findings <run_id> --state confirmed
acyl report <run_id> --open
```

### Web dashboard

```bash
acyl dashboard
# open http://127.0.0.1:8787
```

The dashboard lists runs, shows confirmed / needs-review findings with evidence, renders reports, and can queue new scans or offline autofixes. It binds to localhost by default.

### Docker (recommended for “download and run”)

```bash
# From a clone:
docker compose up --build
# open http://127.0.0.1:8787  → scan path: /targets/app

# Your own repo:
ACYL_TARGET=/absolute/path/to/repo docker compose up --build

# Or one-shot:
docker build -t acyl:local .
docker run --rm -p 127.0.0.1:8787:8787 \
  -v acyl-data:/data \
  -v /absolute/path/to/repo:/targets/app:ro \
  acyl:local
```

Published images (after merge to `main`): `ghcr.io/avinn1990/acyl-app-sec:latest`  
Full guide: [docs/DOCKER.md](docs/DOCKER.md).

Scan any local checkout (public or private). **No per-repo `goals.md` required** — acyl uses bundled [`goals/standard.md`](goals/standard.md) by default:

```bash
acyl scan /path/to/repo --no-antares
# prints: Using goals: …/goals/standard.md
```

Override with `--goals`, a repo-local `goals.md`, or `ACYL_GOALS_FILE`. See [docs/GOALS.md](docs/GOALS.md).

Private repos via git URL use your existing host credentials (`ssh-agent`, `gh auth`, git credential helper). acyl does not store PATs.

```bash
acyl scan --git-url git@github.com:org/private-repo.git --no-antares
```

## Local install from scratch

Full step-by-step for a fresh machine (macOS or Linux), including real Antares inference, dashboard, everyday workflow, Docker-only option, Ollama permanent hosting, and troubleshooting:

**→ [docs/LOCAL.md](docs/LOCAL.md)**

| Step | What |
|---|---|
| 0 | What you end up with (CLI, dashboard `:8787`, model `:8080`) |
| 1 | Base tooling (Xcode CLT / Homebrew / Python ≥ 3.12, optional Docker) |
| 2 | Clone + `pip install -e ".[dev,model]"` |
| 3 | Hugging Face gated access + `huggingface-cli login` |
| 4 | `acyl serve-model` (real weights or mock; transformers pin notes) |
| 5 | `acyl dashboard` on http://127.0.0.1:8787 |
| 6 | First scan (CLI + UI) |
| 7 | Everyday two-process workflow |
| 8 | Optional Docker-only path |

## Antares model hosting

Antares-350M runs **only on the operator machine**. Short path (details in [docs/LOCAL.md](docs/LOCAL.md)):

1. Request access to [`fdtn-ai/antares-350m`](https://huggingface.co/fdtn-ai/antares-350m) (gated).
2. `pip install -e ".[model]"` and ensure `huggingface-cli login` once (online).
3. `acyl serve-model --host 127.0.0.1 --port 8080` loads weights into `~/.cache/acyl/models/` and serves an OpenAI-compatible API.
4. The Antares **agent loop** (outside the model) executes allowlisted shell commands in a Docker sandbox with `network=none` and the target mounted read-only.

For CI / dogfood without weights: `acyl serve-model --mock`.

To keep Antares always on and callable by **any** local web app (OpenAI-compatible), prefer **Ollama** with a GGUF import — see [docs/LOCAL.md § Permanent shared inference](docs/LOCAL.md#permanent-shared-inference-ollama).

Autofix uses a **separate** optional endpoint `ACYL_FIX_MODEL_URL`. SCA bumps and secret redaction stubs work with no LLM.

## Foundry-lite harness

Roles in v1: Orchestrator, Indexer, Cartographer, Detector (CodeGuard + secrets + SCA + Antares), Triager, Reporter, gated Autofix. Validator / `exploited` is disabled until a disposable testbed exists.

See [`specs/001-foundry/`](specs/001-foundry/) for the constitution and clarifications.

## Cursor: CodeGuard agents & skills

This repo vendors [Project CodeGuard](https://github.com/cosai-oasis/project-codeguard) v1.4.0 under [`.cursor/`](.cursor/) so Cursor picks it up from any clone (no global install):

| Path | What it does |
|---|---|
| `.cursor/rules/codeguard-*.mdc` | Always-on secure-coding rules in the editor |
| `.cursor/agents/codeguard-reviewer.md` | `@codeguard-reviewer` — SARIF-oriented security review agent |
| `.cursor/skills/codeguard/` | `/codeguard` skill while writing or reviewing code |
| `.cursor/skills/security-review/` | `/security-review` structured review workflow |
| `.cursor/skills/memory-safe-migration/` | `/memory-safe-migration` for C/C++ → memory-safe ports |

Attribution: [`.cursor/CODEGUARD_NOTICE.md`](.cursor/CODEGUARD_NOTICE.md) (CC-BY-4.0). Re-sync with `scripts/vendor-codeguard.sh`.

These Cursor assets are separate from the **runtime** detector rules in `rules/` used by `acyl scan`.

## Air gap

- Cache Antares weights under `~/.cache/acyl/models/`
- Vendor CodeGuard rules ship in-repo (`rules/`, `vendor/codeguard/`, `.cursor/`)
- Secrets/SCA fallbacks work without downloading scanners
- `acyl fix --finding <id> --offline` writes a patch + `fix-branch.sh` without pushing

## CLI

```
acyl scan [PATH] [--git-url URL] [--goals FILE] [--no-antares] [--llm-codeguard]
acyl status RUN_ID
acyl findings RUN_ID [--state confirmed]
acyl report RUN_ID [--open]
acyl coverage RUN_ID
acyl fix --finding FIND_ID [--run RUN_ID] [--offline]
acyl serve-model [--mock] [--port 8080]
acyl dashboard [--host 127.0.0.1] [--port 8787]
```

## License

MIT for acyl code. Project CodeGuard materials under `vendor/codeguard/`, `rules/`, and `.cursor/` are CC-BY-4.0 (see `vendor/codeguard/NOTICE.md` and `.cursor/CODEGUARD_NOTICE.md`). Antares weights are Apache-2.0 from Cisco Foundation AI / Hugging Face.
