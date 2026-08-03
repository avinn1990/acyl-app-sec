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

Cisco Antares-350M (`fdtn-ai/antares-350m`) is a gated, on-prem vulnerability-localization model built on IBM Granite 4.0 350M. acyl runs it **only on the operator machine** via an OpenAI-compatible localhost server; the Antares **agent loop** (outside the model) executes allowlisted shell commands in a Docker sandbox with `network=none` (or an in-process allowlisted shell when Docker is disabled).

Autofix uses a **separate** optional endpoint `ACYL_FIX_MODEL_URL`. SCA bumps and secret redaction stubs work with no LLM. For CI / dogfood without weights: `acyl serve-model --mock`.

For always-on shared inference callable by **any** local OpenAI-compatible web app, see [docs/LOCAL.md § Permanent shared inference (Ollama)](docs/LOCAL.md#permanent-shared-inference-ollama).

### Install Antares (local / Mac Mini)

Validated on Apple Silicon Mac Mini (8GB+). Python 3.12+, Git, and optional Docker Desktop.

1. **Request gated access** to [`fdtn-ai/antares-350m`](https://huggingface.co/fdtn-ai/antares-350m) on Hugging Face (manual review).
2. **Clone and install model extras:**

```bash
git clone https://github.com/avinn1990/acyl-app-sec.git
cd acyl-app-sec
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[model]"   # pulls torch, transformers, accelerate
```

3. **Authenticate to Hugging Face** (do **not** put tokens in source, LaunchAgents, or compose files):

```bash
huggingface-cli login
# token is stored under ~/.cache/huggingface/ (or ~/.huggingface/)
# optional macOS Keychain:
#   security add-generic-password -a "$USER" -s huggingface -w 'YOUR_TOKEN' -U
```

4. **Start the server** (first run downloads weights into `~/.cache/acyl/models/`):

```bash
acyl serve-model --host 127.0.0.1 --port 8080
```

5. **Verify health and real generation** (health alone is not enough — see troubleshooting):

```bash
curl -s http://127.0.0.1:8080/health
# → {"ok": true, "mock": false, "model": "fdtn-ai/antares-350m"}

curl -sS http://127.0.0.1:8080/v1/chat/completions \
  -H 'Content-Type: application/json' \
  -d '{"model":"fdtn-ai/antares-350m","messages":[{"role":"user","content":"Say hello in one word."}],"max_tokens":64}'
```

6. **Point acyl at the server** (defaults already match localhost:8080):

```bash
export ACYL_MODEL_URL=http://127.0.0.1:8080/v1   # optional; this is the default
export ACYL_MODEL_ID=fdtn-ai/antares-350m          # optional; this is the default
acyl scan /path/to/repo          # omit --no-antares
acyl dashboard                   # UI: uncheck “Skip Antares”
```

The web UI does **not** call Antares directly and has no inference-URL field. The browser talks to the dashboard API; the backend `ChatClient` uses `ACYL_MODEL_URL`. To use a different OpenAI-compatible endpoint, set `ACYL_MODEL_URL` / `ACYL_MODEL_ID` in the environment that runs `acyl` (CLI or dashboard).

### Keep it running on macOS (launchd)

Foreground `serve-model` works for smoke tests. For always-on hosting after login, use a LaunchAgent that calls the **absolute** venv binary (launchd does not load `.zshrc` / PATH):

```bash
mkdir -p "$HOME/bin" "$HOME/Library/Logs/acyl"
cat > "$HOME/bin/acyl-serve-antares.sh" <<'EOF'
#!/bin/bash
set -euo pipefail
export HOME="${HOME:-/Users/REPLACE_ME}"
export PATH="/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin"
# Edit REPO to your clone path (example: /Users/you/acyl-app-sec)
REPO="$HOME/acyl-app-sec"
exec "$REPO/.venv/bin/acyl" serve-model --host 127.0.0.1 --port 8080
EOF
chmod +x "$HOME/bin/acyl-serve-antares.sh"
```

Create `~/Library/LaunchAgents/ai.acyl.antares.plist` with absolute paths only (no `~`), `RunAtLoad`, `KeepAlive`, and `HOME` in `EnvironmentVariables`. Log to `~/Library/Logs/acyl/antares.{out,err}.log`. Then:

```bash
launchctl bootstrap "gui/$(id -u)" ~/Library/LaunchAgents/ai.acyl.antares.plist
launchctl kickstart -k "gui/$(id -u)/ai.acyl.antares"
```

After pulling code fixes:

```bash
cd ~/acyl-app-sec && git pull && source .venv/bin/activate && pip install -e ".[model]"
launchctl kickstart -k "gui/$(id -u)/ai.acyl.antares"
```

Keep the Mini awake when plugged in. Prefer Ethernet. FileVault still requires unlock after power loss for a user LaunchAgent.

### Findings from local install

| Topic | What we found |
|---|---|
| Hardware | Antares-350M is practical on Apple Silicon Mac Mini (8GB+). Torch may stay on CPU unless MPS is wired; CPU is fine for 350M. |
| Gated HF | Access must be approved; `huggingface-cli login` once online. Incomplete / unauthorized downloads cause load failures. |
| Cache layout | Weights and `ACTIVE_MODEL` live under `~/.cache/acyl/models/`. |
| Health vs chat | `/health` only means the process is up. Chat completions exercise `model.generate()` and can 500 while health is green. |
| Granite / transformers bug | Attention-only Granite 4.0 350M hits `ValueError: has_previous_state can only be called on LinearAttention layers` on some transformers builds ([transformers#45507](https://github.com/huggingface/transformers/issues/45507)). acyl passes `use_cache=False` in `serve-model` (slightly slower; acceptable for 350M). |
| launchd | Exit status **78** (`EX_CONFIG`) means launchd never started the process (bad/missing path), not a Python crash. Use absolute `.venv/bin/acyl`; never bare `acyl` or `~` in the plist. |
| Port 8080 | Manual `serve-model` and launchd fight for the same port — free it with `lsof -iTCP:8080 -sTCP:LISTEN` before `kickstart`. |
| Dashboard | Uncheck **Skip Antares**. No UI change needed for a working local Antares. Docker dashboard needs `ACYL_MODEL_URL=http://host.docker.internal:8080/v1` and `ACYL_MODEL_MOCK` unset/0 — see [docs/DOCKER.md](docs/DOCKER.md). |
| Protocol | Swapping `ACYL_MODEL_URL` to another OpenAI-compatible server works at HTTP layer; the localization agent expects Antares-style tool/command behavior. |
| Secrets | Never hardcode HF tokens in plist, compose, or repo. Prefer `huggingface-cli login` or Keychain → `HF_TOKEN`. |

### Troubleshooting

| Symptom | Likely cause | Fix |
|---|---|---|
| `401` / gated / cannot download weights | HF access not approved or not logged in | Request access; `huggingface-cli login`; confirm `~/.cache/huggingface/token` |
| `Install acyl[model] extras…` | Missing torch/transformers | `pip install -e ".[model]"` inside the venv |
| launchd status **78** | Bad `ProgramArguments` / missing script | `plutil -lint` plist; absolute paths; `chmod +x` wrapper; `bootout` → `bootstrap` → `kickstart` |
| `/health` OK, chat returns **500** | Granite cache bug or stale install | Pull main (includes `use_cache=False`), reinstall `.[model]`, restart serve-model; check `~/Library/Logs/acyl/antares.err.log` |
| `Address already in use` / launchd never binds | Leftover process on 8080 | `lsof -iTCP:8080 -sTCP:LISTEN` and stop the old server |
| Dashboard scan skips Antares | UI default | Uncheck **Skip Antares** |
| Dashboard in Docker can’t reach host Antares | Wrong URL / mock mode | Set `ACYL_MODEL_URL=http://host.docker.internal:8080/v1`, disable `ACYL_MODEL_MOCK` |
| Incomplete model cache | Interrupted first download | Remove bad files under `~/.cache/acyl/models/` and restart `serve-model` |
| Need offline after first pull | Hub still contacted | `HF_HUB_OFFLINE=1` and `TRANSFORMERS_OFFLINE=1` once weights are cached |

Useful probes:

```bash
launchctl print "gui/$(id -u)/ai.acyl.antares"
tail -n 100 ~/Library/Logs/acyl/antares.err.log
python -c "import transformers; print(transformers.__version__)"
ls -lah ~/.cache/acyl/models/
```

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
