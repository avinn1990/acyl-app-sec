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

Scan any local checkout (public or private):

```bash
acyl scan /path/to/repo --goals examples/goals.md --no-antares
```

Private repos via git URL use your existing host credentials (`ssh-agent`, `gh auth`, git credential helper). acyl does not store PATs.

```bash
acyl scan --git-url git@github.com:org/private-repo.git --goals examples/goals.md
```

## Antares model hosting

Antares-350M runs **only on the operator machine**:

1. Request access to [`fdtn-ai/antares-350m`](https://huggingface.co/fdtn-ai/antares-350m) (gated).
2. `pip install -e ".[model]"` and ensure `huggingface-cli login` once (online).
3. `acyl serve-model --host 127.0.0.1 --port 8080` loads weights into `~/.cache/acyl/models/` and serves an OpenAI-compatible API.
4. The Antares **agent loop** (outside the model) executes allowlisted shell commands in a Docker sandbox with `network=none` and the target mounted read-only.

For CI / dogfood without weights: `acyl serve-model --mock`.

Autofix uses a **separate** optional endpoint `ACYL_FIX_MODEL_URL`. SCA bumps and secret redaction stubs work with no LLM.

## Foundry-lite harness

Roles in v1: Orchestrator, Indexer, Cartographer, Detector (CodeGuard + secrets + SCA + Antares), Triager, Reporter, gated Autofix. Validator / `exploited` is disabled until a disposable testbed exists.

See [`specs/001-foundry/`](specs/001-foundry/) for the constitution and clarifications.

## Air gap

- Cache Antares weights under `~/.cache/acyl/models/`
- Vendor CodeGuard rules ship in-repo (`rules/`, `vendor/codeguard/`)
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

MIT for acyl code. Project CodeGuard materials under `vendor/codeguard/` and `rules/` are CC-BY-4.0 (see `vendor/codeguard/NOTICE.md`). Antares weights are Apache-2.0 from Cisco Foundation AI / Hugging Face.
