# AGENTS.md

## Cursor Cloud specific instructions

`acyl` is a single-product Python 3.12 AppSec CLI + web dashboard (package `acyl`, entry point `acyl`). It scans local repos for secrets/SCA/CodeGuard/crypto issues, triages them, and writes Markdown/SARIF reports. Persistence is per-run SQLite under `~/.cache/acyl/runs/<id>/` — there is no external database, queue, or cache to run.

### Environment
- Dependencies live in a virtualenv at `.venv` (created/refreshed by the startup update script). Activate it with `source .venv/bin/activate`, or call binaries directly via `.venv/bin/<cmd>` (e.g. `.venv/bin/acyl`, `.venv/bin/pytest`, `.venv/bin/ruff`).
- `python` is not on PATH outside the venv; use `python3` or activate the venv first.
- Always set `ACYL_MODEL_MOCK=1` unless you specifically want the real Antares model. It makes scans/tests deterministic with no GPU/model weights. The optional model server (`acyl serve-model`, port 8080) is not needed for CLI scans, the dashboard, or tests.
- External scanner binaries (`gitleaks`, `osv-scanner`, `docker`, `gh`) are optional — acyl has built-in fallbacks. Pass `--no-docker --no-antares` to CLI scans to avoid Docker/model dependencies.

### Lint / test (standard commands, see `.github/workflows/ci.yml`)
- Lint: `ruff check src tests`
- Tests: `ACYL_MODEL_MOCK=1 pytest -q`

### Run
- CLI scan (hello world): `ACYL_MODEL_MOCK=1 acyl scan fixtures/vulnerable-app --no-docker --no-antares`, then `acyl status <run_id>` / `acyl findings <run_id> --state confirmed` / `acyl report <run_id>`. `fixtures/vulnerable-app` is intentionally vulnerable scan-target test data (not real secrets).
- Web dashboard (port 8888): `ACYL_MODEL_MOCK=1 acyl dashboard --host 127.0.0.1 --port 8888`, then open http://127.0.0.1:8888. The dashboard runs scans as in-process background tasks (no separate worker), so it is the only long-lived service needed for the full UI flow. Full CLI options are in `README.md`.
