# Local install from scratch

Host acyl on a fresh machine (macOS or Linux) with optional real Antares-350M inference. No prior Python/venv/Docker setup is assumed.

## 0. What you end up with

| Piece | Port | Purpose |
|---|---|---|
| `acyl` CLI | — | Scan / triage / reports / autofix |
| Dashboard | `8888` | Web UI for runs, findings, new scans |
| Antares model server | `8080` | Local OpenAI-compatible inference (`fdtn-ai/antares-350m`) |

No cloud database or queue. Run artifacts land under `~/.cache/acyl/`.

You can skip the model server and use `--no-antares` / `ACYL_MODEL_MOCK=1` for deterministic scans without GPU or Hugging Face weights.

---

## 1. Base tooling

### macOS

```bash
xcode-select --install

/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"

# Apple Silicon — add Homebrew to your shell (installer also prints this):
echo 'eval "$(/opt/homebrew/bin/brew shellenv)"' >> ~/.zprofile
eval "$(/opt/homebrew/bin/brew shellenv)"

brew install python@3.12 git gh
python3.12 --version   # must be >= 3.12
```

**Optional but recommended for Antares sandboxing:** install [Docker Desktop for Mac](https://www.docker.com/products/docker-desktop/), open it once, and wait until it is idle. Antares can run without Docker (`--no-docker`); Docker enables the stronger `network=none` sandbox.

Optional scanners (acyl has built-in fallbacks if missing):

```bash
brew install gitleaks
# osv-scanner: https://google.github.io/osv-scanner/installation/
```

### Linux

Install Python **≥ 3.12**, `git`, and a venv package for your distro (e.g. `python3.12-venv` on Debian/Ubuntu). Optional: Docker Engine, `gitleaks`, `osv-scanner`, `gh`.

---

## 2. Clone and install acyl

```bash
mkdir -p ~/src
cd ~/src
git clone https://github.com/avinn1990/acyl-app-sec.git
cd acyl-app-sec

python3.12 -m venv .venv          # or: python3 -m venv .venv
source .venv/bin/activate

python -m pip install --upgrade pip
pip install -e ".[dev,model]"
```

- `[dev]` — `pytest`, `ruff`
- `[model]` — `transformers`, `torch`, `accelerate` (needed for real Antares)

Sanity check:

```bash
acyl version
ruff check src tests
ACYL_MODEL_MOCK=1 pytest -q
```

CLI-only / no GPU install (skip model extras):

```bash
pip install -e ".[dev]"
```

---

## 3. Hugging Face access for Antares-350M

Required only for **real** inference (not mock).

1. Create a Hugging Face account: https://huggingface.co/join
2. Request access to the gated model: https://huggingface.co/fdtn-ai/antares-350m
3. Wait until access is **approved**
4. Create a read token: https://huggingface.co/settings/tokens
5. Log in once (stores credentials in the HF cache — do **not** put tokens in source code):

```bash
source ~/src/acyl-app-sec/.venv/bin/activate
huggingface-cli login
```

The first real load downloads weights into `~/.cache/acyl/models/` (and Hugging Face’s own cache). Network is needed once; afterward the machine can run air-gapped for that model.

---

## 4. Start the Antares model server

Use a dedicated terminal. **Do not** set `ACYL_MODEL_MOCK=1` for real weights.

```bash
cd ~/src/acyl-app-sec
source .venv/bin/activate
unset ACYL_MODEL_MOCK

acyl serve-model --host 127.0.0.1 --port 8080
```

First start can take a while (download + load). When ready:

```bash
curl -s http://127.0.0.1:8080/health
# expect: {"ok":true,"mock":false,"model":"fdtn-ai/antares-350m"}
```

Smoke-test chat:

```bash
curl -s http://127.0.0.1:8080/v1/chat/completions \
  -H 'Content-Type: application/json' \
  -d '{
    "model": "fdtn-ai/antares-350m",
    "messages": [{"role":"user","content":"Say hello in one short sentence."}],
    "max_tokens": 64
  }'
```

Leave this process running. Defaults match what acyl expects: `ACYL_MODEL_URL=http://127.0.0.1:8080/v1`.

### Known transformers / Granite issue

Antares is built on IBM Granite 4.0. Some `transformers` releases raise:

```text
ValueError: `has_previous_state` can only be called on LinearAttention layers...
```

Current acyl `serve-model` works around this by passing `use_cache=False` during generation (slightly slower; fine for 350M). If you still hit the error on an older checkout, pull latest `main`, reinstall `.[model]`, and restart. Pinning `transformers==5.12.1` is an alternative. Mock mode still works regardless:

```bash
ACYL_MODEL_MOCK=1 acyl serve-model --mock --port 8080
```

> Note: `serve-model` loads via transformers defaults (typically **CPU** unless you change device placement). Antares-350M is small enough for CPU on a Mac Mini; expect slower localization than a discrete GPU.

For launchd always-on hosting, validated Mac Mini findings, and a deeper troubleshooting table, see the **Antares model hosting** section in [README.md](../README.md#antares-model-hosting).

---

## 5. Start the dashboard

Second terminal:

```bash
cd ~/src/acyl-app-sec
source .venv/bin/activate
unset ACYL_MODEL_MOCK

acyl dashboard --host 127.0.0.1 --port 8888
```

Open http://127.0.0.1:8888

---

## 6. Run your first real scan

Third terminal (model server still up):

```bash
cd ~/src/acyl-app-sec
source .venv/bin/activate
unset ACYL_MODEL_MOCK

# Intentional fixture (vulnerable on purpose — not real secrets)
acyl scan fixtures/vulnerable-app

# Your own checkout
# acyl scan /absolute/path/to/your-repo
```

If Docker is not running, force the in-process sandbox:

```bash
acyl scan fixtures/vulnerable-app --no-docker
```

Then:

```bash
acyl status <run_id>
acyl findings <run_id> --state confirmed
acyl report <run_id> --open
```

### From the dashboard

1. Click **New scan**
2. Local path: absolute path to your repo (or the fixture under this clone)
3. Leave **Skip Antares** unchecked (Antares is on by default) for real localization; check it only to skip
4. Leave **No Docker sandbox** checked unless Docker Desktop / Engine is up
5. **Start scan**

---

## 7. Everyday workflow (two processes)

```bash
# Terminal A — model
cd ~/src/acyl-app-sec && source .venv/bin/activate && unset ACYL_MODEL_MOCK
acyl serve-model --host 127.0.0.1 --port 8080

# Terminal B — UI
cd ~/src/acyl-app-sec && source .venv/bin/activate && unset ACYL_MODEL_MOCK
acyl dashboard --host 127.0.0.1 --port 8888
```

Scan via the UI or:

```bash
acyl scan /path/to/repo
```

Offline autofix patch (no PR push):

```bash
acyl fix --finding <find_id> --run <run_id> --offline
```

---

## 8. Optional: Docker-only path (no local venv)

Good for dashboard + CLI **without** real Antares (image defaults to mock):

```bash
# macOS
brew install --cask docker   # open Docker Desktop once
cd ~/src/acyl-app-sec
docker compose up --build
# UI: http://127.0.0.1:8888 — scan path: /targets/app
```

For **real** Antares with a Docker dashboard: run `acyl serve-model` on the host (sections 3–4), then point the container at the host:

```bash
ACYL_MODEL_MOCK=0 \
ACYL_MODEL_URL=http://host.docker.internal:8080/v1 \
docker compose up --build
```

In the UI, leave **Skip Antares** unchecked (default), keep **No Docker sandbox** checked (nested Docker sandbox is not enabled in-container).

Full container details: [DOCKER.md](DOCKER.md).

---

## Permanent shared inference (Ollama)

To keep Antares always available so **any** local web app can call OpenAI-compatible chat (not only acyl):

1. Install Ollama (`brew install ollama && brew services start ollama`).
2. Import a GGUF build (e.g. community quant [DevQuasar/fdtn-ai.antares-350m-GGUF](https://huggingface.co/DevQuasar/fdtn-ai.antares-350m-GGUF)) via a Modelfile and `ollama create antares-350m -f Modelfile`.
3. Keep the model warm with `OLLAMA_KEEP_ALIVE=-1` on the Ollama service.
4. Point apps at `http://127.0.0.1:11434/v1` with model name `antares-350m`.

Point acyl at Ollama instead of `serve-model`:

```bash
export ACYL_MODEL_URL=http://127.0.0.1:11434/v1
export ACYL_MODEL_ID=antares-350m
unset ACYL_MODEL_MOCK
```

Bind Ollama to `127.0.0.1` unless you intentionally need LAN access. Ollama has **no auth by default** — do not expose it to the internet without a reverse proxy and authentication.

---

## Troubleshooting

| Symptom | Fix |
|---|---|
| `python: command not found` | Use `python3.12`, or `source .venv/bin/activate` |
| `Install acyl[model] extras…` | `pip install -e ".[model]"` inside the venv |
| HF 401 / gated model | Access approved + `huggingface-cli login` |
| Health shows `"mock": true` | `unset ACYL_MODEL_MOCK` and restart `serve-model` without `--mock` |
| `has_previous_state` / LinearAttention error | Pin `transformers==5.12.1` (or newer git main); see §4 |
| Antares fails / Docker errors | `--no-docker`, or start Docker Desktop / Engine |
| Deterministic CI-style scans | `ACYL_MODEL_MOCK=1 acyl scan … --no-antares --no-docker` |

---

## Minimal “working tonight” path

```bash
# once
xcode-select --install
# install Homebrew, then:
brew install python@3.12 git
cd ~/src && git clone https://github.com/avinn1990/acyl-app-sec.git && cd acyl-app-sec
python3.12 -m venv .venv && source .venv/bin/activate
pip install -U pip && pip install -e ".[dev,model]"
# after HF access approved:
huggingface-cli login

# every session
unset ACYL_MODEL_MOCK
acyl serve-model --port 8080          # terminal 1
acyl dashboard --port 8888            # terminal 2
acyl scan fixtures/vulnerable-app --no-docker   # terminal 3
```
