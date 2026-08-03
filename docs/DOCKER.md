# Run acyl in Docker

acyl ships as a container that runs the **web dashboard** by default. Scan data persists in a volume; you mount the repositories you want to evaluate under `/targets`.

## Quick start (compose)

From a clone of this repo:

```bash
docker compose up --build
```

Open **http://127.0.0.1:8888**

The compose file mounts `./fixtures/vulnerable-app` at `/targets/app`. In the dashboard **New scan** form, use:

```text
/targets/app
```

Leave **No Docker sandbox** checked for the default image. Antares is on by default in the UI — check **Skip Antares** when using the mock image without a host model server, or leave it unchecked and point `ACYL_MODEL_URL` at a host `serve-model` (see below).
Goals default to the bundled `/app/goals/standard.md` when the mounted target has no `goals.md`.

### Scan your own repo

```bash
ACYL_TARGET=/absolute/path/to/your-repo docker compose up --build
```

Then scan `/targets/app` in the UI (or whatever you mounted).

---

## One-shot `docker run`

Build locally:

```bash
docker build -t acyl:local .
```

Run dashboard:

```bash
docker run --rm \
  -p 127.0.0.1:8888:8888 \
  -v acyl-data:/data \
  -v /absolute/path/to/your-repo:/targets/app:ro \
  acyl:local
```

Open http://127.0.0.1:8888

### CLI scan inside the container

```bash
docker run --rm \
  -v acyl-data:/data \
  -v /absolute/path/to/your-repo:/targets/app:ro \
  acyl:local \
  scan /targets/app --no-antares --no-docker
```

Other commands: `status`, `findings`, `report`, `fix`, `version`, `serve-model`.

---

## Pull from GitHub Container Registry

After images are published (CI on `main`):

```bash
docker pull ghcr.io/avinn1990/acyl-app-sec:latest

docker run --rm \
  -p 127.0.0.1:8888:8888 \
  -v acyl-data:/data \
  -v /absolute/path/to/your-repo:/targets/app:ro \
  ghcr.io/avinn1990/acyl-app-sec:latest
```

Private pulls may require:

```bash
echo $GITHUB_TOKEN | docker login ghcr.io -u USERNAME --password-stdin
```

---

## Volumes & paths

| Path in container | Purpose |
|---|---|
| `/data` | Persistent home + `ACYL_DATA_DIR` (`/data/.cache/acyl/runs`, models) |
| `/targets/...` | Mount host repos here (prefer `:ro`) |
| `/app/rules` | Vendored CodeGuard rules (read-only in image) |

Environment knobs:

| Variable | Default | Meaning |
|---|---|---|
| `ACYL_DATA_DIR` | `/data/.cache/acyl` | Run DB + reports |
| `ACYL_RULES_DIR` | `/app/rules` | CodeGuard rule pack |
| `ACYL_MODEL_MOCK` | `1` | Mock Antares (no GPU/HF in default image) |
| `ACYL_OFFLINE` | `1` (compose) | Prefer offline autofix patches |
| `ACYL_DASHBOARD_PORT` | `8888` | Dashboard listen port |
| `ACYL_MODEL_URL` | unset | Point at a model server if you run one |

---

## Antares / model notes

The default image sets `ACYL_MODEL_MOCK=1` so the dashboard works without downloading Antares weights.

For real Antares later:

1. Build/run with model extras (or mount cached weights into `/data/.cache/acyl/models`).
2. Start `serve-model` in a second container or process.
3. Set `ACYL_MODEL_URL=http://host.docker.internal:8080/v1` (or a compose service URL).
4. Leave **Skip Antares** unchecked in the UI (default). Nested Docker sandbox is not enabled in-container — keep **No Docker sandbox** checked (uses the in-process allowlisted shell).

---

## Air-gapped use

1. On a networked machine: `docker pull` (or `docker build`) and `docker save acyl:local | gzip > acyl.tar.gz`
2. Transfer the archive + your repo checkout
3. `gunzip -c acyl.tar.gz | docker load`
4. `docker run ...` as above — no registry access required at runtime
