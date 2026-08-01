# Foundry clarifications — acyl personal local AppSec

Status: clarified for acyl-app-sec v0.1 (personal/local tool).

## Identity & scope

- **System name:** acyl
- **Operator:** single human on their own machine
- **Targets:** git checkouts the operator is authorized to evaluate (public or private)
- **Authorization model:** local path or host-authenticated `git`/`gh` clone; no SaaS install on target orgs

## Integration choices

| Surface | Choice |
|---|---|
| Datastore | SQLite WAL on operator disk (`~/.cache/acyl/runs/`) |
| LLM (localization) | Local Antares-350M via `acyl serve-model` on `127.0.0.1` |
| LLM (autofix) | Optional separate localhost model (`ACYL_FIX_MODEL_URL`); deterministic fixes first |
| Issue tracker | Local Markdown + SARIF reports; optional GitHub draft PRs for fixes only |
| Isolation | Docker `network=none` for Antares terminal agent; host scanners for secrets/SCA |
| Vector search | Disabled in v1 |

## Extension roles

| Role | Enabled? |
|---|---|
| Validator / exploited flag | No (no disposable testbed in v1) |
| Autofix | Yes, gated on confirmed true-positives |
| Self-improver | No (rule-gap records only) |
| Variant-hunter | No |

## Policy

- Detectors never open GitHub Issues
- Antares never generates patches
- Fingerprints exclude line numbers
- Private source never leaves the operator machine for inference
