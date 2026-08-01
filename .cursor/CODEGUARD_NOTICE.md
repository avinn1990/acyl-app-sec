# Project CodeGuard Attribution

This directory vendors security rules, a reviewer agent, and Agent Skills from
[Project CodeGuard](https://github.com/cosai-oasis/project-codeguard)
(Cisco → CoSAI / OASIS) so they travel with every clone of this repo.

| Item | Upstream source | Version |
|------|-----------------|---------|
| `.cursor/rules/`, `.cursor/agents/` | [codeguard-cursor.zip](https://github.com/cosai-oasis/project-codeguard/releases/download/v1.4.0/codeguard-cursor.zip) | v1.4.0 |
| `.cursor/skills/codeguard/` | [`skills/codeguard/`](https://github.com/cosai-oasis/project-codeguard/tree/v1.4.0/skills/codeguard) (from `codeguard-all.zip` → `dist/.agents/skills/codeguard`) | v1.4.0 |
| `.cursor/skills/security-review/` | [`sources/skills/security-review/`](https://github.com/cosai-oasis/project-codeguard/tree/v1.4.0/sources/skills/security-review) | v1.4.0 |
| `.cursor/skills/memory-safe-migration/` | [`sources/skills/memory-safe-migration/`](https://github.com/cosai-oasis/project-codeguard/tree/v1.4.0/sources/skills/memory-safe-migration) | v1.4.0 |

**License:** [Creative Commons Attribution 4.0 International (CC-BY-4.0)](https://creativecommons.org/licenses/by/4.0/)  
Upstream license text: https://github.com/cosai-oasis/project-codeguard/blob/v1.4.0/LICENSE.md

SHA256 verified against the v1.4.0 release `SHA256SUMS` for the zip assets.  
Vendored files are unmodified from upstream.

Runtime detector rules used by the `acyl` scanner also live in `/rules/` at the repo root (normalized copies of the same CodeGuard corpus).
