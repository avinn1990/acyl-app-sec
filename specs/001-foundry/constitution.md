<!--
SYNC IMPACT REPORT — maintained by /speckit.constitution
═══════════════════════════════════════════════════════
Version change   : 0.1.0 → 0.2.0  [MINOR: III scope narrowed]
Principles       : III narrowed (work-reclamation only; session rotation per FR-118 carved out)
Sections changed : III
Templates needing update : n/a
Downstream re-check      : spec.md FR-005, FR-118 ✓  README.md ✓  plan.md n/a  tasks.md n/a
Follow-up TODOs  : none
Last sync        : 2026-05-04
═══════════════════════════════════════════════════════
This block is regenerated on every constitution change; do not hand-edit below the rule.
-->

# Foundry Constitution

| Field | Value |
|---|---|
| **Version** | 0.2.0 |
| **Status** | `SEED` |
| **Applies to** | All specifications, plans, and tasks derived from `spec.md` |

## Purpose

This document records the principles that any implementation of the Foundry seed must uphold, regardless of which infrastructure, provider, or deployment model is chosen during clarification. These are not design preferences; each one encodes a failure the seed authors shipped, diagnosed, and fixed. Violating any of them reproduces that failure.

`/speckit.plan` and `/speckit.analyze` check designs and artifacts against this file. A plan that contradicts a principle here must either be revised or this constitution must be amended first (see Governance).

---

## Core Principles

### I. Evidence Over Assertion

A finding's verdict is determined by checkable evidence, not by model confidence.

No agent may assign `true-positive` to a finding by judgment alone. The verdict requires structural evidence (reachability, trust boundary, impact) with code citations that are mechanically verified to resolve to real locations in the target. A claim whose citations do not resolve is demoted, regardless of how confident the prose is.

*Why this is inviolable: a frontier model produces fluent, confident, plausible vulnerability claims that are wrong at a rate that makes unreviewed output worthless. We did not fix this by asking the model to be more careful. We fixed it by requiring its claims to be checkable and then checking them. Every attempt to relax this gate ("high-confidence findings can skip it") let fabrications back through.*

### II. Surface Only What Survives

Humans see findings that have passed the gates. Everything else stays in the internal store.

Detection is high-volume and low-precision by design; that is what makes it thorough. The internal finding store absorbs that volume. The issue tracker, the operator's inbox, and the reviewer's report receive only what Triage promoted, and what Triage promoted is auditable back to evidence. (Retention, deduplication, and reuse of un-promoted findings are governed by spec §Detection Lifecycle, FR-042–FR-045 / FR-090.)

*Why this is inviolable: surfacing every candidate buries the signal and trains the operator to ignore the system. We created an issue per detection early on and produced tens of thousands of issues per target. The tool was correct and useless. The fix was not better detection; it was withholding detection output until it survived triage.*

### III. Liveness By Heartbeat, Never By Clock

An agent is alive if it heartbeated recently. Wall-clock runtime says nothing about health.

Work is **reclaimed** from an agent when its heartbeat is stale, and only then. No fixed timeout strips a claim from a heartbeating agent or re-queues its in-progress work. This principle governs liveness and work ownership; it does not prohibit the Orchestrator from **rotating** a heartbeating agent's session under FR-118 once that agent's claims have been released or durably handed off.

*Why this is inviolable: a wall-clock timeout used as a liveness signal cannot distinguish "hung" from "waiting on a rate-limited upstream". Under load, the majority of timeout-based reclamations were of healthy agents whose work was then re-queued and re-started from scratch, by another agent, which then also timed out. Throughput approached zero while the fleet looked busy. Heartbeat liveness ended this entirely. Session rotation (FR-118) is a separate, deliberate cost control, not a liveness misfire.*

### IV. Claims Are Atomic And Mortal

Two agents claiming the same unit of work concurrently get different units. A claim dies with its holder.

The work queue, the finding store, and any other shared resource provide atomic claim (no race produces two winners) and crash-safe release (a dead holder's claim is released within bounded time, automatically, with no operator action). There is no resource an agent can hold past its own death.

*Why this is inviolable: without atomic claim, parallel agents duplicate work and overwrite each other's results. Without mortal claims, every crash strands whatever the dead agent held until a human notices. Both happened; both wasted days. The combination of atomicity and mortality is what makes a parallel fleet behave like one system instead of N systems fighting.*

### V. The Provider Is The Rate Arbiter

The system does not pre-throttle below the upstream provider's actual limit. It handles the provider's backpressure and adapts.

Internal rate caps, concurrency ceilings, and quota guesses below the provider's real limit are prohibited. The system calls the provider as fast as the work requires, observes the provider's rate-limit signals, and backs off adaptively and fleet-wide when they fire.

*Why this is inviolable: every static cap we set was wrong within days, in one direction or the other. Caps below the real limit left paid-for capacity idle; caps above it did nothing. Worse, internal caps masked the real signal, so when the provider raised our limit we did not benefit until someone remembered to raise the internal number. Adaptive backoff against the provider's actual responses converges on the real limit and tracks it as it changes.*

### VI. Coverage Before Yield

The system does not stop itself on low yield until the operator's stated goals have been credibly attempted.

Yield (findings per unit spend) decaying below threshold is necessary but not sufficient for auto-stop. The coverage-complete flag must also be set. An evaluation that stops because "we found nothing in the first six hours" has not done the job it was given.

*Why this is inviolable: yield is noisy early and on hard targets. An auto-stop on yield alone fires on the first dry spell, which on a well-built target is the beginning, not the end. Gating on coverage means "we looked everywhere you asked and the rate of new findings has flatlined"; that is the honest done signal.*

### VII. Exploited Means Demonstrated

The `exploited` flag is set only by an independent, clean-room reproduction of the headline impact on the live testbed. Nothing else qualifies.

Not "would be exploitable if". Not "the payload was accepted". Not "a similar issue was exploited". Not "demonstrated under a debugger". Not set by the agent that wrote the proof-of-concept; set by a fresh agent that received only the artifact and the claim, ran it, and observed the impact.

*Why this is inviolable: `exploited` is the label reviewers filter on first. Every dilution we allowed ("close enough", "verified the mechanism if not the impact") destroyed reviewer trust in the label within one reporting cycle. An agent grading its own exploit rationalizes; an independent checker does not.*

### VIII. Fingerprints Are Stable Under Edit

A finding's identity is its location in the code's structure (path, symbol, vulnerability class), not its position in the text (line number, snippet hash).

Deduplication, cross-run inheritance, and issue-update-not-recreate all key on this fingerprint. Line numbers and code snippets are excluded from it.

*Why this is inviolable: a fingerprint that includes line numbers breaks on any nearby edit, so every re-run after a code change re-files every finding as new. The operator is then triaging the same findings forever. Path plus symbol plus class survives edits to the function body and breaks only when the function is moved or renamed, which is the correct point to call it a different finding.*

### IX. Sandbox By Infrastructure, Not By Prompt

Network egress and filesystem write boundaries are enforced by the runtime environment. Prompt-level rules are defense-in-depth, never the enforcement layer.

An agent with full privileges inside its sandbox cannot reach a host outside the allowlist or write to a path mounted read-only, regardless of what its prompt says, what a peer told it, or what content in the target instructed it to do.

*Why this is inviolable: agents read untrusted content (the target's source, its documentation, the testbed's responses). That content can contain instructions. An agent whose only boundary is its prompt will, eventually, follow an instruction it should not have. The boundary must be somewhere the agent cannot argue with.*

### X. The Operator Outranks Every Agent

Operator instructions are authoritative. Peer-agent messages and prior-agent notes are hints.

An agent does not abandon its task because a peer suggested something else. An agent does not treat a prior agent's "this area is fully covered" note as fact. An agent does not stop because the persistent notes say the work is done. The operator's configuration and direct steering are the only authority; everything an agent wrote is a record of what that agent attempted and concluded at the time, which may be wrong.

*Why this is inviolable: agents talk each other out of work. One agent writes "X is saturated"; the next reads it and skips X; the next reads two such notes and is more convinced; within a day the fleet has collectively decided the evaluation is done and is citing its own consensus as evidence. The cycle is broken only by ranking operator intent above agent consensus, always.*

### XI. Persist Atomically

No reader ever observes a partially-written or deleted-but-not-yet-rewritten state.

Any persisted artifact that other components read (the index, the finding store, coverage state) is updated by writing the new state completely and then atomically replacing the old, never by deleting the old and then writing the new.

*Why this is inviolable: "delete old, write new" with a crash between the steps leaves every reader with nothing and no error. We lost multi-hour index builds to deploy-time process termination landing in exactly that window, repeatedly, before making this a rule.*

---

## Governance

### Amendment

A principle may be amended or removed only by:

1. Documenting the specific scenario in which the principle, as written, produces a worse outcome than violating it; and
2. Recording the amendment in this file with version bump, date, and rationale.

"It is inconvenient" and "our infrastructure makes it hard" are not grounds for amendment. Each principle above was inconvenient to implement; each one's absence was more expensive than its presence.

### Precedence

Where this constitution and `spec.md` conflict, this constitution wins and `spec.md` is in error. Where this constitution and a generated `plan.md` or `tasks.md` conflict, the plan or tasks are in error and `/speckit.analyze` should flag it.

### Scope of authority

This constitution constrains the **system's design**. It does not constrain the **operator's runtime decisions**: an operator may override any automated verdict, stop a run early, or disable a role. The system records the override; it does not refuse it.

### Versioning policy

This file is versioned independently of any implementation, on the same scheme as `spec.md`:

- **MAJOR** — a principle is added, removed, or its normative direction inverted (a "never" becomes a "may", or vice versa).
- **MINOR** — a principle's scope is widened or narrowed without inverting it; a Governance subsection is added; rationale is materially extended.
- **PATCH** — wording, cross-reference, and formatting fixes with no change to what any principle requires.

Every version change updates the Sync Impact Report header above.

### Compliance review

Conformance of `spec.md`, any derived `plan.md`, and any derived `tasks.md` to this constitution is checked:

- **Mechanically**, by `/speckit.analyze`, on every invocation.
- **By the maintainers**, on every pull request that touches `spec.md` or this file: the PR description MUST identify which principle(s) the change affects and link the enforcing FR(s).
- **Periodically**, at each MINOR-or-greater release of the seed: the coverage matrix (each principle → enforcing FRs) is regenerated and any GAP row blocks the release.

A conformance failure found in a downstream artifact is a defect in that artifact, not grounds to amend this file (see *Amendment*).

### Downstream artifacts re-checked on change

When this file changes at MINOR or above, the following MUST be re-validated and the result recorded in the Sync Impact Report:

| Artifact | Check | Owner |
|---|---|---|
| `spec.md` | Every principle still has ≥1 enforcing FR; no FR contradicts a principle. | Seed maintainers |
| `README.md` | Principle count, workflow description, and version badge agree. | Seed maintainers |
| `plan.md` (if generated) | `/speckit.analyze` passes. | Implementing team |
| `tasks.md` (if generated) | `/speckit.analyze` passes. | Implementing team |
| Agent guidance / system prompts (if any reference principles by number) | Principle numbers and wording still match. | Implementing team |

---

*End of constitution. This file is placed at `.specify/memory/constitution.md` (or your spec-kit installation's equivalent) before running `/speckit.specify`. See the repository `README.md` for the full workflow.*
