"""Multi-agent worker concurrency limits (Foundry-lite)."""

from __future__ import annotations

# Max concurrent workers per agent family.
# Detectors share one pool of size 2; every other role is single-threaded.
MAX_WORKERS: dict[str, int] = {
    "indexer": 1,
    "cartographer": 1,
    "detector": 2,
    "triager": 1,
    "reporter": 1,
}

ROLE_INDEXER = "indexer"
ROLE_CARTOGRAPHER = "cartographer"
ROLE_DETECTOR_SECRETS = "detector.secrets"
ROLE_DETECTOR_SCA = "detector.sca"
ROLE_DETECTOR_CODEGUARD = "detector.codeguard"
ROLE_DETECTOR_ANTARES = "detector.antares"
ROLE_DETECTOR_CODEGUARD_LLM = "detector.codeguard_llm"
ROLE_TRIAGER = "triager"
ROLE_REPORTER = "reporter"

DETECTOR_ROLES: tuple[str, ...] = (
    ROLE_DETECTOR_SECRETS,
    ROLE_DETECTOR_SCA,
    ROLE_DETECTOR_CODEGUARD,
    ROLE_DETECTOR_ANTARES,
    ROLE_DETECTOR_CODEGUARD_LLM,
)

# Lower priority value = claimed sooner.
PRIORITY = {
    ROLE_INDEXER: 10,
    ROLE_CARTOGRAPHER: 20,
    ROLE_DETECTOR_SECRETS: 30,
    ROLE_DETECTOR_SCA: 30,
    ROLE_DETECTOR_CODEGUARD: 30,
    ROLE_DETECTOR_ANTARES: 30,
    ROLE_DETECTOR_CODEGUARD_LLM: 35,
    ROLE_TRIAGER: 40,
    ROLE_REPORTER: 50,
}

# Heartbeat older than this → reclaim (constitution III: liveness by heartbeat).
STALE_CLAIM_SECONDS = 90.0
WORKER_IDLE_SLEEP = 0.05
