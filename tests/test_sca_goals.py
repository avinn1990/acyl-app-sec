"""Tests for SCA severity parsing and CVE→Antares goal synthesis."""

from __future__ import annotations

import json
from pathlib import Path

from acyl.detectors.sca import (
    parse_osv_report,
    parse_osv_severity,
    vuln_to_hit,
)
from acyl.detectors.sca_goals import SCA_ANTARES_CAP, synthesize_sca_antares_goals
from acyl.orchestrator.config import ROLE_DETECTOR_ANTARES, ROLE_DETECTOR_SCA, ROLE_TRIAGER
from acyl.orchestrator.pipeline import PipelineContext, advance_after, handle_task
from acyl.substrate import Store
from acyl.target import Target


def test_parse_osv_severity_database_specific():
    assert parse_osv_severity({"database_specific": {"severity": "CRITICAL"}}) == "critical"
    assert parse_osv_severity({"database_specific": {"severity": "HIGH"}}) == "high"
    assert parse_osv_severity({"database_specific": {"severity": "MODERATE"}}) == "medium"
    assert parse_osv_severity({"database_specific": {"severity": "LOW"}}) == "low"


def test_parse_osv_severity_cvss_score_not_type():
    # Regression: type CVSS_V3 must not become severity "medium" via allowlist miss alone
    # when a numeric score is present — score drives the band.
    vuln = {
        "severity": [{"type": "CVSS_V3", "score": 9.8}],
    }
    assert parse_osv_severity(vuln) == "critical"
    vuln_high = {"severity": [{"type": "CVSS_V3", "score": 7.5}]}
    assert parse_osv_severity(vuln_high) == "high"
    vuln_med = {"severity": [{"type": "CVSS_V3", "score": 5.0}]}
    assert parse_osv_severity(vuln_med) == "medium"
    vuln_low = {"severity": [{"type": "CVSS_V3", "score": 2.1}]}
    assert parse_osv_severity(vuln_low) == "low"


def test_parse_osv_severity_defaults_medium_without_signal():
    assert parse_osv_severity({"severity": [{"type": "CVSS_V3"}]}) == "medium"
    assert parse_osv_severity({}) == "medium"


def test_vuln_to_hit_extracts_aliases_cwes_fixed():
    vuln = {
        "id": "GHSA-xxxx-yyyy-zzzz",
        "summary": "Prototype pollution",
        "aliases": ["CVE-2021-23337"],
        "database_specific": {"severity": "HIGH", "cwe_ids": ["CWE-1321"]},
        "affected": [
            {
                "ranges": [
                    {
                        "events": [
                            {"introduced": "0"},
                            {"fixed": "4.17.21"},
                        ]
                    }
                ]
            }
        ],
    }
    hit = vuln_to_hit(path="package-lock.json", package="lodash", version="4.17.15", vuln=vuln)
    assert hit.severity == "high"
    assert hit.aliases == ["CVE-2021-23337"]
    assert hit.cwes == ["CWE-1321"]
    assert hit.fixed_version == "4.17.21"
    assert hit.advisory == "GHSA-xxxx-yyyy-zzzz"


def test_parse_osv_report_all_severities():
    data = {
        "results": [
            {
                "source": {"path": "package.json"},
                "packages": [
                    {
                        "package": {"name": "a", "version": "1.0.0"},
                        "vulnerabilities": [
                            {
                                "id": "GHSA-crit",
                                "summary": "crit",
                                "database_specific": {"severity": "CRITICAL"},
                            },
                            {
                                "id": "GHSA-med",
                                "summary": "med",
                                "database_specific": {"severity": "MODERATE"},
                            },
                        ],
                    }
                ],
            }
        ]
    }
    hits = parse_osv_report(data)
    assert len(hits) == 2
    by_id = {h.advisory: h for h in hits}
    assert by_id["GHSA-crit"].severity == "critical"
    assert by_id["GHSA-med"].severity == "medium"


def _finding(
    *,
    finding_id: str,
    severity: str,
    advisory: str,
    package: str = "pkg",
    version: str = "1.0.0",
    source: str = "sca",
    cwes: list[str] | None = None,
) -> dict:
    return {
        "id": finding_id,
        "source": source,
        "severity": severity,
        "rule_id": advisory,
        "title": f"{advisory} in {package}",
        "summary": f"{package}@{version} ({advisory})",
        "symbol": f"{package}@{version}",
        "metadata_json": json.dumps(
            {
                "package": package,
                "version": version,
                "advisory": advisory,
                "aliases": [],
                "cwes": cwes or [],
                "fixed_version": None,
                "severity": severity,
            }
        ),
    }


def test_synthesize_only_high_critical_and_cap():
    findings = [
        _finding(finding_id="f1", severity="medium", advisory="GHSA-med"),
        _finding(finding_id="f2", severity="low", advisory="GHSA-low"),
        _finding(finding_id="f3", severity="high", advisory="GHSA-high", package="lodash"),
        _finding(
            finding_id="f4",
            severity="critical",
            advisory="GHSA-crit",
            package="leftpad",
            cwes=["CWE-94"],
        ),
        _finding(finding_id="f5", severity="high", advisory="GHSA-other", source="secrets"),
    ]
    goals = synthesize_sca_antares_goals(findings)
    assert len(goals) == 2
    assert goals[0]["id"] == "sca-ghsa-crit"
    assert goals[0]["cwe"] == "CWE-94"
    assert "leftpad@1.0.0" in goals[0]["body"]
    assert "GHSA-crit" in goals[0]["body"]
    assert goals[0]["metadata"]["sca_finding_id"] == "f4"
    assert goals[1]["id"] == "sca-ghsa-high"
    assert "lodash" in goals[1]["title"]


def test_synthesize_cap_40():
    findings = [
        _finding(
            finding_id=f"f{i}",
            severity="high" if i % 2 else "critical",
            advisory=f"GHSA-{i:04d}",
            package=f"pkg{i}",
        )
        for i in range(50)
    ]
    goals = synthesize_sca_antares_goals(findings)
    assert len(goals) == SCA_ANTARES_CAP
    assert SCA_ANTARES_CAP == 40
    # Criticals sorted first
    assert all(g["metadata"]["severity"] == "critical" for g in goals[:25])


def test_sca_handler_enqueues_antares_additively(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("ACYL_MODEL_MOCK", "1")
    monkeypatch.setattr("acyl.detectors.sca._osv_available", lambda: False)
    root = Path("fixtures/vulnerable-app").resolve()
    store = Store(tmp_path / "acyl.db")
    static_goals = [
        {"id": "supply-chain", "cwe": "CWE-1104", "title": "deps", "body": "review deps"},
        {"id": "injection", "cwe": "CWE-78", "title": "inj", "body": "find injection"},
    ]
    run_id = store.create_run(
        target_path=str(root),
        pinned_revision="test",
        scope={},
        goals=static_goals,
    )
    # Pre-enqueue static Antares goals (as cartographer fan-out would)
    for idx, goal in enumerate(static_goals, start=1):
        store.add_task(
            run_id,
            ROLE_DETECTOR_ANTARES,
            payload={"goal": goal, "index": idx, "total": len(static_goals)},
            priority=30,
        )
    store.add_task(run_id, ROLE_DETECTOR_SCA, payload={}, priority=30)

    target = Target(
        path=root,
        pinned_revision="test",
        git_url=None,
        scope={},
        goals=static_goals,
        goals_source="test",
    )
    ctx = PipelineContext(
        store=store,
        run_id=run_id,
        target=target,
        artifacts=tmp_path / "artifacts",
        report_dir=tmp_path / "reports",
        enable_antares=True,
        enable_llm_codeguard=False,
        use_docker=False,
        include_candidates=False,
        cancel_check=lambda: None,
    )
    ctx.artifacts.mkdir(parents=True)
    ctx.report_dir.mkdir(parents=True)

    sca_task = next(t for t in store.list_tasks(run_id) if t["role"] == ROLE_DETECTOR_SCA)
    handle_task(ctx, sca_task)
    store.complete_task(sca_task["id"])
    advance_after(ctx, ROLE_DETECTOR_SCA)

    tasks = store.list_tasks(run_id)
    antares = [t for t in tasks if t["role"] == ROLE_DETECTOR_ANTARES]
    static_ids = {
        (t.get("payload") or {}).get("goal", {}).get("id")
        for t in antares
        if (t.get("payload") or {}).get("origin") != "sca"
    }
    sca_ids = {
        (t.get("payload") or {}).get("goal", {}).get("id")
        for t in antares
        if (t.get("payload") or {}).get("origin") == "sca"
    }
    assert "supply-chain" in static_ids
    assert "injection" in static_ids
    # Fixture lodash is high via manifest fallback when osv-scanner absent
    assert any(gid and str(gid).startswith("sca-") for gid in sca_ids)
    assert ctx.counts.get("sca_antares", 0) >= 1

    # Triage must wait while Antares tasks are still open
    assert store.has_incomplete_tasks(run_id, roles=[ROLE_DETECTOR_ANTARES])
    assert not any(t["role"] == ROLE_TRIAGER for t in store.list_tasks(run_id))
    store.close()


def test_sca_handler_skips_antares_when_disabled(tmp_path: Path, monkeypatch):
    monkeypatch.setattr("acyl.detectors.sca._osv_available", lambda: False)
    root = Path("fixtures/vulnerable-app").resolve()
    store = Store(tmp_path / "acyl.db")
    run_id = store.create_run(
        target_path=str(root),
        pinned_revision="test",
        scope={},
        goals=[],
    )
    store.add_task(run_id, ROLE_DETECTOR_SCA, payload={}, priority=30)
    target = Target(
        path=root,
        pinned_revision="test",
        git_url=None,
        scope={},
        goals=[],
        goals_source="test",
    )
    ctx = PipelineContext(
        store=store,
        run_id=run_id,
        target=target,
        artifacts=tmp_path / "artifacts",
        report_dir=tmp_path / "reports",
        enable_antares=False,
        enable_llm_codeguard=False,
        use_docker=False,
        include_candidates=False,
        cancel_check=lambda: None,
    )
    sca_task = store.list_tasks(run_id)[0]
    handle_task(ctx, sca_task)
    assert not any(t["role"] == ROLE_DETECTOR_ANTARES for t in store.list_tasks(run_id))
    assert ctx.counts.get("sca_antares", 0) == 0
    store.close()
