"""acyl CLI."""

from __future__ import annotations

import json
import os
from pathlib import Path

import typer
from rich import print
from rich.console import Console
from rich.table import Table

from acyl import __version__
from acyl.orchestrator.scan import fix_from_run, run_scan
from acyl.paths import runs_dir
from acyl.substrate import Store

app = typer.Typer(
    name="acyl",
    help="Personal local AppSec platform (Foundry-lite + Antares + CodeGuard).",
    no_args_is_help=True,
)
console = Console()


@app.callback()
def main() -> None:
    """acyl — scan your own repos locally."""


@app.command("version")
def version_cmd() -> None:
    """Print acyl version."""
    print(__version__)


@app.command("scan")
def scan_cmd(
    path: Path | None = typer.Argument(None, help="Local repository path"),
    git_url: str | None = typer.Option(None, "--git-url", help="Clone/pin a git URL (uses host auth)"),
    goals: Path | None = typer.Option(None, "--goals", help="Path to goals.md / goals.yml"),
    revision: str | None = typer.Option(None, "--revision", help="Pin a git revision"),
    no_antares: bool = typer.Option(False, "--no-antares", help="Skip Antares localization lane"),
    llm_codeguard: bool = typer.Option(False, "--llm-codeguard", help="Enable CodeGuard LLM sweep"),
    no_docker: bool = typer.Option(False, "--no-docker", help="Force non-Docker sandbox fallback"),
    include_candidates: bool = typer.Option(
        False, "--include-candidates", help="Include untriaged candidates in report"
    ),
) -> None:
    """Pin a target and run detectors + triage + report."""
    if path is None and not git_url:
        raise typer.BadParameter("Provide PATH or --git-url")
    result = run_scan(
        path=path,
        git_url=git_url,
        goals_file=goals,
        revision=revision,
        enable_antares=not no_antares,
        enable_llm_codeguard=llm_codeguard,
        use_docker=False if no_docker else None,
        include_candidates=include_candidates,
    )
    print(f"[bold green]Scan complete[/bold green] run={result.run_id}")
    print(f"DB: {result.db_path}")
    print(f"Report: {result.report_dir / 'summary.md'}")
    print(json.dumps(result.counts, indent=2))


@app.command("status")
def status_cmd(run_id: str = typer.Argument(..., help="Run id")) -> None:
    """Show run status and finding counts."""
    db = runs_dir() / run_id / "acyl.db"
    if not db.exists():
        raise typer.Exit(code=1)
    store = Store(db)
    try:
        run = store.get_run(run_id)
        findings = store.list_findings(run_id)
        table = Table(title=f"Run {run_id}")
        table.add_column("Field")
        table.add_column("Value")
        if run:
            table.add_row("target", run["target_path"])
            table.add_row("revision", run["pinned_revision"])
            table.add_row("state", run["state"])
        from collections import Counter

        c = Counter(f["state"] for f in findings)
        for k, v in sorted(c.items()):
            table.add_row(f"findings:{k}", str(v))
        console.print(table)
    finally:
        store.close()


@app.command("report")
def report_cmd(
    run_id: str = typer.Argument(..., help="Run id"),
    open_file: bool = typer.Option(False, "--open", help="Print report path / contents"),
) -> None:
    """Show report location (and optionally print markdown)."""
    report = runs_dir() / run_id / "reports" / "summary.md"
    if not report.exists():
        print(f"[red]No report for {run_id}[/red]")
        raise typer.Exit(1)
    print(str(report))
    if open_file:
        print(report.read_text(encoding="utf-8"))


@app.command("findings")
def findings_cmd(
    run_id: str = typer.Argument(...),
    state: str | None = typer.Option(None, "--state"),
) -> None:
    """List findings for a run."""
    store = Store(runs_dir() / run_id / "acyl.db")
    try:
        rows = store.list_findings(run_id, state=state)
        table = Table(title="Findings")
        table.add_column("id")
        table.add_column("state")
        table.add_column("severity")
        table.add_column("class")
        table.add_column("path")
        table.add_column("title")
        for f in rows:
            table.add_row(
                f["id"],
                f["state"],
                str(f.get("severity") or ""),
                f["vuln_class"],
                str(f.get("path") or ""),
                f["title"][:60],
            )
        console.print(table)
    finally:
        store.close()


@app.command("fix")
def fix_cmd(
    finding_id: str = typer.Option(..., "--finding", help="Finding id"),
    run_id: str | None = typer.Option(None, "--run", help="Run id (inferred from finding prefix lookup)"),
    offline: bool = typer.Option(False, "--offline", help="Write patch only; do not push PR"),
) -> None:
    """Create a gated autofix patch/PR for a confirmed true-positive."""
    if run_id is None:
        # search runs
        for candidate in sorted(runs_dir().glob("run_*/acyl.db"), reverse=True):
            store = Store(candidate)
            try:
                if store.get_finding(finding_id):
                    run_id = candidate.parent.name
                    break
            finally:
                store.close()
    if not run_id:
        raise typer.BadParameter("Could not locate finding; pass --run")
    result = fix_from_run(run_id, finding_id, offline=offline or os.environ.get("ACYL_OFFLINE") == "1")
    print(result)


@app.command("serve-model")
def serve_model_cmd(
    host: str = typer.Option("127.0.0.1", "--host"),
    port: int = typer.Option(8080, "--port"),
    model_id: str = typer.Option("fdtn-ai/antares-350m", "--model-id"),
    mock: bool = typer.Option(False, "--mock", help="Serve deterministic mock completions (no GPU/HF)"),
) -> None:
    """Serve Antares (or a mock) on localhost OpenAI-compatible HTTP."""
    from acyl.model.server import run_server

    run_server(host=host, port=port, model_id=model_id, mock=mock)


@app.command("dashboard")
def dashboard_cmd(
    host: str = typer.Option("127.0.0.1", "--host", help="Bind address (localhost by default)"),
    port: int = typer.Option(8787, "--port"),
) -> None:
    """Open the local web dashboard for runs, findings, and scans."""
    from acyl.dashboard import run_dashboard

    print(f"[bold green]acyl dashboard[/bold green] http://{host}:{port}")
    run_dashboard(host=host, port=port)


@app.command("coverage")
def coverage_cmd(run_id: str = typer.Argument(...)) -> None:
    """Show coverage checklist for a run."""
    store = Store(runs_dir() / run_id / "acyl.db")
    try:
        table = Table(title="Coverage")
        table.add_column("goal")
        table.add_column("technique")
        table.add_column("state")
        for row in store.list_coverage(run_id):
            table.add_row(row["goal"], row["technique"], row["state"])
        console.print(table)
    finally:
        store.close()


if __name__ == "__main__":
    app()
