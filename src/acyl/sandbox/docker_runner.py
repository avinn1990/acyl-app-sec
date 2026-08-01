"""Docker sandbox with network=none for Antares terminal commands."""

from __future__ import annotations

import shutil
import subprocess
import uuid
from dataclasses import dataclass
from pathlib import Path


@dataclass
class SandboxResult:
    exit_code: int
    stdout: str
    stderr: str


ALLOWLIST_PREFIXES = (
    "ls",
    "find",
    "grep",
    "egrep",
    "fgrep",
    "rg",
    "cat",
    "head",
    "tail",
    "wc",
    "sed",
    "awk",
    "cut",
    "sort",
    "uniq",
    "file",
    "pwd",
    "basename",
    "dirname",
    "realpath",
    "stat",
    "test",
    "[",
    "echo",
    "printf",
)


class Sandbox:
    def __init__(
        self,
        target_ro: Path,
        artifacts: Path,
        *,
        image: str = "ubuntu:24.04",
        use_docker: bool | None = None,
    ) -> None:
        self.target_ro = Path(target_ro).resolve()
        self.artifacts = Path(artifacts).resolve()
        self.artifacts.mkdir(parents=True, exist_ok=True)
        self.image = image
        self.container_name = f"acyl-antares-{uuid.uuid4().hex[:10]}"
        if use_docker is None:
            use_docker = shutil.which("docker") is not None
        self.use_docker = use_docker
        self._started = False

    def start(self) -> None:
        if not self.use_docker:
            self._started = True
            return
        cmd = [
            "docker",
            "run",
            "-d",
            "--name",
            self.container_name,
            "--network",
            "none",
            "--memory",
            "4g",
            "--cpus",
            "2",
            "-v",
            f"{self.target_ro}:/workspace/repo:ro",
            "-v",
            f"{self.artifacts}:/artifacts:rw",
            "-w",
            "/workspace/repo",
            self.image,
            "sleep",
            "infinity",
        ]
        subprocess.run(cmd, check=True, capture_output=True, text=True)
        self._started = True

    def stop(self) -> None:
        if not self.use_docker or not self._started:
            return
        subprocess.run(
            ["docker", "rm", "-f", self.container_name],
            check=False,
            capture_output=True,
            text=True,
        )
        self._started = False

    def __enter__(self) -> Sandbox:
        self.start()
        return self

    def __exit__(self, *args: object) -> None:
        self.stop()

    def _allowed(self, command: str) -> bool:
        stripped = command.strip()
        if not stripped:
            return False
        # Block obvious write / network attempts
        lowered = stripped.lower()
        for banned in ("curl ", "wget ", "nc ", "ncat ", "ssh ", "scp ", ">", ">>", "rm ", "chmod "):
            if banned in lowered:
                return False
        first = stripped.split()[0]
        first = Path(first).name
        return first in ALLOWLIST_PREFIXES or first.startswith("grep")

    def exec(self, command: str, timeout: int = 30) -> SandboxResult:
        if not self._allowed(command):
            return SandboxResult(
                exit_code=126,
                stdout="",
                stderr="Command blocked by acyl sandbox allowlist / network policy.",
            )
        if not self.use_docker:
            # Local fallback for environments without Docker (still no network tools)
            result = subprocess.run(
                ["bash", "-lc", command],
                cwd=self.target_ro,
                capture_output=True,
                text=True,
                timeout=timeout,
                check=False,
            )
            return SandboxResult(result.returncode, result.stdout[-20000:], result.stderr[-8000:])
        result = subprocess.run(
            ["docker", "exec", self.container_name, "bash", "-lc", command],
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
        return SandboxResult(result.returncode, result.stdout[-20000:], result.stderr[-8000:])
