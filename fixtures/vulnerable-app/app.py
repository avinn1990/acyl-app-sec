"""Intentionally vulnerable sample application for acyl dogfood scans."""

import os
import subprocess
import hashlib


# CWE-798: hardcoded credentials (presence-is-vulnerability)
API_PASSWORD = "supersecret-demo-password"
AWS_KEY = "AKIAIOSFODNN7EXAMPLE"


def insecure_hash(value: str) -> str:
    # CWE / CodeGuard: weak crypto
    return hashlib.md5(value.encode()).hexdigest()


def run_user_command(user_input: str) -> str:
    # CWE-78: OS command injection
    return os.system("echo " + user_input)  # noqa: S605


def fetch_url(name: str) -> None:
    # Cleartext transport example
    subprocess.run(["curl", "http://example.com/api/" + name], check=False)


def main() -> None:
    print("vulnerable-app demo", insecure_hash("x"), API_PASSWORD)


if __name__ == "__main__":
    main()
