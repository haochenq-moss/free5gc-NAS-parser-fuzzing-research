"""Command-line entry point for the free5GC security lab."""

from __future__ import annotations

import argparse
import shutil
import subprocess
import sys
from pathlib import Path

REPOSITORY = "https://github.com/free5gc/free5gc.git"


def _root() -> Path:
    return Path(__file__).resolve().parents[2]


def doctor() -> int:
    checks = {
        "python3": sys.executable,
        "git": shutil.which("git"),
        "go": shutil.which("go"),
        "docker": shutil.which("docker"),
        "docker-compose": shutil.which("docker-compose"),
    }
    print("free5GC security lab prerequisites")
    for name, value in checks.items():
        status = "available" if value else "missing"
        print("  {:16} {}".format(name, status))
    print("\nA missing Go or Docker installation prevents running free5GC, but not the lab tests.")
    return 0


def bootstrap(ref: str) -> int:
    if not ref.strip():
        print("error: --ref must be a tag or commit for reproducibility", file=sys.stderr)
        return 2
    destination = _root() / "vendor" / "free5gc"
    if destination.exists():
        print("error: destination already exists: {}".format(destination), file=sys.stderr)
        return 2
    destination.parent.mkdir(parents=True, exist_ok=True)
    command = ["git", "clone", "--depth", "1", "--branch", ref, REPOSITORY, str(destination)]
    print("Preparing free5GC checkout at {}".format(destination))
    try:
        subprocess.run(command, check=True)
    except (OSError, subprocess.CalledProcessError) as error:
        print("bootstrap failed: {}".format(error), file=sys.stderr)
        return 1
    print("Checkout prepared. Record the resolved commit before experiments.")
    return 0


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(prog="free5gc-lab")
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("doctor", help="check local prerequisites")
    bootstrap_parser = commands.add_parser("bootstrap", help="clone a pinned free5GC checkout")
    bootstrap_parser.add_argument("--ref", required=True, help="free5GC tag or commit ref")
    args = parser.parse_args(argv)
    if args.command == "doctor":
        return doctor()
    return bootstrap(args.ref)


if __name__ == "__main__":
    raise SystemExit(main())
