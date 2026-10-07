"""Check that every release version field of zmuxio and zmuxio-aioquic agrees.

Usage:
    python tools/check_release_version.py            # fields must agree
    python tools/check_release_version.py X.Y.Z      # fields must all be X.Y.Z

The release workflow passes the version from the pushed ``vX.Y.Z`` tag.
"""

from __future__ import annotations

import ast
import re
import sys
from pathlib import Path

import tomllib

ROOT = Path(__file__).resolve().parent.parent
CORE_PYPROJECT = ROOT / "pyproject.toml"
CORE_INIT = ROOT / "src" / "zmux" / "__init__.py"
ADAPTER_PYPROJECT = ROOT / "packages" / "zmuxio-aioquic" / "pyproject.toml"

_VERSION = re.compile(r"^\d+\.\d+\.\d+$")


def _requirement_floor(requirements: list[str], name: str, label: str) -> str:
    for requirement in requirements:
        match = re.fullmatch(r"\s*%s\s*>=\s*(\S+)\s*" % re.escape(name), requirement)
        if match:
            return match.group(1)
    raise SystemExit("%s: no '%s>=X.Y.Z' requirement found" % (label, name))


def _module_version(path: Path) -> str:
    for node in ast.parse(path.read_text(encoding="utf-8")).body:
        if (
                isinstance(node, ast.Assign)
                and any(isinstance(target, ast.Name) and target.id == "__version__" for target in node.targets)
                and isinstance(node.value, ast.Constant)
                and isinstance(node.value.value, str)
        ):
            return node.value.value
    raise SystemExit("%s: no __version__ string found" % path.relative_to(ROOT))


def release_fields() -> dict[str, str]:
    core = tomllib.loads(CORE_PYPROJECT.read_text(encoding="utf-8"))["project"]
    adapter = tomllib.loads(ADAPTER_PYPROJECT.read_text(encoding="utf-8"))["project"]
    return {
        "pyproject.toml version": core["version"],
        "src/zmux/__init__.py __version__": _module_version(CORE_INIT),
        "pyproject.toml aioquic extra (zmuxio-aioquic>=)": _requirement_floor(
            core["optional-dependencies"]["aioquic"], "zmuxio-aioquic", "pyproject.toml"
        ),
        "packages/zmuxio-aioquic/pyproject.toml version": adapter["version"],
        "packages/zmuxio-aioquic/pyproject.toml dependency (zmuxio>=)": _requirement_floor(
            adapter["dependencies"], "zmuxio", "packages/zmuxio-aioquic/pyproject.toml"
        ),
    }


def main(argv: list[str]) -> int:
    if len(argv) > 2:
        print(__doc__, file=sys.stderr)
        return 2
    fields = release_fields()
    expected = argv[1] if len(argv) == 2 else fields["pyproject.toml version"]
    if not _VERSION.match(expected):
        print("release version must look like X.Y.Z, got %r" % expected, file=sys.stderr)
        return 1
    mismatched = {label: value for label, value in fields.items() if value != expected}
    for label, value in fields.items():
        print("%-62s %s" % (label, value))
    if mismatched:
        print("expected every field to be %s" % expected, file=sys.stderr)
        return 1
    print("release version %s is consistent" % expected)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
