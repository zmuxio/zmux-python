"""Install the requirements for building the wheel with the current interpreter."""

import subprocess
import sys
import tomllib
from pathlib import Path

project = Path(__file__).resolve().parents[1] / "pyproject.toml"
with project.open("rb") as file:
    requirements = tomllib.load(file)["build-system"]["requires"]
subprocess.run(
    [sys.executable, "-m", "pip", "install", *requirements], check=True, timeout=180
)
