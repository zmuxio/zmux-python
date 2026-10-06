# Releasing

This document is for maintainers. User installation instructions belong in `README.md`.

Published distributions:

- `zmuxio` (import package `zmux`)
- `zmuxio-aioquic` (import package `zmux_aioquic`)

Releases are automated from tag `vX.Y.Z`. The workflow (`.github/workflows/release.yml`) validates versions, runs the
test suite on every supported Python version, builds and checks both distributions, publishes `zmuxio`, waits until
PyPI serves it, and publishes `zmuxio-aioquic`.

Publishing uses PyPI Trusted Publishing (GitHub OIDC), so no PyPI token is stored in the repository. Each PyPI project
has a trusted publisher with owner `zmuxio`, repository `zmux-python`, workflow `release.yml` and environment `pypi`.

## Version Rules

Both distributions are released together with the same version:

- `pyproject.toml` project version: `X.Y.Z`
- `pyproject.toml` `aioquic` extra: `zmuxio-aioquic>=X.Y.Z`
- `src/zmux/__init__.py` `__version__`: `X.Y.Z`
- `packages/zmuxio-aioquic/pyproject.toml` project version: `X.Y.Z`
- `packages/zmuxio-aioquic/pyproject.toml` dependency: `zmuxio>=X.Y.Z`
- Git tag: `vX.Y.Z`

`python tools/check_release_version.py` checks that these fields agree; CI runs it on every push, and the release
workflow runs it with the tag version.

## Release

```bash
git status --short --branch
git fetch origin
git rev-list --left-right --count main...origin/main
```

The ahead/behind count should be `0 0`.

Update the version fields above, then check, commit and push:

```bash
python tools/check_release_version.py X.Y.Z
git add pyproject.toml src/zmux/__init__.py packages/zmuxio-aioquic/pyproject.toml
git commit -m "release: prepare vX.Y.Z"
git push origin main
```

Tag the release:

```bash
git tag -a vX.Y.Z -m "vX.Y.Z"
git push origin vX.Y.Z
```

If the workflow fails before publishing, fix the issue, delete the failed remote tag, retag the fixed commit, and push
again. If `zmuxio` was published but `zmuxio-aioquic` was not, rerun the workflow from the same tag after fixing the
adapter-side problem; already published files are skipped. PyPI versions are immutable after publication.

After the workflow succeeds:

```bash
python -m pip index versions zmuxio
python -m pip index versions zmuxio-aioquic
```
