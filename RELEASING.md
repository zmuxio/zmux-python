# Releasing

This document is for maintainers. User installation instructions belong in `README.md`.

Published distribution: `zmuxio` (import package `zmux`), a maturin/PyO3 extension module.

Releases are automated from tag `vX.Y.Z`. The workflow (`.github/workflows/release.yml`) validates versions, checks
whether PyPI already has the version, builds the wheel matrix (manylinux, musllinux, macOS and Windows) and the sdist,
tests the wheels, and publishes `zmuxio`. A manual `workflow_dispatch` run builds and checks everything without
publishing.

## Publishing Setup

Publishing uses PyPI Trusted Publishing (GitHub OIDC), so no PyPI token is stored in the repository. The `zmuxio` PyPI
project trusts owner `zmuxio`, repository `zmux-python`, workflow `release.yml` and environment `pypi`.

GitHub creates the environment the first time the workflow uses it. Required reviewers can be added under
Settings → Environments to make every publish wait for approval. If the workflow file or the environment is renamed,
update the trusted publisher on PyPI in the same change.

## Version Rules

These fields must hold the same version:

- `pyproject.toml` project version: `X.Y.Z`
- `Cargo.toml` package version: `X.Y.Z`
- `python/zmux/__init__.py` `__version__`: `X.Y.Z`
- Git tag: `vX.Y.Z`

The release workflow compares the tag with these fields and fails on any mismatch.

## Release

```bash
git status --short --branch
git fetch origin
git rev-list --left-right --count main...origin/main
```

The ahead/behind count should be `0 0`.

Review the metadata before setting the release version: `requires-python`, the Python version classifiers (they should
match the versions CI tests) and the `Development Status` classifier. Keep Python compatibility unchanged unless that
is an intentional release decision.

Update the version fields above, then commit and push:

```bash
git add pyproject.toml Cargo.toml Cargo.lock python/zmux/__init__.py
git commit -m "release: prepare vX.Y.Z"
git push origin main
```

Wait for CI on `main` to pass. If the version fields already hold `X.Y.Z`, there is nothing to commit; tag the current
`main` once its CI is green.

Tag the release:

```bash
git tag -a vX.Y.Z -m "vX.Y.Z"
git push origin vX.Y.Z
```

If the workflow fails before publishing, fix the issue, delete the failed remote tag, retag the fixed commit, and push
again. PyPI versions are immutable after publication, and a deleted version number can never be uploaded again.

After the workflow succeeds:

```bash
python -m pip index versions zmuxio
python -m pip install "zmuxio==X.Y.Z"
```
