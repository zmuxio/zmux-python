# Releasing

This document is for maintainers. User installation instructions belong in `README.md`.

Published distributions:

- `zmuxio` (import package `zmux`)
- `zmuxio-aioquic` (import package `zmux_aioquic`)

Releases are automated from tag `vX.Y.Z`. The workflow (`.github/workflows/release.yml`) validates versions, checks
which versions PyPI already has, runs the test suite on every supported Python version, builds and checks both
distributions, installs the built wheels, publishes `zmuxio`, waits until PyPI serves it, and publishes
`zmuxio-aioquic`.

## Publishing Setup

Publishing uses PyPI Trusted Publishing (GitHub OIDC), so no PyPI token is stored in the repository. Both PyPI projects
trust owner `zmuxio`, repository `zmux-python` and workflow `release.yml`; they differ only in the GitHub environment,
because PyPI requires each pending publisher configuration to be unique:

| PyPI project     | Environment    |
|------------------|----------------|
| `zmuxio`         | `pypi`         |
| `zmuxio-aioquic` | `pypi-aioquic` |

GitHub creates both environments the first time the workflow uses them. Required reviewers can be added under
Settings → Environments to make every publish wait for approval. If the workflow file or an environment is renamed,
update the trusted publisher on PyPI in the same change.

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

Review the dependency and metadata fields before setting the release version:

- the `aioquic` requirement of `zmuxio-aioquic` and the supported `requires-python` range;
- the Python version classifiers, which should match the versions CI tests;
- the `Development Status` classifier of both distributions.

Keep Python compatibility unchanged unless that is an intentional release decision.

Update the version fields above, then verify the candidate:

```bash
python tools/check_release_version.py X.Y.Z
PYTHONPATH=src:packages/zmuxio-aioquic/src python -m unittest discover -s tests
python -m build --outdir dist/zmuxio .
python -m build --outdir dist/zmuxio-aioquic packages/zmuxio-aioquic
python -m twine check --strict dist/zmuxio/* dist/zmuxio-aioquic/*
```

The tests need `aioquic` and `cryptography` installed; building needs `build` and `twine`. `dist/` is ignored by git.

Commit and push:

```bash
git add pyproject.toml src/zmux/__init__.py packages/zmuxio-aioquic/pyproject.toml
git commit -m "release: prepare vX.Y.Z"
git push origin main
```

If the version fields already hold `X.Y.Z`, there is nothing to commit; tag the current `main`.

Tag the release:

```bash
git tag -a vX.Y.Z -m "vX.Y.Z"
git push origin vX.Y.Z
```

If the workflow fails before publishing, fix the issue, delete the failed remote tag, retag the fixed commit, and push
again. If `zmuxio` was published but `zmuxio-aioquic` was not, rerun the workflow from the same tag after fixing the
adapter-side problem; already published versions are detected and skipped. PyPI versions are immutable after
publication, and a deleted version number can never be uploaded again.

After the workflow succeeds:

```bash
python -m pip index versions zmuxio
python -m pip index versions zmuxio-aioquic
python -m pip install "zmuxio-aioquic==X.Y.Z"
```
