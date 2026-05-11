"""Fixture loading helpers for zmux conformance tests.

These helpers mirror Go's ``internal/testutil/fixtures.go`` for Python adapter
and conformance packages.  Values are cached by file path, but callers always
receive a deep JSON clone so one test cannot mutate another test's fixtures.
"""

from __future__ import annotations

import json
import os
import threading
import unittest
from copy import deepcopy
from pathlib import Path, PureWindowsPath
from typing import Any, Dict, List, Optional, Union

PathLike = Union[str, os.PathLike]

_FIXTURE_ENV = "ZMUX_FIXTURE_DIR"
_REQUIRED_FIXTURE_FILES = ("wire_valid.ndjson", "wire_invalid.ndjson")
_CACHE_MISSING = object()
_FIXTURE_DIR_LOCK = threading.Lock()
_FIXTURE_DIR: Optional[Path] = None
_NDJSON_CACHE: Dict[str, List[Any]] = {}
_JSON_CACHE: Dict[str, Any] = {}
_CACHE_LOCK = threading.RLock()


def locate_fixture_dir(search_from: Optional[PathLike] = None) -> Path:
    """Return the nearest valid fixture directory or raise ``SkipTest``.

    The default search follows the Go helper by accepting ``testdata/fixtures``
    below the current working directory.  It also accepts the spec repository's
    ``fixtures`` directory when ``search_from`` points at that repository.  For
    Python adapter projects that keep the generated bundle elsewhere, set
    ``ZMUX_FIXTURE_DIR`` or pass ``search_from``.
    """

    fixture_dir = _cached_fixture_dir(search_from)
    if fixture_dir is not None:
        return fixture_dir
    raise unittest.SkipTest("wire fixtures not found in testdata/fixtures")


def load_fixture_ndjson(name: PathLike, fixture_dir: Optional[PathLike] = None) -> List[Any]:
    """Load an NDJSON fixture file by name from the located fixture directory."""

    return load_ndjson(_fixture_path(name, fixture_dir))


def load_ndjson(path: PathLike) -> List[Any]:
    """Load an NDJSON file and return a clone of its parsed entries."""

    resolved = _resolve_path(path)
    cache_key = str(resolved)
    with _CACHE_LOCK:
        cached = _NDJSON_CACHE.get(cache_key)
        if cached is not None:
            return _clone_json_value(cached)

    with resolved.open("r", encoding="utf-8") as file:
        fixtures = _decode_json_sequence(file.read(), resolved)
    if not fixtures:
        raise ValueError("no fixtures loaded from %s" % resolved)

    with _CACHE_LOCK:
        _NDJSON_CACHE[cache_key] = fixtures
    return _clone_json_value(fixtures)


def read_fixture_json(name: PathLike, fixture_dir: Optional[PathLike] = None) -> Any:
    """Read a JSON fixture file by name from the located fixture directory."""

    return read_json(_fixture_path(name, fixture_dir))


def read_json(path: PathLike) -> Any:
    """Read a JSON file and return a clone of its parsed value."""

    resolved = _resolve_path(path)
    cache_key = str(resolved)
    with _CACHE_LOCK:
        cached = _JSON_CACHE.get(cache_key, _CACHE_MISSING)
        if cached is not _CACHE_MISSING:
            return _clone_json_value(cached)

    with resolved.open("r", encoding="utf-8") as file:
        value = json.load(file)

    with _CACHE_LOCK:
        _JSON_CACHE[cache_key] = value
    return _clone_json_value(value)


def clear_fixture_caches() -> None:
    """Clear fixture directory and parsed-value caches."""

    global _FIXTURE_DIR
    with _FIXTURE_DIR_LOCK:
        _FIXTURE_DIR = None
    with _CACHE_LOCK:
        _NDJSON_CACHE.clear()
        _JSON_CACHE.clear()


def _cached_fixture_dir(search_from: Optional[PathLike]) -> Optional[Path]:
    global _FIXTURE_DIR
    if search_from is not None:
        return _locate_fixture_dir(Path(search_from))
    with _FIXTURE_DIR_LOCK:
        if _FIXTURE_DIR is None:
            _FIXTURE_DIR = _locate_fixture_dir(Path.cwd())
        return _FIXTURE_DIR


def _locate_fixture_dir(search_from: Path) -> Optional[Path]:
    env_dir = os.environ.get(_FIXTURE_ENV)
    if env_dir:
        candidate = Path(env_dir)
        if _valid_fixture_dir(candidate):
            return candidate.resolve()
        return None

    base = search_from.resolve()
    if base.is_file():
        base = base.parent
    for parent in (base, *base.parents):
        for candidate in (
                parent,
                parent / "testdata" / "fixtures",
                parent / "fixtures",
        ):
            if _valid_fixture_dir(candidate):
                return candidate.resolve()
    return None


def _fixture_path(name: PathLike, fixture_dir: Optional[PathLike]) -> Path:
    name_path = Path(name)
    windows_name = PureWindowsPath(os.fspath(name))
    if (
            name_path.is_absolute()
            or name_path.anchor
            or windows_name.is_absolute()
            or windows_name.anchor
    ):
        raise ValueError("fixture name must be relative to the fixture directory")
    if ".." in name_path.parts or ".." in windows_name.parts:
        raise ValueError("fixture name must not escape the fixture directory")
    base = Path(fixture_dir).resolve() if fixture_dir is not None else locate_fixture_dir()
    resolved = _resolve_path(base / name_path)
    try:
        resolved.relative_to(base)
    except ValueError as exc:
        raise ValueError("fixture path escapes the fixture directory") from exc
    return resolved


def _valid_fixture_dir(path: Path) -> bool:
    return path.is_dir() and all(
        (path / name).is_file() for name in _REQUIRED_FIXTURE_FILES
    )


def _resolve_path(path: PathLike) -> Path:
    resolved = Path(path).resolve()
    if not resolved.is_file():
        raise FileNotFoundError(str(resolved))
    return resolved


def _decode_json_sequence(text: str, path: Path) -> List[Any]:
    decoder = json.JSONDecoder()
    fixtures: List[Any] = []
    offset = 0
    length = len(text)
    while True:
        while offset < length and text[offset].isspace():
            offset += 1
        if offset >= length:
            break
        try:
            value, offset = decoder.raw_decode(text, offset)
        except json.JSONDecodeError as exc:
            raise ValueError(
                "decode fixture entry in %s at line %d: %s"
                % (path, exc.lineno, exc)
            ) from exc
        fixtures.append(value)
    return fixtures


def _clone_json_value(value: Any) -> Any:
    return deepcopy(value)


__all__ = (
    "clear_fixture_caches",
    "load_fixture_ndjson",
    "load_ndjson",
    "locate_fixture_dir",
    "read_fixture_json",
    "read_json",
)
