# AGENTS.md

- Before you finish, `cargo fmt --check` must print nothing, and
  `cargo clippy --locked --all-targets -- -D warnings`,
  `mypy --strict python/zmux` and `pytest -q tests` on both the abi3 build
  (Python 3.12) and the free-threaded build (3.14t) must pass.
- Stay a thin binding: protocol logic lives in the Rust crates. Python and
  PyO3 code only convert types, wrap handles and add asyncio conveniences.
- Typed values (enums, dataclasses, events) live in `python/zmux/_types.py`;
  native classes and functions are declared with docstrings in
  `python/zmux/_zmux.pyi`, which must match the extension and `__all__`.
- Options after the first argument are keyword-only.
- Every coroutine stays cancellation-safe: a cancelled call leaves the
  session, stream or pipe usable and leaks nothing.
- Tests must not leak tasks, streams or file descriptors.
- Commit subjects are short, English and imperative.
- Never commit host names, IP addresses or credentials.
