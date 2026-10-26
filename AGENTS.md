# AGENTS.md

- Before you finish, formatting, lints, the type check and the tests that CI
  runs must pass, on both the abi3 and the free-threaded build.
- Stay a thin binding: protocol logic lives in the Rust crates. Python and
  native code only convert types, wrap handles and add asyncio conveniences.
- The type stubs match the extension module and `__all__`, with a docstring
  on every public item.
- Options after the first argument are keyword-only.
- Every coroutine stays cancellation-safe: a cancelled call leaves the
  session, stream or pipe usable and leaks nothing.
- Tests must not leak tasks, streams or file descriptors.
- Never commit build outputs, IDE settings or other generated files.
- Commit subjects are short, English and imperative.
- Never commit host names, IP addresses or credentials.
