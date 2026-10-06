# Vendored zmux-spec fixture bundle

This directory is a byte-for-byte copy of `zmux-spec/fixtures/*`. It is test input, not a second source of protocol
truth: `zmux-spec` stays authoritative for the fixture format and the expected behavior. It is not part of the
`zmuxio` sdist or wheel (`MANIFEST.in` prunes `testdata`).

`zmux_testing.locate_fixture_dir()` finds this directory from the repository root; set `ZMUX_FIXTURE_DIR` to run the
tests against another bundle.

## Files and the tests that run them

All tests live in `tests/test_spec_fixtures.py`.

- `wire_valid.ndjson`: `WireValidFixtureTest`
  - decodes every preface and frame with each reader and checks every `expect` field (an unknown field fails);
  - re-encodes it and compares the bytes. A padded preface is re-encoded with its padding TLV; the
    empty-padding vector is compared as the unpadded encoding plus its 2-byte padding TLV, because an empty padding
    TLV cannot be requested from the encoder.
- `wire_invalid.ndjson`: `WireInvalidFixtureTest`
  - every codec reader (`parse_frame`, `read_frame`, the session frame reader, or the varint readers for
    `bytes_invalid`) fails with the fixture code;
  - every `frame_invalid` vector makes a live session send `CLOSE` with that code.
- `invalid_cases.ndjson`: `InvalidCaseFixtureTest`
  - every id needs an explicit runner in `_INVALID_CASE_RUNNERS`, so an unmapped id fails, and a runner without a
    vendored fixture fails `FixtureBundleTest`;
  - the expected code or action always comes from the fixture, with no local overrides;
  - session- and stream-scope cases run on the wire: a raw peer (role initiator, so the Python session is the
    responder) sends the frames over `socket.socketpair`, and preface cases also establish a real session.
- `state_cases.ndjson`: `PortableStateFixtureTest` runs the `portable_state` case set (`examples/fixture_mapping.md`
  section 2.1). The other state cases are reference-harness labels and are only inventoried.
- `case_sets.json` and `index.json`: `FixtureBundleTest` checks that record counts match `index.json`, fixture ids
  are globally unique, every case-set id resolves, and `codec_valid` / `codec_invalid` equal the wire bundles.

## Refreshing

Copy `zmux-spec/fixtures/*` over the bundle files here, then run the test suite. Run it with
`ZMUX_SPEC_ROOT=/path/to/zmux-spec` as well; `FixtureBundleTest` then fails if any vendored file differs from that
checkout.

A new `invalid_cases` id needs a runner. A new portable event or result needs handling in the portable_state runner.
