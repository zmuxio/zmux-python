# Changelog

## 0.3.0

- Typed API: `Role`, `SessionState`, `Direction`, `PipeState`, `ErrorKind`
  and other `StrEnum`s; `Priority`, `Tlv`, `Preamble`, `PipePolicy`,
  `PipeStats`, `SessionStats` and `CloseInfo` value types.
- Session events as dataclasses: `await session.next_event()` and
  `async for event in session.events()`; `session.datagrams()` iterates
  received datagrams; `session.stats()`.
- `async with` on `SendStream` (finish, or reset on error), `RecvStream`
  (stop on error) and `Pipe` (close, or abort on error); `async for chunk in
  recv`. `RecvStream.preamble` is a property; `SendStream.priority` is
  readable.
- Carrier entry points take the address first and keyword-only options:
  `connect_x(target, *, tls=None, config=None, ...)`, `dial_x(...)`,
  `Listener.serve_x(addr, *, ...)`. `tls` defaults to the bundled web roots
  and `server_name` to the address's host. WebSocket `headers` accept a
  mapping.
- `QuicClient.connect()` returns the session; its 0-RTT report is
  `session.zero_rtt`.
- `wait_closed()` returns `CloseInfo`; `SessionClosed` carries `reason` and
  `remote`. `EarlyDataRejected` derives from `ZmuxError`. New
  `LimitExceeded` (`read_to_end` limit) and `ListenerClosed`
  (`Listener.accept()` after close).
- `Config` is a frozen dataclass with `replace()`; durations accept
  `timedelta`.
- `StreamWriter` sends in the background with `drain()` backpressure and
  adds `writelines`, `write_eof`, `can_write_eof`, `is_closing` and
  `get_extra_info`.
- Pipe multipath settings use `PipePolicy` (`add_pipe`, `reserve_pipe`,
  `Pipe.set_policy`, `Pipe.policy`).
- Wheels for more Linux architectures and 32-bit Windows.
