import sys
import unittest

from zmux._runtime.keepalive import (
    DEFAULT_KEEPALIVE_TIMEOUT_MAX,
    DEFAULT_KEEPALIVE_TIMEOUT_MIN,
    KEEPALIVE_JITTER_GAMMA,
    MAX_UINT64,
    PING_NONCE_BYTES,
    PingPayloadFingerprint,
    average_u64_floor,
    build_padded_ping_echo,
    build_ping_payload,
    effective_keepalive_timeout,
    fill_ping_padding_from_state,
    has_ping_padding_tag,
    init_keepalive_jitter_state,
    keepalive_timeout_rtt_floor,
    make_ping_padding,
    next_uint64n_from_state,
    ping_padding_bounds,
    ping_padding_tag,
    ping_payload_hash,
    ping_payload_len,
    ping_payload_limit,
    pong_payload_for_ping,
    pong_payload_matches_ping,
    rate_bytes_per_second,
    send_rate_sample,
    saturating_duration_mul_add,
    splitmix64_from_state,
)
from zmux.config import Settings


class Holder(object):
    ping_padding = True
    ping_padding_min = 8
    ping_padding_max = 8
    last_ping_padding_len = 0
    ping_nonce_state = 1
    keepalive_jitter_state = 1


class RuntimeKeepaliveTest(unittest.TestCase):
    def test_ping_payload_and_fingerprint_helpers_match_rust_liveness(self) -> None:
        nonce = 0x0102030405060708
        payload = build_ping_payload(b"abc", nonce)

        self.assertEqual(ping_payload_len(3), PING_NONCE_BYTES + 3)
        self.assertEqual(payload[:PING_NONCE_BYTES], nonce.to_bytes(8, "big"))
        self.assertEqual(ping_payload_hash(payload), ping_payload_hash(payload))
        self.assertTrue(PingPayloadFingerprint.from_payload(payload).matches(payload))
        self.assertFalse(PingPayloadFingerprint.from_payload(payload).matches(payload + b"x"))
        self.assertTrue(
            PingPayloadFingerprint.from_payload(
                payload,
                allow_padding=True,
            ).matches(payload + b"x")
        )
        self.assertFalse(pong_payload_matches_ping(payload + b"x", payload))
        self.assertTrue(
            pong_payload_matches_ping(payload + b"x", payload, allow_padding=True)
        )

    def test_ping_padding_tag_bounds_and_pong_padding(self) -> None:
        key = 0xABC
        local = Settings(ping_padding_key=key)
        peer = Settings(ping_padding_key=key)
        holder = Holder()

        tag = ping_padding_tag(key, 7)
        payload = build_ping_payload(tag.to_bytes(8, "big") + b"hi", 7)
        self.assertTrue(has_ping_padding_tag(payload, key))
        self.assertEqual(ping_padding_bounds(4, 16, 64), (4, 4))

        echo, padded = build_padded_ping_echo(holder, local, peer, b"hi", 7)
        self.assertTrue(padded)
        ping = build_ping_payload(echo, 7)
        self.assertTrue(has_ping_padding_tag(ping, key))
        pong = pong_payload_for_ping(holder, local, peer, ping)
        self.assertGreaterEqual(len(pong), len(ping))

        zero_limit = Settings(max_control_payload_bytes=0, ping_padding_key=key)
        self.assertEqual(ping_payload_limit(zero_limit, zero_limit), 0)
        self.assertEqual(
            ping_payload_limit(
                Settings(max_control_payload_bytes=0),
                Settings(max_control_payload_bytes=32),
            ),
            32,
        )
        zero_echo, zero_padded = build_padded_ping_echo(
            holder, zero_limit, zero_limit, b"", 7
        )
        self.assertFalse(zero_padded)
        self.assertFalse(has_ping_padding_tag(build_ping_payload(zero_echo, 7), key))

    def test_jitter_padding_and_uint64_boundaries_are_strict(self) -> None:
        holder = Holder()
        first_state = (1 + KEEPALIVE_JITTER_GAMMA) & MAX_UINT64
        second_state = (first_state + KEEPALIVE_JITTER_GAMMA) & MAX_UINT64
        self.assertEqual(
            fill_ping_padding_from_state(9, holder),
            splitmix64_from_state(first_state).to_bytes(8, "big")
            + splitmix64_from_state(second_state).to_bytes(8, "big")[:1],
        )
        self.assertEqual(next_uint64n_from_state(holder, 1), 0)

        with self.assertRaises(TypeError):
            init_keepalive_jitter_state(True)
        with self.assertRaises(OverflowError):
            init_keepalive_jitter_state(MAX_UINT64 + 1)
        with self.assertRaises(ValueError):
            next_uint64n_from_state(holder, -1)
        with self.assertRaises(ValueError):
            fill_ping_padding_from_state(-1, holder)
        with self.assertRaises(ValueError):
            ping_payload_len(-1)
        with self.assertRaises(TypeError):
            build_ping_payload(b"", True)
        with self.assertRaises(TypeError):
            build_ping_payload(8, 1)
        with self.assertRaises(TypeError):
            build_padded_ping_echo(holder, Settings(), Settings(), 8, 1)
        with self.assertRaises(TypeError):
            pong_payload_for_ping(holder, Settings(), Settings(), 8)
        with self.assertRaises(OverflowError):
            ping_payload_len(sys.maxsize)
        with self.assertRaises(TypeError):
            ping_padding_tag(True, 1)
        with self.assertRaises(ValueError):
            ping_padding_bounds(-1)
        with self.assertRaises(TypeError):
            PingPayloadFingerprint.from_payload(b"12345678", allow_padding=1)

        holder.ping_padding = 1
        with self.assertRaises(TypeError):
            make_ping_padding(holder, 16)

    def test_keepalive_timeout_and_send_rate_follow_rust_edges(self) -> None:
        self.assertEqual(effective_keepalive_timeout(0.0), 0.0)
        self.assertEqual(effective_keepalive_timeout(0.0, 10.0), 0.0)
        self.assertEqual(effective_keepalive_timeout(0.5), DEFAULT_KEEPALIVE_TIMEOUT_MIN)
        self.assertEqual(effective_keepalive_timeout(float("inf")), DEFAULT_KEEPALIVE_TIMEOUT_MAX)
        self.assertEqual(
            effective_keepalive_timeout(1.0, 0.0, float("inf")),
            DEFAULT_KEEPALIVE_TIMEOUT_MAX,
        )
        self.assertEqual(keepalive_timeout_rtt_floor(0.0), 0.0)
        self.assertGreater(keepalive_timeout_rtt_floor(1.0), 4.0)

        self.assertEqual(send_rate_sample(1024, 0.001), 0)
        self.assertEqual(send_rate_sample(4096, 1.0), 4096)
        self.assertEqual(rate_bytes_per_second(8192, 2.0), 4096)
        self.assertEqual(rate_bytes_per_second(sys.maxsize, 1e-9), MAX_UINT64)
        self.assertEqual(average_u64_floor(4096, 8192), 6144)
        self.assertEqual(average_u64_floor(8193, 4096), 6144)
        self.assertEqual(
            saturating_duration_mul_add(float("inf"), 2, 0.0),
            ((1 << 63) - 1) / 1_000_000_000,
        )


if __name__ == "__main__":
    unittest.main()
