import socket
import threading
import unittest

import zmux


def session_pair():
    left, right = socket.socketpair()
    result = {}

    def run_server():
        try:
            result["server"] = zmux.server(right)
        except BaseException as exc:
            result["error"] = exc

    thread = threading.Thread(target=run_server, daemon=True)
    thread.start()
    client = zmux.client(left)
    thread.join(2.0)
    if "error" in result:
        client.close()
        raise result["error"]
    if "server" not in result:
        client.close()
        raise AssertionError("server session establishment timed out")
    return client, result["server"]


class NativeSessionTest(unittest.TestCase):
    def test_native_session_is_primary_sync_session(self):
        client, server = session_pair()
        try:
            self.assertIsInstance(client, zmux.Conn)
            self.assertIsInstance(client, zmux.Session)
            self.assertIsInstance(client.stats, zmux.SessionStats)
            self.assertEqual(client.state, zmux.SessionState.READY)
            self.assertEqual(server.state, zmux.SessionState.READY)
            self.assertEqual(client.local_preface().role, zmux.Role.INITIATOR)
            self.assertEqual(server.local_preface().role, zmux.Role.RESPONDER)
            self.assertEqual(client.negotiated().local_role, zmux.Role.INITIATOR)
            self.assertEqual(server.negotiated().local_role, zmux.Role.RESPONDER)
        finally:
            client.close()
            server.close()

    def test_bidirectional_stream_roundtrip_with_metadata(self):
        client, server = session_pair()
        try:
            outbound = client.open_stream(zmux.OpenOptions(open_info=b"rpc"))
            outbound.write_final(b"hello")

            inbound = server.accept_stream(timeout=1.0)
            self.assertIsInstance(inbound, zmux.NativeStream)
            self.assertIsInstance(inbound, zmux.Stream)
            self.assertIsInstance(inbound.metadata, zmux.StreamMetadata)
            self.assertEqual(inbound.stream_id, 4)
            self.assertFalse(inbound.opened_locally)
            self.assertTrue(inbound.bidirectional)
            self.assertEqual(inbound.open_info, b"rpc")
            self.assertEqual(inbound.read_exact(5), b"hello")
            self.assertEqual(inbound.read(), b"")

            inbound.write_final(b"world")
            self.assertEqual(outbound.read_exact(5), b"world")
            self.assertEqual(outbound.read(), b"")
        finally:
            client.close()
            server.close()

    def test_unidirectional_stream_roundtrip(self):
        client, server = session_pair()
        try:
            send = client.open_uni_and_send(b"event", zmux.OpenOptions(open_info=b"uni"))
            recv = server.accept_uni_stream(timeout=1.0)
            self.assertIsInstance(send, zmux.SendStream)
            self.assertIsInstance(recv, zmux.RecvStream)
            self.assertTrue(send.write_closed)
            self.assertFalse(recv.bidirectional)
            self.assertEqual(recv.open_info, b"uni")
            self.assertEqual(recv.read(), b"event")
            with self.assertRaises(zmux.StreamNotWritable):
                recv.write(b"nope")
        finally:
            client.close()
            server.close()

    def test_ping_uses_native_session_not_adapter(self):
        client, server = session_pair()
        try:
            rtt = client.ping(b"echo", timeout=1.0)
            self.assertGreaterEqual(rtt, 0.0)
            self.assertGreaterEqual(client.stats.sent_frames, 1)
            self.assertGreaterEqual(server.stats.received_frames, 1)
        finally:
            client.close()
            server.close()


if __name__ == "__main__":
    unittest.main()
