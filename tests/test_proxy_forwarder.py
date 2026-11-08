import asyncio
import base64
import os
import pathlib
import socket
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))
import proxy_forwarder as pf

GOOD = base64.b64encode(b"me@corp.example:secret").decode()


class FakeCorporateProxy:
    """Requires Basic auth; answers CONNECT with an echo tunnel and GET with a body."""

    def __init__(self):
        self.heads = []

    async def handle(self, reader, writer):
        try:
            head = (await reader.readuntil(b"\r\n\r\n")).decode("latin-1")
            self.heads.append(head)
            if f"Proxy-Authorization: Basic {GOOD}\r\n" not in head:
                writer.write(b"HTTP/1.1 407 Proxy Authentication Required\r\n"
                             b"Proxy-Authenticate: Basic realm=\"corp\"\r\nContent-Length: 0\r\n\r\n")
            elif head.startswith("CONNECT "):
                writer.write(b"HTTP/1.1 200 Connection established\r\n\r\n")
                await writer.drain()
                data = await reader.read(100)
                writer.write(b"echo:" + data)
            else:
                writer.write(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
            await writer.drain()
        finally:
            writer.close()


class FakeOrigin:
    def __init__(self):
        self.heads = []

    async def handle(self, reader, writer):
        head = (await reader.readuntil(b"\r\n\r\n")).decode("latin-1")
        self.heads.append(head)
        writer.write(b"HTTP/1.1 200 OK\r\nContent-Length: 6\r\n\r\norigin")
        await writer.drain()
        writer.close()


class ForwarderTest(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.upstream = FakeCorporateProxy()
        self.origin = FakeOrigin()
        self.upstream_server = await asyncio.start_server(self.upstream.handle, "127.0.0.1", 0)
        self.origin_server = await asyncio.start_server(self.origin.handle, "127.0.0.1", 0)
        self.upstream_port = self.upstream_server.sockets[0].getsockname()[1]
        self.origin_port = self.origin_server.sockets[0].getsockname()[1]
        self.state = pf.State()
        self.uid = os.getuid()
        self.forwarder = pf.Forwarder(self.state, uid=self.uid, uid_lookup=lambda a, b: self.uid)
        self.server = await asyncio.start_server(self.forwarder.handle, "127.0.0.1", 0)
        self.port = self.server.sockets[0].getsockname()[1]

    async def asyncTearDown(self):
        for server in (self.server, self.upstream_server, self.origin_server):
            server.close()
            await server.wait_closed()

    async def exchange(self, payload, after=b""):
        reader, writer = await asyncio.open_connection("127.0.0.1", self.port)
        writer.write(payload)
        await writer.drain()
        if after:
            await asyncio.sleep(0.05)
            writer.write(after)
            await writer.drain()
        try:
            data = await asyncio.wait_for(reader.read(), 5)
        except ConnectionResetError:
            data = b""
        writer.close()
        return data

    def sign_in(self):
        self.state.set_upstream(("127.0.0.1", self.upstream_port), GOOD)

    async def test_upstream_connect_adds_login(self):
        self.sign_in()
        data = await self.exchange(b"CONNECT intranet.corp:443 HTTP/1.1\r\nHost: intranet.corp:443\r\n\r\n",
                                   after=b"hello")
        self.assertTrue(data.startswith(b"HTTP/1.1 200"))
        self.assertTrue(data.endswith(b"echo:hello"))

    async def test_upstream_get_replaces_client_login_and_closes(self):
        self.sign_in()
        data = await self.exchange(b"GET http://intranet.corp/x?y=1 HTTP/1.1\r\nHost: intranet.corp\r\n"
                                   b"Proxy-Authorization: Basic bogus\r\nProxy-Connection: keep-alive\r\n\r\n")
        self.assertTrue(data.endswith(b"ok"))
        head = self.upstream.heads[-1]
        self.assertTrue(head.startswith("GET http://intranet.corp/x?y=1 HTTP/1.1\r\n"))
        self.assertNotIn("bogus", head)
        self.assertNotIn("Proxy-Connection", head)
        self.assertIn("Connection: close\r\n", head)

    async def test_direct_get_uses_origin_form_without_proxy_headers(self):
        data = await self.exchange(
            f"GET http://127.0.0.1:{self.origin_port}/path HTTP/1.1\r\nHost: x\r\n"
            "Proxy-Authorization: Basic leak\r\n\r\n".encode())
        self.assertTrue(data.endswith(b"origin"))
        head = self.origin.heads[-1]
        self.assertTrue(head.startswith("GET /path HTTP/1.1\r\n"))
        self.assertNotIn("Proxy-Authorization", head)
        self.assertEqual(self.upstream.heads, [])

    async def test_localhost_bypasses_upstream(self):
        self.sign_in()
        data = await self.exchange(
            f"GET http://127.0.0.1:{self.origin_port}/ HTTP/1.1\r\nHost: x\r\n\r\n".encode())
        self.assertTrue(data.endswith(b"origin"))
        self.assertEqual(self.upstream.heads, [])

    async def test_other_users_are_refused(self):
        self.forwarder.uid_lookup = lambda a, b: self.uid + 1
        self.sign_in()
        data = await self.exchange(b"CONNECT intranet.corp:443 HTTP/1.1\r\n\r\n")
        self.assertEqual(data, b"")
        self.assertEqual(self.upstream.heads, [])

    async def test_bad_request_gets_400(self):
        data = await self.exchange(b"GET /relative HTTP/1.1\r\nHost: x\r\n\r\n")
        self.assertTrue(data.startswith(b"HTTP/1.1 400"))

    async def test_sign_in_verifies_login(self):
        upstream = f"127.0.0.1:{self.upstream_port}"
        with patch.object(pf, "emit") as emit:
            with self.assertRaisesRegex(pf.ForwarderError, "rejected the login"):
                await pf.apply_command(self.state, {"mode": "upstream", "upstream": upstream,
                                                    "username": "me@corp.example", "password": "wrong"})
            self.assertEqual(self.state.mode, "direct")
            await pf.apply_command(self.state, {"mode": "upstream", "upstream": "http://" + upstream,
                                                "username": "me@corp.example", "password": "secret"})
            self.assertEqual(self.state.mode, "upstream")
            await pf.apply_command(self.state, {"mode": "direct"})
            self.assertIsNone(self.state.auth)
        for call in emit.call_args_list:
            self.assertNotIn("secret", repr(call))


class HelperTest(unittest.TestCase):
    def test_peer_uid_finds_own_loopback_socket(self):
        server = socket.socket()
        server.bind(("127.0.0.1", 0))
        server.listen(1)
        client = socket.create_connection(server.getsockname())
        accepted, _ = server.accept()
        try:
            self.assertEqual(pf.peer_uid(client.getsockname()[1], server.getsockname()[1]), os.getuid())
            self.assertIsNone(pf.peer_uid(1, 1, tables=()))
        finally:
            for sock in (client, accepted, server):
                sock.close()

    def test_host_port_and_auth_validation(self):
        self.assertEqual(pf.parse_host_port("proxy.corp.local:80"), ("proxy.corp.local", 80))
        self.assertEqual(pf.parse_host_port("proxy.corp.local", default_port=80), ("proxy.corp.local", 80))
        self.assertEqual(pf.parse_host_port("[::1]:3128"), ("::1", 3128))
        for value in ("", "proxy:0", "proxy:99999", "pro xy:80", "user@proxy:80"):
            with self.subTest(value=value), self.assertRaises(pf.ForwarderError):
                pf.parse_host_port(value)
        with self.assertRaises(pf.ForwarderError):
            pf.basic_auth("a:b", "pw")
        with self.assertRaises(pf.ForwarderError):
            pf.basic_auth("me", "")
        self.assertEqual(base64.b64decode(pf.basic_auth("me@corp", "p:w")), b"me@corp:p:w")

    def test_connection_listed_headers_are_removed(self):
        headers = [("Connection", "X-Secret, close"), ("X-Secret", "1"), ("Host", "h")]
        self.assertEqual(pf.clean_headers(headers), [("Host", "h")])


if __name__ == "__main__":
    unittest.main()
