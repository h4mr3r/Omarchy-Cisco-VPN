#!/usr/bin/env python3
"""Loopback HTTP proxy that adds the corporate proxy login for this user only.

Apps point http_proxy/https_proxy at 127.0.0.1:3128 without credentials. While
the VPN is up and signed in, requests go to the corporate proxy with a Basic
Proxy-Authorization header added here; otherwise they go direct. The password
only ever lives in this process's memory.

Control: one JSON object per stdin line.
  {"mode": "direct"}
  {"mode": "upstream", "upstream": "host:port", "username": "...", "password": "..."}
EOF on stdin stops the forwarder. Events are JSON lines on stdout.
"""

import asyncio
import base64
import json
import os
import re
import sys
from urllib.parse import urlsplit

LISTEN_HOST = "127.0.0.1"
LISTEN_PORT = int(os.environ.get("CISCO_VPN_PROXY_PORT", "3128"))
MAX_HEAD = 65536
HEAD_TIMEOUT = 30
CONNECT_TIMEOUT = 15
HOP_HEADERS = {"proxy-authorization", "proxy-connection", "connection", "keep-alive", "te",
               "trailer", "upgrade"}
HOST_PORT = re.compile(r"^([A-Za-z0-9.\-]+|\[[0-9A-Fa-f:.]+\]):(\d{1,5})$")
LOCAL_HOSTS = {"localhost", "127.0.0.1", "::1", "[::1]"}


class ForwarderError(Exception):
    pass


class State:
    def __init__(self):
        self.mode = "direct"
        self.upstream = None
        self.auth = None

    def set_direct(self):
        self.mode, self.upstream, self.auth = "direct", None, None

    def set_upstream(self, upstream, auth):
        self.mode, self.upstream, self.auth = "upstream", upstream, auth


def emit(event, **fields):
    print(json.dumps({"event": event, **fields}), flush=True)


def parse_host_port(value, default_port=None):
    match = HOST_PORT.fullmatch(value)
    if match:
        host, port = match.group(1), int(match.group(2))
    elif default_port is not None and re.fullmatch(r"[A-Za-z0-9.\-]+|\[[0-9A-Fa-f:.]+\]", value):
        host, port = value, default_port
    else:
        raise ForwarderError("Expected host:port")
    if not 0 < port < 65536:
        raise ForwarderError("Invalid port")
    return host.strip("[]"), port


def basic_auth(username, password):
    if not username or not password or any(c in username + password for c in "\r\n"):
        raise ForwarderError("Enter the corporate proxy login and password")
    if ":" in username:
        raise ForwarderError("The proxy login cannot contain ':'")
    return base64.b64encode(f"{username}:{password}".encode()).decode()


def peer_uid(client_port, server_port, tables=("/proc/net/tcp", "/proc/net/tcp6")):
    """UID owning the loopback client socket, from the kernel's TCP tables."""
    for table in tables:
        try:
            with open(table) as handle:
                next(handle, None)
                for line in handle:
                    fields = line.split()
                    if len(fields) < 8:
                        continue
                    local_port = int(fields[1].rsplit(":", 1)[1], 16)
                    remote_port = int(fields[2].rsplit(":", 1)[1], 16)
                    if local_port == client_port and remote_port == server_port:
                        return int(fields[7])
        except OSError:
            continue
    return None


def parse_head(head):
    lines = head.decode("latin-1").split("\r\n")
    parts = lines[0].split(" ")
    if len(parts) != 3 or not parts[2].startswith("HTTP/"):
        raise ForwarderError("Malformed request line")
    headers = []
    for line in lines[1:]:
        if not line:
            continue
        name, separator, value = line.partition(":")
        if not separator or not name.strip() or name != name.strip():
            raise ForwarderError("Malformed header")
        headers.append((name, value.strip()))
    return parts[0], parts[1], parts[2], headers


def request_target(method, target):
    """Return (host, port, origin_form) for a proxy request."""
    if method.upper() == "CONNECT":
        host, port = parse_host_port(target)
        return host, port, None
    parsed = urlsplit(target)
    if parsed.scheme != "http" or not parsed.hostname:
        raise ForwarderError("Only absolute http:// URLs and CONNECT are supported")
    path = parsed.path or "/"
    if parsed.query:
        path += "?" + parsed.query
    return parsed.hostname, parsed.port or 80, path


def build_head(request_line, headers):
    lines = [request_line] + [f"{name}: {value}" for name, value in headers]
    return ("\r\n".join(lines) + "\r\n\r\n").encode("latin-1")


def clean_headers(headers):
    connection_tokens = set()
    for name, value in headers:
        if name.lower() == "connection":
            connection_tokens.update(token.strip().lower() for token in value.split(","))
    return [(name, value) for name, value in headers
            if name.lower() not in HOP_HEADERS and name.lower() not in connection_tokens]


async def pipe(reader, writer):
    try:
        while True:
            chunk = await reader.read(65536)
            if not chunk:
                break
            writer.write(chunk)
            await writer.drain()
    except (ConnectionError, asyncio.CancelledError):
        pass
    finally:
        try:
            if writer.can_write_eof():
                writer.write_eof()
        except (OSError, RuntimeError):
            pass


async def relay(client_reader, client_writer, server_reader, server_writer):
    await asyncio.gather(pipe(client_reader, server_writer), pipe(server_reader, client_writer))


async def open_connection(host, port):
    return await asyncio.wait_for(asyncio.open_connection(host, port), CONNECT_TIMEOUT)


async def respond(writer, status, reason):
    body = f"{status} {reason}\n".encode()
    writer.write(f"HTTP/1.1 {status} {reason}\r\nContent-Type: text/plain\r\n"
                 f"Content-Length: {len(body)}\r\nConnection: close\r\n\r\n".encode() + body)
    await writer.drain()


class Forwarder:
    def __init__(self, state, uid=None, uid_lookup=peer_uid):
        self.state = state
        self.uid = os.getuid() if uid is None else uid
        self.uid_lookup = uid_lookup

    async def handle(self, reader, writer):
        server_writer = None
        try:
            peer = writer.get_extra_info("peername")
            local = writer.get_extra_info("sockname")
            if self.uid_lookup(peer[1], local[1]) != self.uid:
                return
            try:
                head = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), HEAD_TIMEOUT)
                method, target, version, headers = parse_head(head[:-4])
                host, port, origin = request_target(method, target)
            except (asyncio.IncompleteReadError, asyncio.LimitOverrunError, asyncio.TimeoutError):
                return
            except ForwarderError as error:
                await respond(writer, 400, str(error))
                return

            headers = clean_headers(headers)
            use_upstream = self.state.mode == "upstream" and host.lower() not in LOCAL_HOSTS
            try:
                if use_upstream:
                    server_reader, server_writer = await open_connection(*self.state.upstream)
                else:
                    server_reader, server_writer = await open_connection(host, port)
            except (OSError, asyncio.TimeoutError):
                await respond(writer, 502, "Could not connect"
                              + (" to the corporate proxy" if use_upstream else ""))
                return

            if use_upstream:
                forwarded = headers + [("Proxy-Authorization", "Basic " + self.state.auth)]
                if origin is not None:
                    # One request per connection, so every request carries the login.
                    forwarded.append(("Connection", "close"))
                server_writer.write(build_head(f"{method} {target} {version}", forwarded))
                await server_writer.drain()
            elif origin is None:
                writer.write(b"HTTP/1.1 200 Connection established\r\n\r\n")
                await writer.drain()
            else:
                forwarded = headers + [("Connection", "close")]
                server_writer.write(build_head(f"{method} {origin} {version}", forwarded))
                await server_writer.drain()
            await relay(reader, writer, server_reader, server_writer)
        except (ConnectionError, OSError):
            pass
        finally:
            for stream in (server_writer, writer):
                if stream is not None:
                    stream.close()


async def verify_upstream(upstream, auth, target="www.example.com:443"):
    """True unless the corporate proxy answers 407 to an authenticated CONNECT."""
    reader, writer = await open_connection(*upstream)
    try:
        writer.write(build_head(f"CONNECT {target} HTTP/1.1",
                                [("Host", target), ("Proxy-Authorization", "Basic " + auth)]))
        await writer.drain()
        line = await asyncio.wait_for(reader.readline(), CONNECT_TIMEOUT)
    finally:
        writer.close()
    match = re.match(rb"HTTP/\d(?:\.\d)?\s+(\d{3})", line)
    if not match:
        raise ForwarderError("The corporate proxy returned an unexpected response")
    return int(match.group(1)) != 407


async def apply_command(state, command):
    mode = command.get("mode")
    if mode == "direct":
        state.set_direct()
        emit("mode", mode="direct")
        return
    if mode != "upstream":
        raise ForwarderError("Unknown command")
    upstream = parse_host_port(str(command.get("upstream", "")).removeprefix("http://").rstrip("/"),
                               default_port=80)
    auth = basic_auth(str(command.get("username", "")), str(command.get("password", "")))
    try:
        accepted = await verify_upstream(upstream, auth)
    except (OSError, asyncio.TimeoutError) as error:
        raise ForwarderError("Could not reach the corporate proxy") from error
    if not accepted:
        state.set_direct()
        raise ForwarderError("The corporate proxy rejected the login")
    state.set_upstream(upstream, auth)
    emit("mode", mode="upstream", upstream=f"{upstream[0]}:{upstream[1]}")


async def control(state):
    loop = asyncio.get_running_loop()
    reader = asyncio.StreamReader(limit=MAX_HEAD)
    await loop.connect_read_pipe(lambda: asyncio.StreamReaderProtocol(reader), sys.stdin)
    while True:
        try:
            line = await reader.readline()
        except (ValueError, asyncio.LimitOverrunError):
            emit("error", error="Control message too long")
            continue
        if not line:
            return
        try:
            command = json.loads(line)
            if not isinstance(command, dict):
                raise ForwarderError("Invalid command")
            await apply_command(state, command)
        except (ForwarderError, ValueError) as error:
            emit("error", error=str(error) if isinstance(error, ForwarderError) else "Invalid command")


async def main():
    state = State()
    forwarder = Forwarder(state)
    try:
        server = await asyncio.start_server(forwarder.handle, LISTEN_HOST, LISTEN_PORT, limit=MAX_HEAD)
    except OSError:
        emit("error", error=f"Port {LISTEN_PORT} is already in use", fatal=True)
        return 1
    emit("listening", host=LISTEN_HOST, port=LISTEN_PORT)
    async with server:
        await control(state)
    return 0


if __name__ == "__main__":
    try:
        sys.exit(asyncio.run(main()))
    except KeyboardInterrupt:
        sys.exit(0)
