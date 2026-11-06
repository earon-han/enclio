#!/usr/bin/env python3
"""Deterministic proxy integration against loopback peers via test-only linker wrappers.

The production executable has no resolver/private-address test policy. This
harness records the public sockaddr actually passed to connect, then redirects
only the separately linked fixture to local peers. Parser/filter code is shared.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import signal
import socket
import socketserver
import struct
import subprocess
import tempfile
import threading
import time


class ThreadServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


class HTTPPeer(socketserver.BaseRequestHandler):
    def handle(self):
        stream = self.request.makefile("rb")
        request = stream.readline(16384).decode("ascii")
        method, path, version = request.strip().split(" ")
        headers = {}
        while True:
            line = stream.readline(16384)
            if line == b"\r\n":
                break
            if not line:
                return
            key, value = line.decode("ascii").split(":", 1)
            headers[key.lower()] = value.strip()
        if path == "/reject-early":
            data = b"early-origin-response" * 8192
            self.request.sendall(b"HTTP/1.1 413 Content Too Large\r\nContent-Length: "
                                 + str(len(data)).encode() + b"\r\nConnection: close\r\n\r\n" + data)
            # A bare close with unread request bytes sends TCP RST and can lose
            # this peer's own queued response. Half-close first, then drain, so
            # the test measures the proxy rather than fixture packet loss.
            self.request.shutdown(socket.SHUT_WR)
            self.request.settimeout(5)
            try:
                while self.request.recv(65536):
                    pass
            except (TimeoutError, ConnectionResetError):
                pass
            return
        if path == "/informational":
            self.request.sendall(b"HTTP/1.1 100 Continue\r\n\r\n")
        body = bytearray()
        if headers.get("transfer-encoding") == "chunked":
            while True:
                line = stream.readline().strip()
                if not line:
                    return
                try:
                    n = int(line, 16)
                except ValueError:
                    return
                if not n:
                    assert stream.readline() == b"\r\n"
                    break
                body.extend(stream.read(n))
                assert stream.read(2) == b"\r\n"
        elif "content-length" in headers:
            body.extend(stream.read(int(headers["content-length"])))
        trailing = b""
        early_fin = False
        if path in {"/pipeline", "/no-early-fin"}:
            self.request.settimeout(0.1)
            try:
                if path == "/pipeline":
                    trailing = stream.peek(4096)
                else:
                    early_fin = self.request.recv(1, socket.MSG_PEEK) == b""
            except TimeoutError:
                pass
            self.request.settimeout(None)
        data = json.dumps(dict(method=method, path=path, version=version, trailing_bytes=len(trailing), early_fin=early_fin,
                              headers=headers, body_length=len(body),
                              body_sha256=hashlib.sha256(body).hexdigest())).encode()
        self.request.sendall(b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: "
                             + str(len(data)).encode() + b"\r\nConnection: close\r\n\r\n")
        if method != "HEAD":
            self.request.sendall(data)


class EchoPeer(socketserver.BaseRequestHandler):
    def handle(self):
        while True:
            data = self.request.recv(32768)
            if not data:
                self.request.sendall(b"FIXTURE_HALF_CLOSE")
                return
            self.request.sendall(data)


def recv_all(connection):
    output = bytearray()
    while True:
        try:
            data = connection.recv(65536)
        except ConnectionResetError:
            if output:
                return bytes(output)
            raise
        if not data:
            return bytes(output)
        output.extend(data)


def recv_exact(connection, size):
    output = bytearray()
    while len(output) < size:
        data = connection.recv(size - len(output))
        if not data:
            raise AssertionError("connection closed before handshake completed")
        output.extend(data)
    return bytes(output)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", default="build/network-integration.json")
    parser.add_argument("--quick", action="store_true",
                        help="test-only timing compression; production timing is default")
    args = parser.parse_args()
    Path("build").mkdir(exist_ok=True)
    binary = Path("build/proxy_fixture").resolve()
    command = ["cc", "-std=c11", "-O2", "-g", "-Wall", "-Wextra", "-Werror", "-Isrc"]
    if args.quick:
        command.append("-DENCLIO_PROXY_TESTING")
    subprocess.run(command + ["tests/proxy_fixture.c", "src/proxy.c", "-Wl,--wrap=getaddrinfo",
                             "-Wl,--wrap=connect", "-lseccomp", "-o", str(binary)], check=True)
    checks = []
    http = ThreadServer(("127.0.0.1", 0), HTTPPeer)
    echo = ThreadServer(("127.0.0.1", 0), EchoPeer)
    for server in (http, echo):
        threading.Thread(target=server.serve_forever, daemon=True).start()
    http_port, echo_port = http.server_address[1], echo.server_address[1]
    audit_entries = []
    with tempfile.TemporaryDirectory(prefix="enclio-network-") as temporary:
        path = str(Path(temporary) / "proxy.sock")
        read_fd, write_fd = os.pipe()
        env = os.environ.copy()
        env["ENCLIO_CONNECT_AUDIT_FD"] = str(write_fd)
        rules = [f"{host}:{port}" for host in
                 ("public.test", "mixed.test", "private.test", "missing.test", "refused.test", "flip.test")
                 for port in (http_port, echo_port)]
        process = subprocess.Popen([str(binary), path, *rules], env=env,
                                   pass_fds=(write_fd,), start_new_session=True,
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        os.close(write_fd)
        def audit_reader():
            with os.fdopen(read_fd) as stream:
                for line in stream:
                    audit_entries.append(line.strip())
        reader = threading.Thread(target=audit_reader, daemon=True)
        reader.start()
        def connect(timeout=5):
            connection = socket.socket(socket.AF_UNIX)
            connection.settimeout(timeout)
            connection.connect(path)
            return connection
        def check(name, operation):
            try:
                detail = operation() or {}
                checks.append(dict(name=name, status="PASS", **detail))
            except Exception as error:
                detail = dict(name=name, status="FAIL", error=repr(error))
                if hasattr(error, "test_evidence"):
                    detail["evidence"] = error.test_evidence
                checks.append(detail)
            print(checks[-1]["status"] + ": " + name, flush=True)
        def request(payload):
            with connect() as connection:
                connection.sendall(payload)
                return recv_all(connection)
        def positive_http(method="GET", body=b"", chunked=False):
            authority = f"public.test:{http_port}"
            headers = (f"{method} http://{authority}/some/path?q=1 HTTP/1.1\r\n"
                       f"Host: {authority}\r\nProxy-Authorization: secret-not-forwarded\r\n"
                       "Connection: keep-alive, X-Removed\r\nX-Removed: secret-hop\r\n")
            if chunked:
                wire = headers.encode() + b"Transfer-Encoding: chunked\r\n\r\n"
                wire += f"{len(body):x}\r\n".encode() + body + b"\r\n0\r\n\r\n"
            else:
                wire = headers.encode() + f"Content-Length: {len(body)}\r\n\r\n".encode() + body
            result = request(wire)
            header, response_body = result.split(b"\r\n\r\n", 1)
            assert header.startswith(b"HTTP/1.1 200")
            if method == "HEAD":
                assert not response_body
                return dict(status_line=header.split(b"\r\n")[0].decode())
            data = json.loads(response_body)
            assert data["method"] == method and data["path"] == "/some/path?q=1"
            assert data["body_sha256"] == hashlib.sha256(body).hexdigest()
            assert "proxy-authorization" not in data["headers"]
            assert "x-removed" not in data["headers"] and data["headers"]["connection"] == "close"
            return dict(peer=data)
        def denial(host, expected):
            before = len(audit_entries)
            authority = f"{host}:{http_port}"
            result = request(f"GET http://{authority}/ HTTP/1.1\r\nHost: {authority}\r\n\r\n".encode())
            assert result.startswith(f"HTTP/1.1 {expected}".encode()), result[:120]
            time.sleep(0.03)
            if host in {"mixed.test", "private.test", "missing.test", "denied.test"}:
                assert len(audit_entries) == before, audit_entries[before:]
            return dict(status_line=result.split(b"\r\n")[0].decode(),
                        upstream_attempts=audit_entries[before:])
        def tunnel(kind):
            payload = bytes(range(256)) * 16384  # 4 MiB, both directions.
            with connect() as connection:
                if kind == "CONNECT":
                    connection.sendall(f"CONNECT public.test:{echo_port} HTTP/1.1\r\nHost: public.test:{echo_port}\r\n\r\n".encode())
                    header = bytearray()
                    while not header.endswith(b"\r\n\r\n"):
                        header.extend(recv_exact(connection, 1))
                    assert header.startswith(b"HTTP/1.1 200")
                else:
                    connection.sendall(b"\x05\x01\x00")
                    assert recv_exact(connection, 2) == b"\x05\x00"
                    host = b"public.test"
                    connection.sendall(b"\x05\x01\x00\x03" + bytes([len(host)]) + host + struct.pack("!H", echo_port))
                    assert recv_exact(connection, 10)[:2] == b"\x05\x00"
                errors = []
                def producer():
                    try:
                        connection.sendall(payload)
                        connection.shutdown(socket.SHUT_WR)
                    except Exception as error:
                        errors.append(repr(error))
                sender = threading.Thread(target=producer)
                sender.start()
                data = recv_all(connection)
                sender.join(timeout=5)
                assert not sender.is_alive() and not errors, errors
                assert data == payload + b"FIXTURE_HALF_CLOSE", (len(data), len(payload))
                return dict(bytes_each_direction=len(payload), half_close_suffix=True,
                            sha256=hashlib.sha256(payload).hexdigest())
        def socks_rejection(message, expected):
            with connect() as connection:
                connection.sendall(b"\x05\x01\x00")
                assert recv_exact(connection, 2) == b"\x05\x00"
                connection.sendall(message)
                response = recv_exact(connection, 10)
                assert response[0] == 5 and response[1] == expected, response
                return dict(reply_status=response[1])
        try:
            ready = False
            for _ in range(200):
                try:
                    connection = connect(); connection.close(); ready = True; break
                except OSError:
                    if process.poll() is not None:
                        break
                    time.sleep(0.01)
            if not ready:
                raise RuntimeError("fixture server failed startup")
            def early_response():
                with connect() as connection:
                    connection.sendall(f"POST http://public.test:{http_port}/reject-early HTTP/1.1\r\nHost: public.test:{http_port}\r\nContent-Length: 4194304\r\n\r\nabc".encode())
                    data = recv_all(connection)
                header, body = data.split(b"\r\n\r\n", 1)
                assert header.startswith(b"HTTP/1.1 413")
                assert body == b"early-origin-response" * 8192, len(body)
                return dict(response_body_bytes=len(body), request_complete=False)
            def informational():
                body = b"request-body-after-informational"
                data = request(f"POST http://public.test:{http_port}/informational HTTP/1.1\r\nHost: public.test:{http_port}\r\nContent-Length: {len(body)}\r\n\r\n".encode() + body)
                assert data.startswith(b"HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 200")
                payload = json.loads(data.split(b"\r\n\r\n", 2)[2])
                assert payload["body_sha256"] == hashlib.sha256(body).hexdigest()
                return dict(informational_and_final_forwarded=True)
            def worker_limit():
                held = []
                expected = 4 if args.quick else 32
                # Quick headers expire after 250ms; production headers after
                # 10s. Filling and observing all held workers must fit inside.
                fill_budget = 0.15 if args.quick else 2.0
                evidence = dict(phase="pre_fill_reap", expected_workers=expected,
                                fill_budget_seconds=fill_budget, reap_budget_seconds=2,
                                extra_connect_timeout_seconds=5, extra_receive_timeout_seconds=1,
                                extra_attempts=0, recovery_attempts=0)
                def children():
                    try:
                        pids = [int(value) for value in
                                Path(f"/proc/{process.pid}/task/{process.pid}/children").read_text().split()]
                        return dict(available=True, pids=pids, count=len(pids))
                    except OSError as error:
                        return dict(available=False, error=repr(error))
                def held_states():
                    states = []
                    for index, connection in enumerate(held):
                        previous = connection.gettimeout()
                        try:
                            # MSG_DONTWAIT alone does not bypass Python's
                            # timeout-mode pre-select. Change this socket only.
                            connection.setblocking(False)
                            try:
                                data = connection.recv(1, socket.MSG_PEEK)
                                states.append(dict(index=index, state="eof" if not data else "data",
                                                   data_hex=data.hex()))
                            except BlockingIOError:
                                states.append(dict(index=index, state="open_no_data"))
                            except OSError as error:
                                states.append(dict(index=index, state="error", error=repr(error)))
                        finally:
                            connection.settimeout(previous)
                    return states
                def wait_empty(label):
                    begin = time.monotonic()
                    deadline = begin + 2
                    observation = dict(initial=children())
                    evidence[label] = observation
                    while True:
                        current = children()
                        observation.update(final=current, elapsed_seconds=round(time.monotonic()-begin, 6))
                        if not current["available"] or process.poll() is not None:
                            raise RuntimeError("fixture worker state unavailable")
                        if not current["pids"]:
                            return
                        if time.monotonic() >= deadline:
                            raise TimeoutError("fixture workers were not reaped within two seconds")
                        time.sleep(0.005)
                try:
                    # A response EOF precedes _exit/reap. Wait for the previous
                    # case's real workers, rather than assuming an idle server.
                    wait_empty("before_fill")
                    evidence["phase"] = "fill"
                    begin = time.monotonic()
                    deadline = begin + fill_budget
                    for index in range(expected):
                        remaining = deadline - time.monotonic()
                        if remaining <= 0:
                            raise TimeoutError("worker filling exceeded its total deadline")
                        connection = connect(timeout=min(5, remaining))
                        held.append(connection)
                        remaining = deadline - time.monotonic()
                        if remaining <= 0:
                            raise TimeoutError("worker greeting exceeded the total fill deadline")
                        connection.settimeout(remaining)
                        connection.sendall(b"\x05\x01\x00")
                        reply = bytearray()
                        while len(reply) < 2:
                            remaining = deadline - time.monotonic()
                            if remaining <= 0:
                                raise TimeoutError("worker greeting exceeded the total fill deadline")
                            connection.settimeout(remaining)
                            part = connection.recv(2-len(reply))
                            if not part:
                                raise AssertionError("held connection closed before NOAUTH confirmation")
                            reply.extend(part)
                        assert reply == b"\x05\x00", reply
                        connection.settimeout(5)
                        evidence["confirmed_handshakes"] = index + 1
                    evidence.update(phase="verify_occupied", children_before_extra=children(),
                                    held_before_extra=held_states(),
                                    fill_elapsed_seconds=round(time.monotonic()-begin, 6))
                    assert time.monotonic() < deadline, "worker fill/verification exceeded its total deadline"
                    assert evidence["children_before_extra"]["available"]
                    assert evidence["children_before_extra"]["count"] == expected, evidence
                    assert all(item["state"] == "open_no_data" for item in evidence["held_before_extra"]), evidence
                    evidence.update(phase="extra_rejection", extra_attempts=1)
                    begin_extra = time.monotonic()
                    try:
                        evidence["extra_step"] = "connect"
                        with connect() as extra:
                            extra.settimeout(1)
                            try:
                                evidence["extra_step"] = "send"
                                extra.sendall(b"G")
                                evidence["extra_step"] = "receive"
                                data = extra.recv(1)
                                evidence["extra_outcome"] = "eof" if not data else "data"
                                assert not data, data
                            except (BrokenPipeError, ConnectionResetError) as error:
                                evidence["extra_outcome"] = type(error).__name__
                        evidence["extra_step"] = "complete"
                    except Exception as error:
                        evidence["extra_outcome"] = type(error).__name__
                        raise
                    finally:
                        evidence["extra_elapsed_seconds"] = round(time.monotonic()-begin_extra, 6)
                except Exception as error:
                    # Capture the failing state before closing the held sockets.
                    evidence.update(children_at_failure=children(), held_at_failure=held_states())
                    error.test_evidence = evidence
                    raise
                finally:
                    for connection in held:
                        connection.close()
                try:
                    evidence["phase"] = "post_close_reap"
                    wait_empty("after_close")
                    evidence.update(phase="recovery", recovery_attempts=1)
                    positive_http()
                except Exception as error:
                    evidence["children_at_failure"] = children()
                    error.test_evidence = evidence
                    raise
                evidence["phase"] = "complete"
                return dict(held_workers=expected, recovered=True, evidence=evidence)
            def no_early_fin():
                body = b"body-complete-without-TCP-FIN"
                data = request(f"POST http://public.test:{http_port}/no-early-fin HTTP/1.1\r\nHost: public.test:{http_port}\r\nContent-Length: {len(body)}\r\n\r\n".encode() + body)
                peer = json.loads(data.split(b"\r\n\r\n", 1)[1])
                assert not peer["early_fin"]
                assert peer["body_sha256"] == hashlib.sha256(body).hexdigest()
                return dict(origin_observed_fin=False)
            def dns_rebinding():
                before = len(audit_entries)
                authority = f"flip.test:{http_port}"
                data = request(f"GET http://{authority}/ HTTP/1.1\r\nHost: {authority}\r\n\r\n".encode())
                assert data.startswith(b"HTTP/1.1 200")
                time.sleep(0.03)
                attempts = audit_entries[before:]
                assert attempts == [f"8.8.8.8:{http_port}"], attempts
                return dict(validated_sockaddr=attempts[0], hypothetical_second_dns="private")
            check("dns_rebinding_connects_only_validated_sockaddr", dns_rebinding)
            check("http_body_completion_does_not_half_close_upstream", no_early_fin)
            check("http_origin_early_413_large_response", early_response)
            check("http_informational_100_then_final", informational)
            check("worker_limit_and_recovery", worker_limit)
            check("http_get_origin_rewrite_and_hop_header_removal", positive_http)
            check("http_head", lambda: positive_http("HEAD"))
            check("http_post_content_length", lambda: positive_http("POST", b"A" * 131072))
            check("http_post_chunked", lambda: positive_http("POST", b"chunked-body" * 4096, True))
            check("connect_large_duplex_half_close", lambda: tunnel("CONNECT"))
            check("socks5_large_duplex_half_close", lambda: tunnel("SOCKS5"))
            for host, expected in [("denied.test", 403), ("mixed.test", 502),
                                   ("private.test", 502), ("missing.test", 502), ("refused.test", 502)]:
                check("destination_" + host, lambda host=host, expected=expected: denial(host, expected))
            malformed = [
                f"GET http://public.test:{http_port}/ HTTP/1.1\r\nHost: denied.test:{http_port}\r\n\r\n",
                f"POST http://public.test:{http_port}/ HTTP/1.1\r\nHost: public.test:{http_port}\r\nContent-Length: 2\r\nContent-Length: 2\r\n\r\nxx",
                f"POST http://public.test:{http_port}/ HTTP/1.1\r\nHost: public.test:{http_port}\r\nContent-Length: 2\r\nTransfer-Encoding: chunked\r\n\r\nxx",
                f"GET http://public.test:{http_port}/ HTTP/1.1\r\nHost: public.test:{http_port}\r\nConnection: Host\r\n\r\n",
            ]
            for index, wire in enumerate(malformed):
                def reject(wire=wire):
                    result = request(wire.encode())
                    assert result.startswith(b"HTTP/1.1 400"), result[:100]
                check("http_smuggling_rejected_" + str(index), reject)
            host = b"public.test"
            check("socks5_udp_rejected", lambda: socks_rejection(b"\x05\x03\x00\x03" + bytes([len(host)]) + host + struct.pack("!H", echo_port), 7))
            check("socks5_numeric_address_rejected", lambda: socks_rejection(b"\x05\x01\x00\x01\x7f\x00\x00\x01\x01\xbb", 8))
            def slow_header():
                start = time.monotonic()
                with connect() as connection:
                    connection.settimeout(12 if not args.quick else 2)
                    connection.sendall(b"GET http://public.test")
                    result = recv_all(connection)
                elapsed = time.monotonic() - start
                assert elapsed < (11.5 if not args.quick else 1.5)
                assert not result or result.startswith(b"HTTP/1.1 400")
                return dict(elapsed_seconds=round(elapsed, 3), timing_compressed=args.quick)
            wrong_port = next(p for p in range(1024, 65535) if p not in {http_port, echo_port})
            def wrong_port_denied():
                data = request(f"GET http://public.test:{wrong_port}/ HTTP/1.1\r\nHost: public.test:{wrong_port}\r\n\r\n".encode())
                assert data.startswith(b"HTTP/1.1 403")
            check("http_unauthorized_port", wrong_port_denied)
            malformed_domain = f"public.test:{echo_port}".encode()
            check("socks_domain_cannot_override_port", lambda: socks_rejection(b"\x05\x01\x00\x03" + bytes([len(malformed_domain)]) + malformed_domain + struct.pack("!H", wrong_port), 2))
            for name, chunk in [("extension", b"4;x=y\r\nbody\r\n0\r\n\r\n"),
                                ("trailer", b"0\r\nX-Trailer: y\r\n\r\n"),
                                ("invalid_hex", b"z\r\n"),
                                ("over_limit", b"4000001\r\n")]:
                def invalid_chunk(chunk=chunk):
                    with connect() as connection:
                        connection.sendall(f"POST http://public.test:{http_port}/ HTTP/1.1\r\nHost: public.test:{http_port}\r\nTransfer-Encoding: chunked\r\n\r\n".encode() + chunk)
                        connection.shutdown(socket.SHUT_WR)
                        try:
                            data = recv_all(connection)
                        except ConnectionResetError:
                            data = b""
                    assert not data.startswith(b"HTTP/1.1 200"), data[:100]
                    assert process.poll() is None
                check("chunked_invalid_" + name, invalid_chunk)
            def pipelined_authority_not_forwarded():
                data = request(f"GET http://public.test:{http_port}/pipeline HTTP/1.1\r\nHost: public.test:{http_port}\r\n\r\nGET http://denied.test:{http_port}/ HTTP/1.1\r\nHost: denied.test:{http_port}\r\n\r\n".encode())
                assert data.startswith(b"HTTP/1.1 200")
                body = json.loads(data.split(b"\r\n\r\n", 1)[1])
                assert body["trailing_bytes"] == 0
            check("http_pipeline_not_forwarded_as_tunnel", pipelined_authority_not_forwarded)
            check("slow_header_deadline", slow_header)
        finally:
            try:
                os.killpg(process.pid, signal.SIGTERM)
            except ProcessLookupError:
                pass
            stdout, stderr = process.communicate(timeout=5)
            reader.join(timeout=1)
            for server in (http, echo):
                server.shutdown(); server.server_close()
        output = dict(schema_version=1, fixture_sha256=hashlib.sha256(binary.read_bytes()).hexdigest(),
                      source_identity=json.loads(subprocess.check_output(["python3", "scripts/source-id.py", "--json"], text=True)),
                      production_timing=not args.quick, resolver_override="test-only linker --wrap",
                      results=checks, failed=sum(c["status"] != "PASS" for c in checks),
                      audit_sockaddrs=audit_entries, server_stdout=stdout.decode(errors="replace"),
                      server_stderr=stderr.decode(errors="replace"))
        Path(args.output).parent.mkdir(parents=True, exist_ok=True)
        Path(args.output).write_text(json.dumps(output, indent=2) + "\n")
        return int(bool(output["failed"]))


if __name__ == "__main__":
    raise SystemExit(main())
