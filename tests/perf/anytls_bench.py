#!/usr/bin/env python3
"""Repeatable AnyTLS application-layer benchmark using only the stdlib."""

from __future__ import annotations

import argparse
import hashlib
import json
import multiprocessing as mp
import selectors
import socket
import ssl
import statistics
import struct
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable

CMD_SYN = 1
CMD_PSH = 2
CMD_FIN = 3
CMD_SETTINGS = 4
MAX_FRAME_DATA = 65535
HEADER = struct.Struct("!BIH")


def frame(command: int, stream_id: int, payload: bytes = b"") -> bytes:
    if len(payload) > MAX_FRAME_DATA:
        raise ValueError("AnyTLS frame payload exceeds 65535 bytes")
    return HEADER.pack(command, stream_id, len(payload)) + payload


def socks_address(host: str, port: int) -> bytes:
    try:
        packed = socket.inet_pton(socket.AF_INET, host)
        return b"\x01" + packed + struct.pack("!H", port)
    except OSError:
        pass
    try:
        packed = socket.inet_pton(socket.AF_INET6, host)
        return b"\x04" + packed + struct.pack("!H", port)
    except OSError:
        encoded = host.encode("idna")
        if not 0 < len(encoded) <= 255:
            raise ValueError("upstream hostname must encode to 1..255 bytes")
        return b"\x03" + bytes((len(encoded),)) + encoded + struct.pack("!H", port)


def uot_packet(host: str, port: int, payload: bytes) -> bytes:
    encoded = host.encode("idna")
    if not 0 < len(encoded) <= 255:
        raise ValueError("UoT hostname must encode to 1..255 bytes")
    return (
        b"\x02"
        + bytes((len(encoded),))
        + encoded
        + struct.pack("!HH", port, len(payload))
        + payload
    )


def percentile(values: list[float], p: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    position = (len(ordered) - 1) * p
    lower = int(position)
    upper = min(lower + 1, len(ordered) - 1)
    fraction = position - lower
    return ordered[lower] + (ordered[upper] - ordered[lower]) * fraction


@dataclass
class Counters:
    useful_bytes: int = 0
    frame_bytes: int = 0
    succeeded: int = 0
    failed: int = 0
    latencies_ms: list[float] = field(default_factory=list)

    def merge(self, other: "Counters") -> None:
        self.useful_bytes += other.useful_bytes
        self.frame_bytes += other.frame_bytes
        self.succeeded += other.succeeded
        self.failed += other.failed
        self.latencies_ms.extend(other.latencies_ms)


class AnyTLSClient:
    def __init__(self, args: argparse.Namespace):
        raw = socket.create_connection((args.host, args.port), timeout=15)
        raw.settimeout(15)
        if args.transport == "tls":
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            self.sock = context.wrap_socket(raw, server_hostname=args.host)
        else:
            self.sock = raw
        self.selector = selectors.DefaultSelector()
        self.selector.register(self.sock, selectors.EVENT_READ)
        self.buffer = bytearray()
        self.frame_bytes = 0
        self.send_raw(hashlib.sha256(args.password.encode()).digest() + b"\x00\x00")
        self.send_frame(CMD_SETTINGS, 0, b"v=2\nclient=anytls_bench\n")

    def close(self) -> None:
        self.selector.close()
        self.sock.close()

    def send_raw(self, data: bytes) -> None:
        self.sock.sendall(data)

    def send_frame(self, command: int, stream_id: int, payload: bytes = b"") -> None:
        encoded = frame(command, stream_id, payload)
        self.sock.sendall(encoded)
        self.frame_bytes += len(encoded)

    def receive_frame(self, deadline: float) -> tuple[int, int, bytes]:
        while True:
            if len(self.buffer) >= HEADER.size:
                command, stream_id, length = HEADER.unpack_from(self.buffer)
                total = HEADER.size + length
                if len(self.buffer) >= total:
                    payload = bytes(self.buffer[HEADER.size:total])
                    del self.buffer[:total]
                    self.frame_bytes += total
                    return command, stream_id, payload
            timeout = deadline - time.monotonic()
            if timeout <= 0 or not self.selector.select(timeout):
                raise TimeoutError("timed out waiting for AnyTLS frame")
            chunk = self.sock.recv(65536)
            if not chunk:
                raise EOFError("AnyTLS session closed")
            self.buffer.extend(chunk)

    def receive_payloads(self, expected: dict[int, int]) -> dict[int, bytes]:
        received = {stream_id: bytearray() for stream_id in expected}
        deadline = time.monotonic() + 30
        while any(len(received[sid]) < size for sid, size in expected.items()):
            command, stream_id, payload = self.receive_frame(deadline)
            if command == CMD_PSH and stream_id in received:
                received[stream_id].extend(payload)
            elif command == CMD_FIN and stream_id in expected:
                if len(received[stream_id]) < expected[stream_id]:
                    raise EOFError(f"stream {stream_id} closed before expected payload")
        return {stream_id: bytes(data) for stream_id, data in received.items()}


def chunks(payload: bytes, size: int) -> Iterable[bytes]:
    for offset in range(0, len(payload), size):
        yield payload[offset : offset + size]


def run_tcp_session(args: argparse.Namespace, session_index: int) -> Counters:
    result = Counters()
    client = AnyTLSClient(args)
    try:
        stream_count = args.streams_per_session
        if args.mode == "stream-churn":
            stream_count = max(stream_count, args.iterations)
        stream_ids = [session_index * 1_000_000 + i * 2 + 1 for i in range(stream_count)]
        address = socks_address(args.upstream_host, args.upstream_port)

        if args.mode == "latency":
            stream_ids = stream_ids[:1]
            for iteration in range(args.iterations):
                stream_id = stream_ids[0] + iteration * 2
                payload = bytes((iteration & 0xFF,)) * args.payload_size
                started = time.perf_counter()
                client.send_frame(CMD_SYN, stream_id)
                client.send_frame(CMD_PSH, stream_id, address + payload)
                echoed = client.receive_payloads({stream_id: len(payload)})[stream_id]
                client.send_frame(CMD_FIN, stream_id)
                if echoed != payload:
                    result.failed += 1
                else:
                    result.succeeded += 1
                    result.useful_bytes += len(payload)
                    result.latencies_ms.append((time.perf_counter() - started) * 1000)
        else:
            expected: dict[int, bytes] = {}
            for ordinal, stream_id in enumerate(stream_ids):
                payload = bytes(((session_index + ordinal) & 0xFF,)) * args.bytes_per_stream
                expected[stream_id] = payload
                client.send_frame(CMD_SYN, stream_id)
                first = True
                for part in chunks(payload, args.payload_size):
                    client.send_frame(CMD_PSH, stream_id, (address if first else b"") + part)
                    first = False
                if not payload:
                    client.send_frame(CMD_PSH, stream_id, address)
                if args.mode == "stream-churn":
                    echoed = client.receive_payloads({stream_id: len(payload)})[stream_id]
                    client.send_frame(CMD_FIN, stream_id)
                    if echoed == payload:
                        result.succeeded += 1
                        result.useful_bytes += len(payload)
                    else:
                        result.failed += 1

            if args.mode != "stream-churn":
                received = client.receive_payloads(
                    {stream_id: len(payload) for stream_id, payload in expected.items()}
                )
                for stream_id, payload in expected.items():
                    client.send_frame(CMD_FIN, stream_id)
                    if received[stream_id] == payload:
                        result.succeeded += 1
                        result.useful_bytes += len(payload)
                    else:
                        result.failed += 1
    except (OSError, EOFError, TimeoutError, ValueError):
        result.failed += 1
    finally:
        result.frame_bytes += client.frame_bytes
        client.close()
    return result


def run_uot_session(args: argparse.Namespace, session_index: int) -> Counters:
    result = Counters()
    client = AnyTLSClient(args)
    try:
        stream_id = session_index * 1_000_000 + 1
        open_request = socks_address("sp.v2.udp-over-tcp.arpa", 443) + b"\x00" + socks_address(
            args.upstream_host, args.upstream_port
        )
        client.send_frame(CMD_SYN, stream_id)
        client.send_frame(CMD_PSH, stream_id, open_request)
        expected: list[bytes] = []
        for iteration in range(args.iterations):
            payload = bytes(((session_index + iteration) & 0xFF,)) * args.payload_size
            expected.append(payload)
            client.send_frame(
                CMD_PSH,
                stream_id,
                uot_packet(args.upstream_host, args.upstream_port, payload),
            )
        deadline = time.monotonic() + 30
        received: list[bytes] = []
        while len(received) < len(expected):
            command, returned_id, payload = client.receive_frame(deadline)
            if command != CMD_PSH or returned_id != stream_id or len(payload) < 2:
                continue
            packet_len = struct.unpack_from("!H", payload, len(payload) - len(expected[0]) - 2)[0]
            received.append(payload[-packet_len:] if packet_len else b"")
        client.send_frame(CMD_FIN, stream_id)
        for wanted, got in zip(expected, received):
            if wanted == got:
                result.succeeded += 1
                result.useful_bytes += len(wanted)
            else:
                result.failed += 1
    except (OSError, EOFError, TimeoutError, ValueError, struct.error):
        result.failed += 1
    finally:
        result.frame_bytes += client.frame_bytes
        client.close()
    return result


def worker(payload: tuple[argparse.Namespace, int]) -> Counters:
    args, session_index = payload
    if args.mode == "uot-domain-churn":
        return run_uot_session(args, session_index)
    return run_tcp_session(args, session_index)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("mode", choices=("throughput", "latency", "mux", "stream-churn", "uot-domain-churn"))
    parser.add_argument("--host", required=True)
    parser.add_argument("--port", required=True, type=int)
    parser.add_argument("--password", required=True)
    parser.add_argument("--transport", choices=("plain", "tls"), required=True)
    parser.add_argument("--upstream-host", required=True)
    parser.add_argument("--upstream-port", required=True, type=int)
    parser.add_argument("--sessions", required=True, type=int)
    parser.add_argument("--streams-per-session", required=True, type=int)
    parser.add_argument("--payload-size", required=True, type=int)
    parser.add_argument("--bytes-per-stream", required=True, type=int)
    parser.add_argument("--iterations", required=True, type=int)
    parser.add_argument("--json-out", required=True)
    args = parser.parse_args()
    for name in ("sessions", "streams_per_session", "payload_size", "iterations"):
        if getattr(args, name) < 1:
            parser.error(f"--{name.replace('_', '-')} must be positive")
    if not 1 <= args.bytes_per_stream:
        parser.error("--bytes-per-stream must be positive")
    if args.payload_size > MAX_FRAME_DATA - 259:
        parser.error("--payload-size leaves no room for the first SOCKS address")
    return args


def main() -> None:
    args = parse_args()
    started = time.perf_counter()
    process_count = min(args.sessions, max(1, mp.cpu_count()))
    with mp.Pool(processes=process_count) as pool:
        samples = pool.map(worker, [(args, index) for index in range(args.sessions)])
    elapsed = time.perf_counter() - started
    total = Counters()
    for sample in samples:
        total.merge(sample)
    output = {
        "mode": args.mode,
        "transport": args.transport,
        "host": args.host,
        "port": args.port,
        "upstream_host": args.upstream_host,
        "upstream_port": args.upstream_port,
        "sessions": args.sessions,
        "streams_per_session": args.streams_per_session,
        "payload_size": args.payload_size,
        "bytes_per_stream": args.bytes_per_stream,
        "iterations": args.iterations,
        "useful_bytes": total.useful_bytes,
        "anytls_frame_bytes": total.frame_bytes,
        "wall_seconds": elapsed,
        "useful_throughput_bps": total.useful_bytes / elapsed if elapsed else 0.0,
        "latency_p50_ms": percentile(total.latencies_ms, 0.50),
        "latency_p95_ms": percentile(total.latencies_ms, 0.95),
        "latency_p99_ms": percentile(total.latencies_ms, 0.99),
        "latency_mean_ms": statistics.fmean(total.latencies_ms) if total.latencies_ms else 0.0,
        "succeeded_streams": total.succeeded,
        "failed_streams": total.failed,
    }
    destination = Path(args.json_out)
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(json.dumps(output, indent=2, sort_keys=True) + "\n")
    print(json.dumps(output, sort_keys=True))


if __name__ == "__main__":
    mp.freeze_support()
    main()
