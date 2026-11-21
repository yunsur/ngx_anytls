#!/usr/bin/env python3

import importlib.util
import struct
import sys
import unittest
from pathlib import Path


MODULE_PATH = Path(__file__).with_name("anytls_bench.py")
SPEC = importlib.util.spec_from_file_location("anytls_bench", MODULE_PATH)
bench = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = bench
assert SPEC.loader is not None
SPEC.loader.exec_module(bench)


class EncodingTests(unittest.TestCase):
    def test_frame_encodes_header_and_payload(self):
        self.assertEqual(
            bench.frame(bench.CMD_PSH, 0x01020304, b"abc"),
            b"\x02\x01\x02\x03\x04\x00\x03abc",
        )

    def test_frame_rejects_oversized_payload(self):
        with self.assertRaises(ValueError):
            bench.frame(bench.CMD_PSH, 1, b"x" * 65536)

    def test_socks_addresses_cover_ipv4_ipv6_and_domain(self):
        self.assertEqual(
            bench.socks_address("127.0.0.1", 443),
            b"\x01\x7f\x00\x00\x01\x01\xbb",
        )
        self.assertEqual(
            bench.socks_address("::1", 53),
            b"\x04" + b"\x00" * 15 + b"\x01\x00\x35",
        )
        self.assertEqual(
            bench.socks_address("example.test", 80),
            b"\x03\x0cexample.test\x00\x50",
        )

    def test_uot_domain_packet_encodes_lengths(self):
        self.assertEqual(
            bench.uot_packet("echo.test", 5353, b"data"),
            b"\x02\x09echo.test" + struct.pack("!HH", 5353, 4) + b"data",
        )


class MetricsTests(unittest.TestCase):
    def test_percentile_interpolates_sorted_values(self):
        self.assertEqual(bench.percentile([], 0.95), 0.0)
        self.assertEqual(bench.percentile([40.0, 10.0, 20.0, 30.0], 0.5), 25.0)

    def test_counters_merge_every_metric(self):
        left = bench.Counters(1, 2, 3, 4, [5.0])
        left.merge(bench.Counters(10, 20, 30, 40, [50.0]))
        self.assertEqual(left, bench.Counters(11, 22, 33, 44, [5.0, 50.0]))


if __name__ == "__main__":
    unittest.main()
