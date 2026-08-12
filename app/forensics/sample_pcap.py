from __future__ import annotations

import socket
import struct
import time
from pathlib import Path
from typing import Any


def _checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\x00"
    total = sum(struct.unpack(f"!{len(data) // 2}H", data))
    total = (total >> 16) + (total & 0xFFFF)
    total += total >> 16
    return (~total) & 0xFFFF


def _ipv4_udp_packet(
    src_ip: str,
    dst_ip: str,
    src_port: int,
    dst_port: int,
    payload: bytes,
) -> bytes:
    src_mac = bytes.fromhex("020000000001")
    dst_mac = bytes.fromhex("020000000002")
    ethernet = dst_mac + src_mac + struct.pack("!H", 0x0800)

    src = socket.inet_aton(src_ip)
    dst = socket.inet_aton(dst_ip)
    udp_length = 8 + len(payload)
    total_length = 20 + udp_length

    version_ihl = (4 << 4) | 5
    ip_header = struct.pack(
        "!BBHHHBBH4s4s",
        version_ihl,
        0,
        total_length,
        1,
        0,
        64,
        17,
        0,
        src,
        dst,
    )
    ip_checksum = _checksum(ip_header)
    ip_header = struct.pack(
        "!BBHHHBBH4s4s",
        version_ihl,
        0,
        total_length,
        1,
        0,
        64,
        17,
        ip_checksum,
        src,
        dst,
    )

    udp_header = struct.pack("!HHHH", src_port, dst_port, udp_length, 0)
    pseudo = src + dst + struct.pack("!BBH", 0, 17, udp_length)
    udp_checksum = _checksum(pseudo + udp_header + payload)
    if udp_checksum == 0:
        udp_checksum = 0xFFFF
    udp_header = struct.pack("!HHHH", src_port, dst_port, udp_length, udp_checksum)

    return ethernet + ip_header + udp_header + payload


def _dns_query(name: str = "sentinel.local") -> bytes:
    transaction_id = 0x1234
    flags = 0x0100
    header = struct.pack("!HHHHHH", transaction_id, flags, 1, 0, 0, 0)
    labels = b"".join(bytes([len(label)]) + label.encode("ascii") for label in name.split(".")) + b"\x00"
    question = labels + struct.pack("!HH", 1, 1)
    return header + question


def create_sample_pcap(path: str = "workspace/sample.pcap") -> dict[str, Any]:
    target = Path(path).expanduser().resolve()
    target.parent.mkdir(parents=True, exist_ok=True)

    packets = [
        _ipv4_udp_packet("192.0.2.10", "198.51.100.53", 53000, 53, _dns_query("sentinel.local")),
        _ipv4_udp_packet("192.0.2.10", "198.51.100.20", 54000, 4444, b"sentinel-network-test"),
    ]

    # Classic PCAP, little-endian, Ethernet link type.
    global_header = struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
    now = time.time()

    with target.open("wb") as handle:
        handle.write(global_header)
        for index, packet in enumerate(packets):
            ts = now + index
            seconds = int(ts)
            microseconds = int((ts - seconds) * 1_000_000)
            handle.write(struct.pack("<IIII", seconds, microseconds, len(packet), len(packet)))
            handle.write(packet)

    return {
        "path": str(target),
        "packets_written": len(packets),
        "size_bytes": target.stat().st_size,
        "description": "Synthetic local PCAP with one DNS query and one UDP flow",
    }
