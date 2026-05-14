#!/usr/bin/env python3
import os
import sys
import re
import time
import struct
import socket
import statistics
import argparse
from datetime import datetime, timezone, timedelta
from dataclasses import dataclass
from typing import Optional


# Data Handling
# ---------------------------------------

ICMP_TIMESTAMP_REQUEST = 13
ICMP_TIMESTAMP_REPLY = 14
PROC_IDENT = os.getpid() & 0xffff

IPV4_RE = re.compile(
    r"^(25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)\."
    r"(25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)\."
    r"(25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)\."
    r"(25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)$"
)

IPV6_RE = re.compile(
    r"^("
    r"([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}|"
    r"([0-9a-fA-F]{1,4}:){1,7}:|"
    r"([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|"
    r"([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|"
    r"([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|"
    r"([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|"
    r"([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|"
    r"[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|"
    r":((:[0-9a-fA-F]{1,4}){1,7}|:)"
    r")$"
)

@dataclass
class Asset:
    target: str
    ipv4: Optional[str] = None
    ipv6: Optional[str] = None

@dataclass
class Stats:
    values: list[float]

    def __post_init__(self):
        self.avg = statistics.mean(self.values)
        self.min = min(self.values)
        self.max = max(self.values)
        self.stdev = (
            statistics.stdev(self.values)
            if len(self.values) > 1 else 0.0)

@dataclass
class ICMPRequest:
    packet_format: str = "!BBHHHIII"
    icmp_type: int = 0
    code: int = 0
    checksum: int = 0
    ident: int = PROC_IDENT
    sequence: int = 0
    originate_ts: int = 0
    receive_ts: int = 0
    transmit_ts: int = 0

    def pack(self) -> bytes:
        packet = struct.pack(
            self.packet_format,
            self.icmp_type,
            self.code,
            self.checksum,
            self.ident,
            self.sequence,
            self.originate_ts,
            self.receive_ts,
            self.transmit_ts)

        return (
            packet[:2]
            + struct.pack("!H", mk_checksum(packet))
            + packet[4:])

@dataclass
class ICMPReply:
    icmp_type: int
    code: int
    checksum: int
    ident: int
    sequence: int
    originate_ms: int
    receive_ms: int
    transmit_ms: int

    @classmethod
    def unpack(cls, packet: bytes):
        return cls(*struct.unpack("!BBHHHIII", packet[:20]))


# Helper Functions
# ---------------------------------------

def resolve_asset(target: str) -> Asset:
    ipv4 = None
    ipv6 = None

    # Direct IP input
    if IPV4_RE.match(target):
        ipv4 = target
    elif IPV6_RE.match(target):
        ipv6 = target
    else:
        # DNS lookup
        try:
            infos = socket.getaddrinfo(target, None)
            for info in infos:
                family, _, _, _, sockaddr = info
                if family == socket.AF_INET and not ipv4:
                    ipv4 = sockaddr[0]
                elif family == socket.AF_INET6 and not ipv6:
                    ipv6 = sockaddr[0]
        except socket.gaierror:
            raise ValueError("Could not resolve target")

    return Asset(target=target, ipv4=ipv4, ipv6=ipv6)

def mk_checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\x00"

    total = 0

    for i in range(0, len(data), 2):
        total += (data[i] << 8) | data[i + 1]

    while total >> 16:
        total = (total & 0xffff) + (total >> 16)

    return (~total) & 0xffff

def ms_since_midnight_utc() -> int:
    now = datetime.now(timezone.utc)
    midnight = now.replace(hour=0, minute=0, second=0, microsecond=0)
    return int((now - midnight).total_seconds() * 1000)

def decode_ms(ms: int) -> str:
    return str(timedelta(milliseconds=ms % 86_400_000))

def parse_ipv4_icmp(raw_packet: bytes) -> bytes:
    ip_header_len = (raw_packet[0] & 0x0F) * 4
    return raw_packet[ip_header_len:]

# Estimate clock drift slope in ms/sec using simple linear regression.
def linear_slope(packets: list):

    if len(packets) < 2:
        return 0.0

    x0 = packets[0]["local_recv_ts"]
    xs = [p["local_recv_ts"] - x0 for p in packets]
    ys = [p["offset_ms"] for p in packets]

    return statistics.linear_regression(xs, ys).slope


# ICMP packet handler
# ---------------------------------------

def send_icmp_ts(sock: socket.socket, asset: Asset, sequence: int, timeout: float):
    
    originate_ms = ms_since_midnight_utc()
    send_mono = time.monotonic()
    
    packet = ICMPRequest(   
        sequence=sequence,
        icmp_type=ICMP_TIMESTAMP_REQUEST,
        originate_ts=originate_ms).pack()
    sock.settimeout(timeout)
    sock.sendto(packet, (asset.ipv4, 0))

    try:
        while True:
            raw_packet, source = sock.recvfrom(1024)
            local_recv_ts = time.monotonic()
            local_recv_wall_ms = ms_since_midnight_utc()
            reply = ICMPReply.unpack(parse_ipv4_icmp(raw_packet))

            if (reply.icmp_type, reply.ident, reply.sequence) != (
                ICMP_TIMESTAMP_REPLY,PROC_IDENT,sequence):
                continue

            offset_ms = (
                (reply.receive_ms - originate_ms)
                + (reply.transmit_ms - local_recv_wall_ms)
            ) / 2

            return {
                "sequence": sequence,
                "source": source[0],
                "originate_ms": reply.originate_ms,
                "receive_ms": reply.receive_ms,
                "transmit_ms": reply.transmit_ms,
                "rtt_ms": (local_recv_ts - send_mono) * 1000,
                "processing_ms": reply.transmit_ms - reply.receive_ms,
                "offset_ms": offset_ms,
                "local_recv_ts": local_recv_ts}

    except socket.timeout:
        return False


# ICMP request modes
# ---------------------------------------

def icmp_audit_all(args, asset):
    for audit in list(ICMP_AUDIT_EXEC)[1:]:
        ICMP_AUDIT_EXEC[audit]["runner"](args, asset)

def icmp_audit_echo(args, asset):
    print("\n---------------------------------------")
    print("ICMP Echo (Mode 0) is not implemented yet.")

def icmp_audit_ts(args, asset):    

    if not asset.ipv4:
        print("ICMP Timestamp requires an IPv4 address.")
        return

    print("\n---------------------------------------")
    print("ICMP Timestamp Disclosure (Mode 13/14)")
    
    packets = []
    with socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP) as sock:
        for seq in range(1, args.count + 1):
            result = send_icmp_ts(
                timeout=args.timeout,
                sequence=seq,
                asset=asset,
                sock=sock)
            
            if args.verbose: 
                if not result: 
                    print(f"seq={seq} Timeout exceeded")
                else:
                    print(
                        f"seq={result['sequence']} "
                        f"rtt={result['rtt_ms']:.3f}ms "
                        f"offset={result['offset_ms']:.3f}ms "
                        f"proc={result['processing_ms']}ms "
                        f"orig={decode_ms(result['originate_ms'])} "
                        f"tx={decode_ms(result['transmit_ms'])} "
                        f"recv={decode_ms(result['receive_ms'])}")
            packets.append(result)
            time.sleep(args.interval)
    
    packets = [p for p in packets if p]
    received = len(packets)

    if not received:
        print("\n---------------------------------------")
        print("Timestamp Fingerprint Summary")
        print("No ICMP timestamp replies received.")
        return

    rtt = Stats([p["rtt_ms"] for p in packets])
    offset = Stats([p["offset_ms"] for p in packets])
    proc = Stats([p["processing_ms"] for p in packets])
    loss_pct = 100 * (1 - (received / args.count)) 
    drift_ms_per_sec = linear_slope(packets)
    local_time = ms_since_midnight_utc()
    remote_time = int((local_time +offset.avg) % 86_400_000)
    
    match offset.avg:
        case x if abs(x) < 50:
            offset_desc = "near-synchronised clock"
        case x if x > 0:
            offset_desc = "remote clock appears ahead"
        case _:
            offset_desc = "remote clock appears behind"

    match proc.avg:
        case x if x > 5:
            proc_desc = "noticeable processing delay"
        case x if x > 0:
            proc_desc = "low processing delay"
        case _:
            proc_desc = "zero or rounded processing delay"

    match drift_ms_per_sec:
        case x if x > 0.01:
            drift_desc = "remote clock appears to drift faster than local"
        case x if x < -0.01:
            drift_desc = "remote clock appears to drift slower than local"
        case _:
            drift_desc = "no obvious short-window clock drift"

    match rtt.stdev:
        case x if x < 2:
            rtt_stdev_desc ="low RTT jitter"
        case x if x < 10:
            rtt_stdev_desc ="moderate RTT jitter"
        case _:
            rtt_stdev_desc ="high RTT jitter"

    print("\n---------------------------------------")
    print("[+] Simple Timestamp Fingerprint")
    print(f"- {offset_desc}")
    print(f"- {rtt_stdev_desc}")
    print(f"- {proc_desc}")
    print(f"- {drift_desc}")
    print("\n---------------------------------------")
    print("\n[+] Timestamp Fingerprint Summary")
    print(f"Packets sent:                  {args.count}")
    print(f"Replies received:              {received}")
    print(f"Packet loss:                   {loss_pct:.1f}%")
    print()
    print(f"Local Time (HH:MM:SS):         {decode_ms(local_time)} UTC")
    print(f"Remote Time (HH:MM:SS):        {decode_ms(remote_time)} UTC")
    print()
    print(f"RTT avg:                       {rtt.avg:.3f} ms")
    print(f"RTT min/max:                   {rtt.min:.3f} / {rtt.max:.3f} ms")
    print(f"RTT jitter stdev:              {rtt.stdev:.3f} ms ({rtt_stdev_desc})")
    print()
    print(f"Clock offset avg:              {offset.avg:.3f} ms")
    print(f"Clock offset min/max:          {offset.min:.3f} / {offset.max:.3f} ms")
    print(f"Clock offset stability stdev:  {offset.stdev:.3f} ms")
    print()
    print(f"Remote processing avg:         {proc.avg:.3f} ms")
    print(f"Estimated clock drift:         {drift_ms_per_sec:.6f} ms/sec")    

ICMP_AUDIT_EXEC = {
    "all": {
        "description": "Run all ICMP Checks",
        "runner": icmp_audit_all,
    },
    "echo": {
        "description": "ICMP Echo Request/Reply",
        "runner": icmp_audit_echo,
    },
    "timestamp": {
        "description": "ICMP Timestamp Request/Reply",
        "runner": icmp_audit_ts}}


# main
# ---------------------------------------

def parse_args():
    p = argparse.ArgumentParser(description="ICMP fingerprinting tool for authorised testing.")
    p.add_argument( "target", help="target address or hostname")
    p.add_argument("-m", "--mode", default="all", choices=ICMP_AUDIT_EXEC.keys(), help="ICMP fingerprint mode")
    p.add_argument("-c", "--count", type=int, default=5, help="number of probes to send")
    p.add_argument("-i", "--interval", type=float, default=1.0, help="seconds between probes")
    p.add_argument("-t", "--timeout", type=float, default=2.0, help="reply timeout in seconds")
    p.add_argument("-v", "--verbose", action="store_true", help="print verbose info")
    args = p.parse_args()

    # Sanity checks
    match args:
        case x if args.count < 1:
            raise ValueError("count must be at least 1")
        case x if args.interval < 0:
            raise ValueError("interval cannot be negative")
        case x if args.timeout <= 0:
            raise ValueError("timeout must be greater than zero")
        case _: 
            return args

def main():
    print("\n-------------------------------------------")
    print("|             ICMP Audit Tool             |")
    print("-------------------------------------------\n")

    args = parse_args()
    asset = resolve_asset(args.target)

    print(f"target: {args.target}")
    print(f"IPv4:   {asset.ipv4}")
    print(f"IPv6:   {asset.ipv6}")

    ICMP_AUDIT_EXEC[args.mode]["runner"](args, asset)

if __name__ == "__main__":
    try: main() 
    except PermissionError:
        print("\n[!] Error: raw ICMP sockets requires elevated privileges.")
        print(f"Try: sudo python3 icmp-audit.py <target>")
        sys.exit(1)
    except KeyboardInterrupt:
        print("\n [!] Error: Interrupted.")
        sys.exit(130)
    except RuntimeError as exc:
        print(f"\n [!] Warning: {exc}")
    except Exception as exc:
        print(f"\n [!] Error: {exc}")
        sys.exit(1)
