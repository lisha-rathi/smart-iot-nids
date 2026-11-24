"""Hand-made checks for sniffer.py (no live capture needed).
Run from iot_nids:  python capture\\tests\\test_sniffer.py"""
import csv
import sys
import tempfile
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from scapy.all import ARP, Ether, ICMP, IP, IPv6, Raw, TCP, UDP, wrpcap

from features import FEATURE_NAMES
from sniffer import CSV_COLUMNS, Sniffer, make_output, packet_to_record, run_pcap

ESP, LAP, ATK = "192.168.137.50", "192.168.137.1", "192.168.137.99"


def check(name, ok):
    print(("PASS  " if ok else "FAIL  ") + name)
    return ok


def wire(pkt, ts, pad=0):
    """Build the bytes, add optional Ethernet padding, read it back like a real capture."""
    pkt[Ether].src = "aa:bb:cc:dd:ee:01"
    pkt[Ether].dst = "aa:bb:cc:dd:ee:02"
    raw = bytes(pkt) + b"\x00" * pad
    out = Ether(raw)
    out.time = ts
    return out


def tcp(src, dst, sport, dport, payload=b"", flags="PA", ts=0.0, pad=0):
    return wire(Ether() / IP(src=src, dst=dst) / TCP(sport=sport, dport=dport, flags=flags) / Raw(payload), ts, pad)


def udp(src, dst, sport, dport, payload=b"", ts=0.0):
    return wire(Ether() / IP(src=src, dst=dst) / UDP(sport=sport, dport=dport) / Raw(payload), ts)


results = []

# --- packet_to_record ---
r = packet_to_record(tcp(ESP, LAP, 50000, 1883, b"x" * 60, ts=123.5))
results += [
    check("TCP: ports, protocol, time", r and (r.src_ip, r.dst_ip, r.src_port, r.dst_port, r.proto, r.ts)
          == (ESP, LAP, 50000, 1883, "TCP", 123.5)),
    check("TCP: payload is 60 bytes", r and r.payload_len == 60),
]
r = packet_to_record(tcp(LAP, ESP, 1883, 50000, b"", flags="A", ts=1.0, pad=6))
results += [check("TCP: Ethernet padding is not counted (payload 0)", r and r.payload_len == 0)]
r = packet_to_record(udp(ATK, ESP, 20000, 5005, b"y" * 100, ts=2.0))
results += [check("UDP: payload is 100 bytes", r and r.proto == "UDP" and r.payload_len == 100)]
p = Ether() / IP(src=ESP, dst=LAP, len=0) / TCP(sport=50000, dport=1883) / Raw(b"z" * 60)
r = packet_to_record(wire(p, 3.0))
results += [check("IP length 0 (NIC offload): falls back to real payload (60)", r and r.payload_len == 60)]
results += [
    check("ICMP is skipped", packet_to_record(wire(Ether() / IP(src=ESP, dst=LAP) / ICMP(), 1.0)) is None),
    check("ARP is skipped", packet_to_record(wire(Ether() / ARP(), 1.0)) is None),
    check("IPv6 is skipped", packet_to_record(wire(Ether() / IPv6() / TCP(), 1.0)) is None),
]

# --- whole path: pcap file -> sniffer -> flows -> CSV ---
packets = []
packets.append(tcp(ESP, LAP, 50000, 1883, b"m" * 60, ts=1000.00))          # normal MQTT
packets.append(tcp(LAP, ESP, 1883, 50000, b"", flags="A", ts=1000.01))
for i in range(100):                                                       # SYN flood, new source port each time
    t = 1001.0 + i * 0.005
    packets.append(tcp(ATK, ESP, 30000 + i, 1883, b"", flags="S", ts=t))
    packets.append(tcp(ESP, ATK, 1883, 30000 + i, b"", flags="SA", ts=t + 0.001))
packets.append(arp := wire(Ether() / ARP(), 1001.2))                       # noise, must be skipped
packets.append(tcp(ESP, LAP, 50000, 1883, b"m" * 60, ts=1003.0))           # closes the flood window

with tempfile.TemporaryDirectory() as tmp:
    pcap = Path(tmp) / "hand_made.pcap"
    csv_path = Path(tmp) / "flows.csv"
    wrpcap(str(pcap), packets)
    on_flow, close = make_output(str(csv_path), quiet=True)
    got = []
    sn = Sniffer(lambda f: (got.append(f), on_flow(f)))
    run_pcap(sn, pcap)
    close()
    with open(csv_path, newline="", encoding="utf-8") as fh:
        rows = list(csv.reader(fh))

mqtt = [f for f in got if f.src_ip == ESP and f.dst_ip == LAP]
flood = [f for f in got if f.src_ip == ATK]
results += [
    check("pcap: 3 flows (MQTT, flood, MQTT again)", len(got) == 3),
    check("pcap: skipped count is 1 (the ARP packet)", sn.stats["skipped"] == 1),
    check("pcap: flood is ONE flow with 100 fwd and 100 bwd",
          len(flood) == 1 and flood[0].features["Total Fwd Packets"] == 100
          and flood[0].features["Total Backward Packets"] == 100),
    check("pcap: flood packets/s is about 403", flood and abs(flood[0].features["Flow Packets/s"] - 403.2) < 2),
    check("pcap: first MQTT flow has 1 fwd (60 bytes) and 1 bwd", mqtt
          and mqtt[0].features["Total Fwd Packets"] == 1 and mqtt[0].features["Total Backward Packets"] == 1
          and mqtt[0].features["Fwd Packet Length Mean"] == 60),
    check("csv: header is the 6 labels + 12 features", rows[0] == CSV_COLUMNS and len(CSV_COLUMNS) == 18),
    check("csv: one row per flow", len(rows) == 1 + len(got)),
    check("csv: every row has 18 columns", all(len(r) == 18 for r in rows)),
]

# --- tick: only closes windows when traffic has stopped ---
got2 = []
sn2 = Sniffer(got2.append)
sn2.handle(tcp(ESP, LAP, 50000, 1883, b"m" * 60, ts=2000.2))
sn2.tick(time.time() + 0.1)   # a packet was handled just now: must not close yet
results += [check("tick: does not close windows while packets are flowing", got2 == [])]
sn2.tick(time.time() + 5)     # quiet for a while: closes now
results += [check("tick: closes the window when traffic stops", len(got2) == 1)]
print()
print("ALL PASSED" if all(results) else "SOME FAILED")
sys.exit(0 if all(results) else 1)