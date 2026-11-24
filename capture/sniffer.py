"""sniffer.py - captures packets, builds flows, writes the 12 features of each flow.

Live (needs Npcap):   python capture\\sniffer.py --csv data\\features\\test.csv --seconds 30
Read a pcap file:     python capture\\sniffer.py --pcap some_file.pcap --csv out.csv
List interfaces:      python capture\\sniffer.py --list

The hotspot interface is found by its IP (default 192.168.137.1), because its
name and number change when the hotspot restarts.
Only IPv4 TCP and UDP packets are used. Everything else is counted as skipped.
"""
import argparse
import csv
import sys
import threading
import time
from collections import Counter
from datetime import datetime
from pathlib import Path

from scapy.all import AsyncSniffer, IP, PcapReader, TCP, UDP, conf

from features import FEATURE_NAMES
from flow_builder import FlowBuilder, PacketRecord

HOTSPOT_IP = "192.168.137.1"
GRACE_SECONDS = 0.5   # wait a little before closing a window, so slow packets still fit
CSV_COLUMNS = ["window_start", "src_ip", "dst_ip", "dst_port", "proto", "n_packets"] + FEATURE_NAMES


def _payload_size(pkt, l4, proto):
    """TCP/UDP data bytes, taken from the header lengths (ignores Ethernet padding)."""
    ip = pkt[IP]
    try:
        if proto == "TCP":
            size = ip.len - ip.ihl * 4 - l4.dataofs * 4
        else:
            size = l4.len - 8
    except TypeError:          # a field is missing
        size = None
    if size is None or size < 0:   # for example the length is 0 because of NIC offload
        size = len(l4.payload)
    return size


def packet_to_record(pkt):
    """scapy packet -> PacketRecord, or None if it is not IPv4 TCP or UDP."""
    if IP not in pkt:
        return None
    if TCP in pkt:
        l4, proto = pkt[TCP], "TCP"
    elif UDP in pkt:
        l4, proto = pkt[UDP], "UDP"
    else:
        return None
    ip = pkt[IP]
    return PacketRecord(
        float(pkt.time), ip.src, ip.dst, int(l4.sport), int(l4.dport),
        proto, _payload_size(pkt, l4, proto),
    )


class Sniffer:
    """Feeds packets to the FlowBuilder and calls on_flow(flow) for each finished flow."""

    def __init__(self, on_flow, window_seconds=1.0):
        self.builder = FlowBuilder(window_seconds)
        self.on_flow = on_flow
        self.lock = threading.Lock()   # the capture thread and the clock tick share the builder
        self.stats = Counter()
        self._last_packet_wall = 0.0   # clock time when we last handled a packet

    def handle(self, pkt):
        self.stats["packets_seen"] += 1
        self._last_packet_wall = time.time()
        rec = packet_to_record(pkt)
        if rec is None:
            self.stats["skipped"] += 1
            return
        self.stats["used"] += 1
        with self.lock:
            flows = self.builder.add_packet(rec)
        self._emit(flows)

    def tick(self, now):
        if now - self._last_packet_wall < GRACE_SECONDS:
            return   # packets are flowing: add_packet closes the windows by itself
        with self.lock:
            flows = self.builder.close_expired(now - GRACE_SECONDS)
        self._emit(flows)

    def finish(self):
        with self.lock:
            flows = self.builder.flush()
        self._emit(flows)

    def _emit(self, flows):
        for flow in flows:
            self.stats["flows"] += 1
            self.on_flow(flow)


def make_output(csv_path=None, quiet=False):
    """Returns (on_flow, close). on_flow prints a line and optionally writes a CSV row."""
    handle = writer = None
    if csv_path:
        path = Path(csv_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        is_new = not path.exists() or path.stat().st_size == 0
        handle = open(path, "a", newline="", encoding="utf-8")
        writer = csv.writer(handle)
        if is_new:
            writer.writerow(CSV_COLUMNS)

    def on_flow(flow):
        if writer:
            writer.writerow(
                [round(flow.window_start, 3), flow.src_ip, flow.dst_ip, flow.dst_port,
                 flow.proto, flow.n_packets] + [flow.features[n] for n in FEATURE_NAMES]
            )
            handle.flush()
        if not quiet:
            when = datetime.fromtimestamp(flow.window_start).strftime("%H:%M:%S")
            print("%s  %s -> %s:%s/%s  packets=%d  pps=%.0f  bytes/s=%.0f" % (
                when, flow.src_ip, flow.dst_ip, flow.dst_port, flow.proto, flow.n_packets,
                flow.features["Flow Packets/s"], flow.features["Flow Bytes/s"]))

    def close():
        if handle:
            handle.close()

    return on_flow, close


def list_interfaces():
    for iface in conf.ifaces.values():
        print("%-40s ip=%-16s %s" % (
            getattr(iface, "name", "?"), getattr(iface, "ip", "") or "-",
            getattr(iface, "description", "") or ""))


def find_interface(ip=None, name_part=None):
    for iface in conf.ifaces.values():
        if ip and getattr(iface, "ip", None) == ip:
            return iface
        if name_part and name_part.lower() in str(getattr(iface, "name", "")).lower():
            return iface
    return None


def run_pcap(sniffer, path):
    with PcapReader(str(path)) as reader:
        for pkt in reader:
            sniffer.handle(pkt)
    sniffer.finish()


def run_live(sniffer, iface, seconds):
    cap = AsyncSniffer(iface=iface, prn=sniffer.handle, store=False)
    cap.start()
    waited = 0.0
    while not cap.running and waited < 3.0:
        time.sleep(0.1)
        waited += 0.1
    if not cap.running:
        print("Could not start the capture. Is Npcap installed? Try an Admin terminal.")
        return False
    start = time.time()
    try:
        while seconds == 0 or time.time() - start < seconds:
            time.sleep(0.25)
            sniffer.tick(time.time())
    except KeyboardInterrupt:
        print("\nStopped with Ctrl+C.")
    finally:
        if cap.running:
            cap.stop()
        sniffer.finish()
    return True


def main():
    ap = argparse.ArgumentParser(description="Capture packets and write flow features.")
    ap.add_argument("--list", action="store_true", help="list interfaces and stop")
    ap.add_argument("--ip", default=HOTSPOT_IP, help="IP of the hotspot adapter (default %s)" % HOTSPOT_IP)
    ap.add_argument("--iface", help="part of an interface name (use instead of --ip)")
    ap.add_argument("--pcap", help="read this pcap file instead of capturing live")
    ap.add_argument("--csv", help="append one row per flow to this CSV file")
    ap.add_argument("--seconds", type=float, default=0, help="stop after this many seconds (0 = until Ctrl+C)")
    ap.add_argument("--quiet", action="store_true", help="do not print each flow")
    args = ap.parse_args()

    if args.list:
        list_interfaces()
        return 0

    on_flow, close = make_output(args.csv, args.quiet)
    sniffer = Sniffer(on_flow)
    try:
        if args.pcap:
            run_pcap(sniffer, args.pcap)
        else:
            iface = find_interface(None if args.iface else args.ip, args.iface)
            if iface is None:
                print("No interface found. Run with --list, then use --iface NAME or --ip IP.")
                return 1
            print("Capturing on: %s (ip %s). Ctrl+C to stop." % (iface.name, getattr(iface, "ip", "-")))
            if not run_live(sniffer, iface, args.seconds):
                return 1
    finally:
        close()
    s = sniffer.stats
    print("Done. packets seen=%d, used (IPv4 TCP/UDP)=%d, skipped=%d, flows=%d, late packets dropped=%d" % (
        s["packets_seen"], s["used"], s["skipped"], s["flows"], sniffer.builder.late_dropped))
    return 0


if __name__ == "__main__":
    sys.exit(main())