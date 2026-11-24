"""Compare the sniffer's flows with Wireshark's own numbers for the SAME pcap file.

Run from iot_nids:
  python capture\\tests\\check_against_wireshark.py data\\raw_pcap\\check1.pcap

For every flow it asks tshark for: packets forward, packets backward,
duration, and payload bytes. A flow is OK only if all of them agree.
"""
import shutil
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from features import MIN_RATE_SECONDS
from sniffer import Sniffer, run_pcap

WINDOWS_TSHARK = r"C:\Program Files\Wireshark\tshark.exe"


def tshark_path():
    if Path(WINDOWS_TSHARK).exists():
        return WINDOWS_TSHARK
    found = shutil.which("tshark")
    if not found:
        sys.exit("tshark not found")
    return found


def tshark_rows(tshark, pcap, display_filter, fields):
    cmd = [tshark, "-r", str(pcap), "-Y", display_filter, "-T", "fields"]
    for f in fields:
        cmd += ["-e", f]
    out = subprocess.run(cmd, capture_output=True, text=True, check=True).stdout
    return [line.split("\t") for line in out.splitlines() if line.strip()]


def main():
    if len(sys.argv) != 2:
        sys.exit("usage: python capture\\tests\\check_against_wireshark.py FILE.pcap")
    pcap = Path(sys.argv[1])
    tshark = tshark_path()

    flows = []
    sniffer = Sniffer(flows.append)
    run_pcap(sniffer, pcap)

    good = 0
    for f in flows:
        p = f.proto.lower()
        span = "frame.time_epoch >= %.6f && frame.time_epoch < %.6f" % (f.window_start, f.window_start + 1.0)
        fwd = "ip.src == %s && ip.dst == %s && %s.dstport == %d && %s" % (f.src_ip, f.dst_ip, p, f.dst_port, span)
        bwd = "ip.src == %s && ip.dst == %s && %s.srcport == %d && %s" % (f.dst_ip, f.src_ip, p, f.dst_port, span)
        len_field = "tcp.len" if p == "tcp" else "udp.length"

        w_fwd = len(tshark_rows(tshark, pcap, fwd, ["frame.number"]))
        w_bwd = len(tshark_rows(tshark, pcap, bwd, ["frame.number"]))
        both = tshark_rows(tshark, pcap, "(%s) || (%s)" % (fwd, bwd), ["frame.time_epoch", len_field])
        times = [float(r[0]) for r in both]
        w_dur_us = (max(times) - min(times)) * 1e6
        sizes = [int(r[1]) - (8 if p == "udp" else 0) for r in both]
        w_payload = sum(sizes)

        feat = f.features
        s_fwd, s_bwd = int(feat["Total Fwd Packets"]), int(feat["Total Backward Packets"])
        ok_pk = (s_fwd, s_bwd) == (w_fwd, w_bwd)
        ok_dur = abs(feat["Flow Duration"] - w_dur_us) <= 2.0
        if f.n_packets >= 2:
            seconds = max(feat["Flow Duration"] / 1e6, MIN_RATE_SECONDS)
            s_payload = feat["Flow Bytes/s"] * seconds
            ok_bytes = abs(s_payload - w_payload) <= 1.0
        else:
            s_payload, ok_bytes = None, True    # a 1-packet flow has no rate to check
        ok = ok_pk and ok_dur and ok_bytes
        good += ok
        print("%s  %s -> %s:%s/%s  fwd %d/%d  bwd %d/%d  dur %.0f/%.0f us  bytes %s/%d" % (
            "OK  " if ok else "DIFF", f.src_ip, f.dst_ip, f.dst_port, f.proto,
            s_fwd, w_fwd, s_bwd, w_bwd, feat["Flow Duration"], w_dur_us,
            "-" if s_payload is None else "%.0f" % s_payload, w_payload))

    print()
    print("(each pair is  sniffer/wireshark)")
    print("%d of %d flows agree with Wireshark" % (good, len(flows)))
    print("ALL MATCH" if good == len(flows) and flows else "SOME DIFFER")
    sys.exit(0 if good == len(flows) and flows else 1)


if __name__ == "__main__":
    main()