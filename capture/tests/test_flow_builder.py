"""Hand-made checks for flow_builder.py. Run from iot_nids:  python capture\\tests\\test_flow_builder.py"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from features import FEATURE_NAMES, to_row
from flow_builder import FlowBuilder, PacketRecord

ESP = "192.168.137.50"
LAP = "192.168.137.1"
ATK = "192.168.137.99"


def check(name, ok):
    print(("PASS  " if ok else "FAIL  ") + name)
    return ok


def close(a, b, tol=1.0):
    return abs(a - b) <= tol


def feed(fb, packets):
    out = []
    for p in packets:
        out += fb.add_packet(p)
    return out


results = []

# 1. Normal MQTT: ESP32 -> laptop:1883, 3 packets in one second, then a packet in the next second
fb = FlowBuilder()
out = feed(fb, [
    PacketRecord(10.00, ESP, LAP, 50000, 1883, "TCP", 60),
    PacketRecord(10.01, LAP, ESP, 1883, 50000, "TCP", 0),
    PacketRecord(10.50, ESP, LAP, 50000, 1883, "TCP", 0),
    PacketRecord(11.20, ESP, LAP, 50000, 1883, "TCP", 60),
])
f = out[0] if out else None
results += [
    check("1: one flow finished when the next window starts", len(out) == 1),
    check("1: flow has 3 packets, 2 fwd and 1 bwd",
          f and f.n_packets == 3 and f.features["Total Fwd Packets"] == 2
          and f.features["Total Backward Packets"] == 1),
    check("1: labels are ESP -> LAP, port 1883, TCP",
          f and (f.src_ip, f.dst_ip, f.dst_port, f.proto) == (ESP, LAP, 1883, "TCP")),
    check("1: features are in the frozen order", f and list(f.features) == FEATURE_NAMES),
    check("1: to_row gives 12 numbers", f and len(to_row(f.features)) == 12),
]

# 2. SYN flood: 100 SYNs with a NEW source port each, plus 100 replies, in one window
fb = FlowBuilder()
pk = []
for i in range(100):
    t = 20.0 + i * 0.005
    pk.append(PacketRecord(t, ATK, ESP, 30000 + i, 1883, "TCP", 0))
    pk.append(PacketRecord(t + 0.001, ESP, ATK, 1883, 30000 + i, "TCP", 0))
pk.append(PacketRecord(21.0, ESP, LAP, 50000, 1883, "TCP", 60))
out = feed(fb, pk)
f = out[0] if out else None
results += [
    check("2: random source ports still make ONE flow", len(out) == 1),
    check("2: 100 fwd and 100 bwd packets",
          f and f.features["Total Fwd Packets"] == 100 and f.features["Total Backward Packets"] == 100),
    check("2: Flow Packets/s is about 403", f and close(f.features["Flow Packets/s"], 403.2)),
    check("2: the flow is labeled with the attacker IP", f and f.src_ip == ATK),
]

# 3. Two windows from the same pair give two flows
fb = FlowBuilder()
out = feed(fb, [
    PacketRecord(30.1, ESP, LAP, 50000, 1883, "TCP", 60),
    PacketRecord(31.1, ESP, LAP, 50000, 1883, "TCP", 60),
    PacketRecord(32.1, ESP, LAP, 50000, 1883, "TCP", 60),
])
results += [check("3: windows 30 and 31 closed, in order",
                  [x.window_start for x in out] == [30.0, 31.0])]

# 4. close_expired uses the clock, not the next packet
fb = FlowBuilder()
fb.add_packet(PacketRecord(40.2, ESP, LAP, 50000, 1883, "TCP", 60))
results += [
    check("4: window not over yet gives nothing", fb.close_expired(40.9) == []),
    check("4: window over gives 1 flow", len(fb.close_expired(41.1)) == 1),
]

# 5. We see the reply first (sniffer started in the middle of a connection)
fb = FlowBuilder()
fb.add_packet(PacketRecord(50.00, LAP, ESP, 1883, 50000, "TCP", 0))
fb.add_packet(PacketRecord(50.01, ESP, LAP, 50000, 1883, "TCP", 60))
out = fb.flush()
f = out[0] if out else None
results += [
    check("5: reply-first still ends up as ONE flow", len(out) == 1),
    check("5: the flow is ESP -> LAP port 1883 (not the client port)",
          f and (f.src_ip, f.dst_port) == (ESP, 1883)),
    check("5: 1 fwd and 1 bwd", f and f.features["Total Fwd Packets"] == 1
          and f.features["Total Backward Packets"] == 1),
]

# 6. Different targets are different flows
fb = FlowBuilder()
fb.add_packet(PacketRecord(60.1, ATK, ESP, 40000, 1883, "TCP", 0))
fb.add_packet(PacketRecord(60.2, ATK, LAP, 40001, 80, "TCP", 100))
fb.add_packet(PacketRecord(60.3, ATK, LAP, 40002, 80, "UDP", 100))
results += [check("6: different port or protocol means different flow", len(fb.flush()) == 3)]

# 7. A late packet (its window is already closed) is dropped and counted
fb = FlowBuilder()
fb.add_packet(PacketRecord(71.2, ESP, LAP, 50000, 1883, "TCP", 60))
out = fb.add_packet(PacketRecord(70.5, ESP, LAP, 50000, 1883, "TCP", 60))
results += [check("7: late packet dropped and counted (count is 1)", out == [] and fb.late_dropped == 1)]
fb.close_expired(72.5)
out = fb.add_packet(PacketRecord(71.5, ESP, LAP, 50000, 1883, "TCP", 60))
results += [check("7b: packet for a closed window is dropped (count is 2)", out == [] and fb.late_dropped == 2)]

# 8. UDP flood with no replies
fb = FlowBuilder()
for i in range(50):
    fb.add_packet(PacketRecord(80.0 + i * 0.01, ATK, ESP, 20000 + i, 5005, "UDP", 100))
out = fb.flush()
f = out[0] if out else None
results += [
    check("8: UDP flood is one flow with 50 fwd and 0 bwd",
          len(out) == 1 and f.features["Total Fwd Packets"] == 50
          and f.features["Total Backward Packets"] == 0),
    check("8: Bwd Packet Length Mean is 0 (no replies)", f and f.features["Bwd Packet Length Mean"] == 0),
]

print()
print("ALL PASSED" if all(results) else "SOME FAILED")
sys.exit(0 if all(results) else 1)