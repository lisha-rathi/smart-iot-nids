"""Hand-made checks for features.py. Run from iot_nids:  python capture\\tests\\test_features.py"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from features import FEATURE_NAMES, compute_features, to_row


def close(a, b, tol=0.05):
    return abs(a - b) <= tol


def check(name, ok):
    print(("PASS  " if ok else "FAIL  ") + name)
    return ok


results = []

# Flow 1: four packets worked out by hand
flow = [
    (0.00, "fwd", 100),
    (0.01, "bwd", 200),
    (0.03, "fwd", 300),
    (0.10, "bwd", 400),
]
f = compute_features(flow, 1883)
results += [
    check("order of names is the frozen order", list(f.keys()) == FEATURE_NAMES),
    check("Flow Duration = 100000 us", close(f["Flow Duration"], 100000)),
    check("Flow Bytes/s = 10000", close(f["Flow Bytes/s"], 10000)),
    check("Flow Packets/s = 40", close(f["Flow Packets/s"], 40)),
    check("Total Fwd Packets = 2", f["Total Fwd Packets"] == 2),
    check("Total Backward Packets = 2", f["Total Backward Packets"] == 2),
    check("Fwd Packet Length Mean = 200", close(f["Fwd Packet Length Mean"], 200)),
    check("Fwd Packet Length Std = 100", close(f["Fwd Packet Length Std"], 100)),
    check("Bwd Packet Length Mean = 300", close(f["Bwd Packet Length Mean"], 300)),
    check("Flow IAT Mean = 33333.33", close(f["Flow IAT Mean"], 33333.33)),
    check("Flow IAT Std = 26246.69", close(f["Flow IAT Std"], 26246.69)),
    check("Destination Port = 1883", f["Destination Port"] == 1883),
    check("Fwd IAT Total = 30000 us", close(f["Fwd IAT Total"], 30000)),
    check("packets in wrong time order give the same answer",
          compute_features(list(reversed(flow)), 1883) == f),
    check("to_row gives 12 numbers", len(to_row(f)) == 12),
]

# Flow 2: one single packet (no reply)
one = compute_features([(5.0, "fwd", 0)], 80)
results += [
    check("1 packet: duration 0", one["Flow Duration"] == 0),
    check("1 packet: rates are 0", one["Flow Bytes/s"] == 0 and one["Flow Packets/s"] == 0),
    check("1 packet: no bwd gives 0", one["Bwd Packet Length Mean"] == 0),
    check("1 packet: IAT is 0", one["Flow IAT Mean"] == 0 and one["Flow IAT Std"] == 0),
]

# Flow 3: a tiny burst (4 packets within 10 microseconds) must not give a crazy rate
burst = compute_features(
    [(1.0, "fwd", 100), (1.000003, "bwd", 100), (1.000006, "fwd", 100), (1.00001, "bwd", 100)], 443)
results += [
    check("burst: duration stays tiny (about 10 us)", close(burst["Flow Duration"], 10, 1)),
    check("burst: Flow Packets/s is capped by the 10 ms floor (400)", close(burst["Flow Packets/s"], 400, 0.5)),
    check("burst: Flow Bytes/s is 40000", close(burst["Flow Bytes/s"], 40000, 5)),
]

# Bad input must be rejected
def raises(fn):
    try:
        fn()
    except ValueError:
        return True
    return False


results += [
    check("empty flow is rejected", raises(lambda: compute_features([], 80))),
    check("bad direction is rejected", raises(lambda: compute_features([(0, "up", 1)], 80))),
    check("bad port is rejected", raises(lambda: compute_features([(0, "fwd", 1)], 70000))),
    check("missing feature is rejected", raises(lambda: to_row({"Flow Duration": 1.0}))),
]

print()
print("ALL PASSED" if all(results) else "SOME FAILED")
sys.exit(0 if all(results) else 1)
