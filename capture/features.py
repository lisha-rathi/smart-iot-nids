"""features.py - the ONE place where the 12 features are defined.

FROZEN when Phase 4 ends. If you change anything here after data
collection starts, you must collect the data again and retrain.

Input: the packets of one flow, as a list of (time_in_seconds, direction, payload_bytes)
  direction is "fwd" (sent by the flow starter) or "bwd" (the reply).
  payload_bytes is the TCP or UDP data size, without headers.
Units: Flow Duration, IAT values are in MICROSECONDS (like the old CICIDS model).
Rates (Flow Bytes/s, Flow Packets/s): a flow with fewer than 2 packets has rate 0.0.
Otherwise the time used is at least 10 ms (MIN_RATE_SECONDS), so a burst of a few
packets that arrive within microseconds does not give a crazy rate.
Std is the population std (divide by n).
"""
import math

FEATURE_NAMES = [
    "Flow Duration",
    "Flow Bytes/s",
    "Flow Packets/s",
    "Total Fwd Packets",
    "Total Backward Packets",
    "Fwd Packet Length Mean",
    "Fwd Packet Length Std",
    "Bwd Packet Length Mean",
    "Flow IAT Mean",
    "Flow IAT Std",
    "Destination Port",
    "Fwd IAT Total",
]

MIN_RATE_SECONDS = 0.01   # 10 ms: the shortest time used when working out the two rates


def _mean(values):
    return sum(values) / len(values) if values else 0.0


def _std(values):
    if len(values) < 2:
        return 0.0
    m = _mean(values)
    return math.sqrt(sum((v - m) ** 2 for v in values) / len(values))


def compute_features(packets, dst_port):
    """Return a dict with the 12 features, keys in FEATURE_NAMES order."""
    if not packets:
        raise ValueError("flow has no packets")
    if not isinstance(dst_port, int) or not 0 <= dst_port <= 65535:
        raise ValueError("bad destination port: %r" % (dst_port,))
    for p in packets:
        if p[1] not in ("fwd", "bwd"):
            raise ValueError("direction must be 'fwd' or 'bwd': %r" % (p[1],))
        if p[2] < 0:
            raise ValueError("payload size cannot be negative")

    pkts = sorted(packets, key=lambda p: p[0])
    times = [p[0] for p in pkts]
    fwd = [p for p in pkts if p[1] == "fwd"]
    bwd = [p for p in pkts if p[1] == "bwd"]

    duration_us = (times[-1] - times[0]) * 1e6
    total_bytes = sum(p[2] for p in pkts)
    if len(pkts) >= 2:
        seconds = max(duration_us / 1e6, MIN_RATE_SECONDS)
        bytes_per_s = total_bytes / seconds
        packets_per_s = len(pkts) / seconds
    else:
        bytes_per_s = 0.0
        packets_per_s = 0.0

    gaps = [(b - a) * 1e6 for a, b in zip(times, times[1:])]
    fwd_times = [p[0] for p in fwd]
    fwd_iat_total = (fwd_times[-1] - fwd_times[0]) * 1e6 if len(fwd_times) >= 2 else 0.0

    fwd_sizes = [p[2] for p in fwd]
    bwd_sizes = [p[2] for p in bwd]

    values = [
        duration_us,
        bytes_per_s,
        packets_per_s,
        float(len(fwd)),
        float(len(bwd)),
        _mean(fwd_sizes),
        _std(fwd_sizes),
        _mean(bwd_sizes),
        _mean(gaps),
        _std(gaps),
        float(dst_port),
        fwd_iat_total,
    ]
    return dict(zip(FEATURE_NAMES, values))


def to_row(features):
    """Dict -> list in the frozen order. Rejects missing or extra features."""
    if set(features) != set(FEATURE_NAMES):
        raise ValueError("feature names do not match the frozen list")
    return [features[name] for name in FEATURE_NAMES]