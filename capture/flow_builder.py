"""flow_builder.py - groups packets into flows and gives each flow its 12 features.

A FLOW = all packets of ONE (source IP, target IP, target port, protocol)
inside ONE time window (default 1 second), plus the replies to them.
The source port is NOT part of the key, so a SYN flood with a new source
port for every packet still becomes one big flow.

Each packet is a PacketRecord (made by sniffer.py, only TCP and UDP):
  ts (seconds), src_ip, dst_ip, src_port, dst_port, proto ("TCP" or "UDP"), payload_len

"fwd" = packets sent by the side that started the conversation.
"bwd" = packets from the other side (the replies).
If we first see a reply (for example the sniffer started in the middle of a
connection), we guess it is a reply when its source port is below 49152 and
its destination port is 49152 or more (a normal client port).

The IP addresses are only labels (for the whitelist and the firewall block).
They are NEVER given to the model. Only Flow.features goes to the model.
"""
from collections import namedtuple

from features import compute_features

PacketRecord = namedtuple(
    "PacketRecord", "ts src_ip dst_ip src_port dst_port proto payload_len"
)
Flow = namedtuple(
    "Flow", "window_start src_ip dst_ip dst_port proto n_packets features"
)

EPHEMERAL_START = 49152


class FlowBuilder:
    def __init__(self, window_seconds=1.0, key_memory_seconds=60.0):
        if window_seconds <= 0:
            raise ValueError("window_seconds must be above 0")
        self.window = float(window_seconds)
        self.memory = float(key_memory_seconds)
        self._open = {}        # (window_number, key) -> list of (ts, direction, payload)
        self._known = {}       # key -> last time seen (key = sender started the talk)
        self._closed_up_to = -1
        self._latest_ts = 0.0
        self.late_dropped = 0  # packets that came after their window was closed

    # ---- public ----
    def add_packet(self, pkt):
        """Add one packet. Returns the list of flows that just finished."""
        win = int(pkt.ts // self.window)
        if win <= self._closed_up_to:
            self.late_dropped += 1
            return []
        self._latest_ts = max(self._latest_ts, pkt.ts)
        done = self._close_before(win)
        key, direction = self._classify(pkt)
        self._open.setdefault((win, key), []).append(
            (pkt.ts, direction, pkt.payload_len)
        )
        return done

    def close_expired(self, now):
        """Call now and then with the clock time. Closes windows that are over."""
        self._latest_ts = max(self._latest_ts, now)
        return self._close_before(int(now // self.window))

    def flush(self):
        """Close everything that is still open (end of a capture)."""
        return self._close_before(None)

    # ---- inside ----
    def _is_known(self, key, ts):
        last = self._known.get(key)
        return last is not None and ts - last <= self.memory

    def _classify(self, pkt):
        fwd_key = (pkt.src_ip, pkt.dst_ip, pkt.dst_port, pkt.proto)
        rev_key = (pkt.dst_ip, pkt.src_ip, pkt.src_port, pkt.proto)
        if self._is_known(fwd_key, pkt.ts):
            self._known[fwd_key] = pkt.ts
            return fwd_key, "fwd"
        if self._is_known(rev_key, pkt.ts):
            self._known[rev_key] = pkt.ts
            return rev_key, "bwd"
        # first time we see this pair
        if pkt.src_port < EPHEMERAL_START <= pkt.dst_port:
            self._known[rev_key] = pkt.ts      # looks like a reply
            return rev_key, "bwd"
        self._known[fwd_key] = pkt.ts
        return fwd_key, "fwd"

    def _close_before(self, win):
        if win is None:
            names = sorted(self._open)
            if names:
                self._closed_up_to = max(self._closed_up_to, names[-1][0])
        else:
            names = sorted(n for n in self._open if n[0] < win)
            self._closed_up_to = max(self._closed_up_to, win - 1)
        flows = []
        for name in names:
            packets = self._open.pop(name)
            number, (src, dst, dport, proto) = name
            flows.append(
                Flow(number * self.window, src, dst, dport, proto,
                     len(packets), compute_features(packets, dport))
            )
        self._prune()
        return flows

    def _prune(self):
        cutoff = self._latest_ts - self.memory
        for key in [k for k, last in self._known.items() if last < cutoff]:
            del self._known[key]