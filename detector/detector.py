"""
Live detector: watches flows, asks the Random Forest, raises an alert when
3 of the last 5 flows from one source IP are attacks, then (optionally)
blocks that IP in the Windows firewall and sends ALERT_ON to the ESP32.

Reuses capture\\sniffer.py unchanged. Settings: config\\settings.json.
Also writes data\\security_status.json once a second for the dashboard (Phase 8).

Replay a recording (nothing live, no MQTT):
    python detector\\detector.py --pcap data\\raw_pcap\\session06_udpflood.pcap --no-mqtt
Live, safe mode (prints "would block", still sends ALERT_ON):
    python detector\\detector.py
Live, really blocks (needs an Admin terminal):
    python detector\\detector.py --arm
"""
import argparse
import collections
import ipaddress
import json
import os
import subprocess
import sys
import threading
import time
from pathlib import Path

import joblib
import numpy as np
import pandas as pd

IOT_ROOT = Path(__file__).resolve().parent.parent
STATUS_PATH = IOT_ROOT / "data" / "security_status.json"
sys.path.insert(0, str(IOT_ROOT / "capture"))
import sniffer as capture  # noqa: E402  (the frozen capture code)


def say(text):
    print(time.strftime("%H:%M:%S ") + text, flush=True)


def make_sender(cfg, enabled):
    if not enabled:
        return lambda cmd: say("(MQTT off) would send " + cmd)
    try:
        import paho.mqtt.client as mqtt
        client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2)
        client.connect(cfg["mqtt_host"], cfg["mqtt_port"], 60)
        client.loop_start()
    except Exception as exc:
        say("MQTT not reachable (%s). Is the broker running? Continuing without it." % exc)
        return lambda cmd: say("(MQTT failed) would send " + cmd)

    def send(cmd):
        client.publish(cfg["cmd_topic"], cmd, qos=1)
        say("sent " + cmd + " to the ESP32")
    return send


class Detector:
    def __init__(self, cfg, send_cmd, dry_run, verbose):
        folder = IOT_ROOT / cfg["model_dir"]
        suffix = "_noport" if cfg["model_variant"] == "noport" else ""
        self.model = joblib.load(folder / ("rf_model%s.pkl" % suffix))
        self.scaler = joblib.load(folder / ("scaler%s.pkl" % suffix))
        self.feats = json.loads((folder / ("feature_names%s.json" % suffix)).read_text())
        self.attack_col = list(self.model.classes_).index(1)
        self.protected = {cfg["defender_ip"], cfg["esp32_ip"]}
        self.whitelist = set(cfg["whitelist"]) | self.protected
        self.protected_port = cfg["protected_port"]
        self.window = cfg["flows_window"]
        self.needed = cfg["flows_needed"]
        self.block_seconds = cfg["block_seconds"]
        # an attack flow keeps a block alive only if it has at least this many packets
        self.extend_min_packets = cfg.get("extend_min_packets", 5)
        self.send_cmd = send_cmd
        self.dry_run = dry_run
        self.verbose = verbose
        self.history = {}
        self.active = {}
        self.buzzer_on = False
        self.last_burst = 0.0
        self.alert_off_delay = cfg.get("alert_off_delay", 5)
        self.counts = collections.Counter()
        self.lock = threading.RLock()
        self.stop = threading.Event()
        # for the dashboard status file
        self.recent = collections.deque(maxlen=10)   # newest scored flow first
        self.traffic = collections.deque()           # (time, packets) of every flow, for packets per second
        self.last_verdict = None
        say("model: %s, features: %d, protected hosts: %s" % (
            cfg["model_variant"], len(self.feats), sorted(self.protected)))
        say("mode: %s" % ("DRY RUN (no firewall changes)" if dry_run else "ARMED (real firewall blocks)"))

    def write_status(self, running=True):
        """Write a small JSON file that the dashboard reads. Never raises."""
        now = time.time()
        with self.lock:
            while self.traffic and now - self.traffic[0][0] > 5:
                self.traffic.popleft()
            pps = sum(n for _, n in self.traffic) / 5.0
            data = {
                "updated": now,
                "running": running,
                "mode": "DRY RUN" if self.dry_run else "ARMED",
                "alert": bool(self.active),
                "pps": round(pps, 1),
                "blocked": [{"ip": ip, "seconds_left": max(0, int(st["until"] - now))}
                            for ip, st in self.active.items()],
                "last_verdict": self.last_verdict,
                "recent": list(self.recent),
                "counts": dict(self.counts),
                "rule": "%d of the last %d flows" % (self.needed, self.window),
            }
        try:
            STATUS_PATH.parent.mkdir(parents=True, exist_ok=True)
            tmp = STATUS_PATH.with_suffix(".tmp")
            tmp.write_text(json.dumps(data), encoding="utf-8")
            os.replace(tmp, STATUS_PATH)
        except OSError:
            pass  # the dashboard may be reading the file right now; the next second will work

    def on_flow(self, flow):
        with self.lock:
            self.counts["flows"] += 1
            self.traffic.append((time.time(), int(flow.n_packets)))
            if flow.src_ip in self.whitelist:
                self.counts["whitelisted"] += 1
                return
            if flow.dst_ip not in self.protected or flow.dst_port != self.protected_port:
                self.counts["not_protected"] += 1
                return
            try:
                row = [float(flow.features[name]) for name in self.feats]
                if not all(np.isfinite(row)):
                    raise ValueError("not finite")
            except (KeyError, TypeError, ValueError):
                self.counts["rejected"] += 1
                return
            try:
                frame = pd.DataFrame([row], columns=self.feats)
                prob = float(self.model.predict_proba(self.scaler.transform(frame))[0, self.attack_col])
            except Exception as exc:
                self.counts["rejected"] += 1
                say("could not score a flow from %s: %s" % (flow.src_ip, exc))
                return
            is_attack = prob >= 0.5
            if is_attack:
                self.counts["attacks"] += 1
            self.last_verdict = {
                "time": time.strftime("%H:%M:%S"),
                "src": flow.src_ip,
                "port": int(flow.dst_port),
                "proto": str(flow.proto),
                "packets": int(flow.n_packets),
                "attack_prob": round(prob, 3),
                "label": "ATTACK" if is_attack else "BENIGN",
            }
            self.recent.appendleft(self.last_verdict)
            if is_attack or self.verbose:
                say("%s %s -> %s:%s/%s packets=%d attack_prob=%.2f" % (
                    "ATTACK-FLOW" if is_attack else "normal     ", flow.src_ip, flow.dst_ip,
                    flow.dst_port, flow.proto, flow.n_packets, prob))
            now = time.time()
            if flow.src_ip in self.active:
                # only a real burst keeps the block alive; a 1-packet leftover must not
                if is_attack and int(flow.n_packets) >= self.extend_min_packets:
                    self.active[flow.src_ip]["last_attack"] = now
                    self.last_burst = now
                    if not self.buzzer_on:
                        self.send_cmd("ALERT_ON")
                        self.buzzer_on = True
                return
            hist = self.history.setdefault(flow.src_ip, collections.deque(maxlen=self.window))
            hist.append(1 if is_attack else 0)
            if sum(hist) >= self.needed:
                self.raise_alert(flow.src_ip, now)

    def raise_alert(self, ip, now):
        say("ALERT: %d of the last %d flows from %s are attacks" % (self.needed, self.window, ip))
        ok = self.block_ip(ip)
        if not ok:
            self.counts["block_failed"] += 1
            say("WARNING: %s is NOT blocked. The alert is still raised." % ip)
        self.send_cmd("ALERT_ON")
        self.buzzer_on = True
        self.last_burst = now
        self.active[ip] = {"until": now + self.block_seconds, "last_attack": now}
        self.counts["alerts"] += 1
        self.write_status()

    def rule_name(self, ip):
        return "IoT-NIDS block " + ip

    def block_ip(self, ip):
        """Returns True if the block is in place (or would be, in dry run)."""
        ipaddress.ip_address(ip)
        if ip in self.whitelist:
            say("refused to block a whitelisted address: " + ip)
            return False
        if self.dry_run:
            say("DRY RUN: would block " + ip + " for %d s" % self.block_seconds)
            return True
        out = subprocess.run(
            ["netsh", "advfirewall", "firewall", "add", "rule", "name=" + self.rule_name(ip),
             "dir=in", "action=block", "remoteip=" + ip],
            capture_output=True, text=True)
        ok = out.returncode == 0
        say("firewall block %s: %s" % (ip, "OK" if ok else
                                       "FAILED (run an Admin terminal) " + out.stdout.strip()))
        return ok
    
    def unblock_ip(self, ip):
        if self.dry_run:
            return
        subprocess.run(["netsh", "advfirewall", "firewall", "delete", "rule",
                        "name=" + self.rule_name(ip)], capture_output=True, text=True)
        say("firewall block removed for " + ip)

    def sweep_loop(self):
        last_report = time.time()
        while not self.stop.wait(1.0):
            now = time.time()
            with self.lock:
                for ip in list(self.active):
                    state = self.active[ip]
                    if now < state["until"]:
                        continue
                    if now - state["last_attack"] < 3:
                        state["until"] = now + self.block_seconds
                        say("%s is still flooding, block extended" % ip)
                        continue
                    self.unblock_ip(ip)
                    del self.active[ip]
                    self.history.pop(ip, None)
                    say("block for %s expired, flood has stopped" % ip)
                if self.buzzer_on and now - self.last_burst >= self.alert_off_delay:
                    self.send_cmd("ALERT_OFF")
                    self.buzzer_on = False
                if now - last_report >= 10:
                    last_report = now
                    say("status: " + ", ".join("%s=%d" % kv for kv in sorted(self.counts.items())))
            self.write_status()

    def shutdown(self):
        self.stop.set()
        with self.lock:
            for ip in list(self.active):
                self.unblock_ip(ip)
            if self.buzzer_on or self.active:
                self.send_cmd("ALERT_OFF")
                self.buzzer_on = False
            self.active.clear()
        self.write_status(running=False)
        say("summary: " + ", ".join("%s=%d" % kv for kv in sorted(self.counts.items())))


def main():
    ap = argparse.ArgumentParser(description="Live flood detector")
    ap.add_argument("--pcap", help="replay this pcap instead of capturing live")
    ap.add_argument("--no-mqtt", action="store_true", help="do not send ALERT_ON / ALERT_OFF")
    ap.add_argument("--arm", action="store_true", help="really block in the firewall (Admin terminal)")
    ap.add_argument("--verbose", action="store_true", help="print normal flows too")
    ap.add_argument("--seconds", type=float, default=0, help="stop after this many seconds (live)")
    args = ap.parse_args()

    cfg = json.loads((IOT_ROOT / "config" / "settings.json").read_text())
    dry_run = not args.arm
    detector = Detector(cfg, make_sender(cfg, not args.no_mqtt), dry_run, args.verbose)
    threading.Thread(target=detector.sweep_loop, daemon=True).start()
    cap = capture.Sniffer(detector.on_flow)
    try:
        if args.pcap:
            capture.run_pcap(cap, args.pcap)
        else:
            iface = capture.find_interface(ip=cfg["defender_ip"])
            if not iface:
                say("Could not find the hotspot adapter. Is the hotspot on?")
                return
            say("capturing on " + str(iface))
            capture.run_live(cap, iface, args.seconds)
    finally:
        detector.shutdown()


if __name__ == "__main__":
    main()