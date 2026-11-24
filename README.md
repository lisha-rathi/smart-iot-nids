# Smart Environment Monitoring IoT System, Secured by AI

A real IoT device (ESP32 with sensors) sends data over MQTT. A defender laptop watches the network, a machine-learning model detects flood attacks, the attacker is blocked automatically, and the device raises a physical alert.

> All attack traffic was generated on an isolated lab network that we own.

## Why this project

IoT devices are common DDoS targets (for example the Mirai botnet) and are too small to run their own security. So the security runs **outside** the device, on the network.

## How it works

```
ESP32 (DHT11, PIR, relay, buzzer, LED)
   |  MQTT telemetry every 2 s
   v
Laptop Wi-Fi hotspot + Mosquitto broker  --->  Flask dashboard (live readings)
   |
   |  packet capture (Scapy)
   v
1-second flows -> 12 features -> Random Forest -> verdict
   |
   |  3 of the last 5 flows flagged
   v
Alert: firewall block of the attacker IP (auto-expires) + ALERT_ON to the ESP32 (buzzer, LED)
```

## What is in the repo

| Folder | Contents |
|---|---|
| `firmware/` | ESP32 sketch (`esp32_node`) and the Wokwi simulation version |
| `backend/` | MQTT listener that stores readings in SQLite, and a stand-in sensor script for testing |
| `capture/` | Packet sniffer, flow builder, 12-feature extractor, tests, and a freeze check so training and live use the same code |
| `data/` | Session log and extracted feature files from 8 capture sessions |
| `training/` | Session labeling and Random Forest training scripts |
| `models/live_v1/` | Trained model, scaler and metrics |
| `detector/` | Live detector: scoring, 3-of-5 rule, whitelist, firewall block, ESP32 alert |
| `dashboard/` | Flask dashboard showing IoT readings and security status together |
| `config/` | Mosquitto config and detector settings |

## Results (honest summary)

- **Data:** traffic captured from the real ESP32 in 8 sessions (normal, SYN flood, UDP flood, HTTP flood). Train and test sets are split **by capture session**, not by random rows. Every session was checked against Wireshark.
- **Held-out test (SYN and UDP, model without destination port, the one used live):** 115 of 116 attack flows detected. Per-flow false-alarm rate 3.3% on normal traffic.
- **Live lab test:** 20 of 20 SYN and UDP flood attempts raised an alert. In armed mode the attacker lost access to the laptop until the 60 s block expired.
- **Detection rule:** an alert needs 3 of the last 5 flows from one source to be flagged, which keeps single odd flows from raising alarms.

## Limits

- Floods only (SYN, UDP). HTTP flood detection is **not** supported: the HTTP model had one training session and no held-out test, and a patch to score port 5000 failed testing.
- The detector only scores traffic to the MQTT port (1883). This removed false alarms from normal dashboard browsing.
- One attacker laptop, one tool, one target port. The results show the system detects what it was trained on, not every attacker or attack type.
- Per-flow false-alarm rate (3.3%) is above our 1% target. The 3-of-5 rule and the whitelist reduce this at alert level.
- Lab network only. MQTT has no TLS or authentication (a deliberate simplification).
- The live detector uses only the Random Forest.

## How to run

Windows, Python 3.12, Wireshark with Npcap, Mosquitto. The laptop's Wi-Fi hotspot is the network.

```powershell
python -m venv venv
.\venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

1. **Firmware:** open `firmware/esp32_node/esp32_node.ino`, set `WIFI_SSID`, `WIFI_PASS` and `MQTT_HOST` (the laptop hotspot IP), then upload with the Arduino IDE (esp32 by Espressif Systems).
2. **Settings:** edit `config/settings.json` with your ESP32 and laptop IP addresses (the whitelist).
3. **Start three terminals** in the project folder:
   - Broker: `& "C:\Program Files\mosquitto\mosquitto.exe" -c config\mosquitto.conf -v`
   - Listener: `python backend\mqtt_listener.py`
   - Dashboard: `python dashboard\app.py`, then open http://127.0.0.1:5000
4. **Detector** (Admin terminal):
   - Dry run, no real blocking: `python detector\detector.py`
   - Armed, blocks for real: `python detector\detector.py --arm`
5. **Replay without hardware** (needs a recorded pcap, which is not in the repo): `python detector\detector.py --pcap <file.pcap> --no-mqtt`

Tests: `python capture\tests\test_features.py` (and the other `test_*.py` files). Before training, run `python capture\freeze_check.py`, which must say STILL FROZEN.

## Tech

ESP32 (Arduino C++), MQTT (Mosquitto), Python, Scapy, scikit-learn, pandas, Flask, SQLite, Wireshark.

## Team

- Lisha Rathi
