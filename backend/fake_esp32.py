"""Stand-in for the ESP32: publishes the same JSON readings to the local broker.
Used to develop and test the laptop side when the real board is not available."""
import json, random, time
import paho.mqtt.client as mqtt

BROKER = "127.0.0.1"
PORT = 1883
PREFIX = "iotnids-demo-4821"
NODE = "node1"
T_TELE = f"{PREFIX}/{NODE}/telemetry"
T_CMD = f"{PREFIX}/{NODE}/cmd"
T_STATUS = f"{PREFIX}/{NODE}/status"

state = {"alert": 0, "fan": 0}

def on_connect(c, u, f, rc, p):
    c.publish(T_STATUS, "online", retain=True)
    c.subscribe(T_CMD)

def on_message(c, u, m, *args):
    cmd = m.payload.decode().strip()
    print("cmd received:", cmd)
    if cmd == "ALERT_ON":
        state["alert"] = 1
    if cmd == "ALERT_OFF":
        state["alert"] = 0

c = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2, client_id="fake-esp32")
c.will_set(T_STATUS, "offline", retain=True)
c.on_connect = on_connect
c.on_message = on_message
c.connect(BROKER, PORT, 60)
c.loop_start()

temp = 26.0
while True:
    temp += random.uniform(-0.4, 0.4)
    temp = max(18.0, min(38.0, temp))
    if state["fan"] == 0 and temp >= 30.0:
        state["fan"] = 1
    if state["fan"] == 1 and temp <= 28.0:
        state["fan"] = 0
    payload = {
        "temp": round(temp, 1),
        "hum": round(random.uniform(40, 60), 1),
        "motion": 1 if random.random() < 0.1 else 0,
        "fan": state["fan"],
        "alert": state["alert"],
    }
    c.publish(T_TELE, json.dumps(payload))
    print(payload)
    time.sleep(2)
