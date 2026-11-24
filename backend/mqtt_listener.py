"""Receives the ESP32 telemetry over MQTT and stores it in a local SQLite database."""
import json, sqlite3, time, os
import paho.mqtt.client as mqtt

BROKER = "localhost"              # own Mosquitto broker. For the Wokwi test: "broker.hivemq.com"
PORT = 1883
PREFIX = "iotnids-demo-4821"      # must match the ESP32 code
TOPIC = f"{PREFIX}/node1/telemetry"

# Always the same file the dashboard reads: backend\iot.db, wherever the script is started from
DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "iot.db")
db = sqlite3.connect(DB_PATH, check_same_thread=False)
db.execute("""CREATE TABLE IF NOT EXISTS sensor_readings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts TEXT NOT NULL,
    temp REAL, hum REAL, motion INTEGER, fan INTEGER, alert INTEGER)""")
db.commit()

def on_connect(client, userdata, flags, reason_code, properties):
    print("connected:", reason_code)
    client.subscribe(TOPIC)

def on_message(client, userdata, msg):
    try:
        d = json.loads(msg.payload)
        db.execute(
            "INSERT INTO sensor_readings (ts,temp,hum,motion,fan,alert) "
            "VALUES (?,?,?,?,?,?)",
            (time.strftime("%Y-%m-%d %H:%M:%S"),
             d["temp"], d["hum"], d["motion"], d["fan"], d["alert"]))
        db.commit()
        print(d)
    except Exception as e:
        print("bad message:", e)

client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2)
client.on_connect = on_connect
client.on_message = on_message
client.connect(BROKER, PORT, 60)
client.loop_forever()
