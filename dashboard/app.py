import json
import sqlite3
import time
from datetime import datetime
from pathlib import Path

from flask import Flask, jsonify, render_template, request

BASE = Path(__file__).resolve().parent
DB_PATH = BASE.parent / "backend" / "iot.db"
STATUS_PATH = BASE.parent / "data" / "security_status.json"  # written by detector\detector.py
ONLINE_SECONDS = 6  # device counts as online if its last reading is newer than this
DETECTOR_SECONDS = 4  # detector counts as running if its status file is newer than this

app = Flask(__name__)


def query(sql, args=()):
    # read-only, so the dashboard can never damage the listener's database
    con = sqlite3.connect(f"file:{DB_PATH.as_posix()}?mode=ro", uri=True, timeout=5)
    try:
        return con.execute(sql, args).fetchall()
    finally:
        con.close()


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/latest")
def latest():
    rows = query(
        "SELECT ts, temp, hum, motion, fan, alert "
        "FROM sensor_readings ORDER BY id DESC LIMIT 1"
    )
    if not rows:
        return jsonify({"online": False, "reading": None, "age": None})
    ts, temp, hum, motion, fan, alert = rows[0]
    age = (datetime.now() - datetime.strptime(ts, "%Y-%m-%d %H:%M:%S")).total_seconds()
    return jsonify({
        "online": age <= ONLINE_SECONDS,
        "age": round(age, 1),
        "reading": {"ts": ts, "temp": temp, "hum": hum,
                    "motion": motion, "fan": fan, "alert": alert},
    })


@app.route("/api/history")
def history():
    n = request.args.get("n", default=60, type=int)
    n = max(10, min(n, 300))
    rows = query(
        "SELECT ts, temp, hum FROM sensor_readings ORDER BY id DESC LIMIT ?", (n,)
    )
    rows.reverse()
    return jsonify([{"ts": r[0], "temp": r[1], "hum": r[2]} for r in rows])


@app.route("/api/security")
def security():
    # read-only: shows what the detector wrote. If the file is old, the detector is not running.
    try:
        data = json.loads(STATUS_PATH.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return jsonify({"detector": "off", "age": None})
    age = time.time() - float(data.get("updated", 0))
    data["age"] = round(age, 1)
    data["detector"] = "on" if data.get("running") and age <= DETECTOR_SECONDS else "off"
    return jsonify(data)


if __name__ == "__main__":
    # debug=False. host 0.0.0.0 is needed so the attacker laptop can reach the dashboard
    # (set back to 127.0.0.1 after the demo).
    app.run(host="127.0.0.1", port=5000, debug=False)
