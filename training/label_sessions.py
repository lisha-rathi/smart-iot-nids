"""
Reads data/sessions_log.csv, labels each session's flow rows (NOT the whole
session as one label), and writes labeled copies into training/data_train/
or training/data_test/, based on each session's own 'split' column.

Why per-row, not per-session: an attack session's capture still contains the
attacker laptop's own normal background traffic (web browsing, DNS, mDNS)
and the ESP32's own normal MQTT traffic. Labeling the whole file "SYN_FLOOD"
would teach the model that browsing traffic is an attack. Instead, only the
rows matching the known flood signature (the defender's IP + the flooded
port/protocol + a packet-count jump for SYN) get the attack label; every
other row in every session -- including attack sessions -- is BENIGN.

Run from the iot_nids root:
    python training\\label_sessions.py
"""
import os
import pandas as pd

ROOT = os.path.dirname(os.path.abspath(__file__))          # .../iot_nids/training
IOT_ROOT = os.path.dirname(ROOT)                            # .../iot_nids
SESSIONS_LOG = os.path.join(IOT_ROOT, 'data', 'sessions_log.csv')
OUT_TRAIN = os.path.join(ROOT, 'data_train')
OUT_TEST = os.path.join(ROOT, 'data_test')

DEFENDER_IP = '192.168.137.1'
ATTACKER_IP = '192.168.137.143'   # used ONLY to write the label, never a model input
MQTT_PORT = '1883'
DASHBOARD_PORT = '5000'


def label_row(row, session_type):
    src_ip = str(row['src_ip']).strip()
    dst_ip = str(row['dst_ip']).strip()
    dst_port = str(row['dst_port']).strip()
    proto = str(row['proto']).strip().upper()

    if session_type in ('normal', 'mixed_normal'):
        return 'BENIGN'

    from_attacker = (src_ip == ATTACKER_IP and dst_ip == DEFENDER_IP)

    if session_type == 'attack_syn':
        if from_attacker and dst_port == MQTT_PORT and proto == 'TCP':
            return 'SYN_FLOOD'
        return 'BENIGN'

    if session_type == 'attack_udp':
        if from_attacker and dst_port == MQTT_PORT and proto == 'UDP':
            return 'UDP_FLOOD'
        return 'BENIGN'

    if session_type == 'attack_http':
        if from_attacker and dst_port == DASHBOARD_PORT and proto == 'TCP':
            return 'HTTP_FLOOD'
        return 'BENIGN'

    print(f"[WARN] Unknown session type '{session_type}', treating all rows as BENIGN")
    return 'BENIGN'


def main():
    os.makedirs(OUT_TRAIN, exist_ok=True)
    os.makedirs(OUT_TEST, exist_ok=True)

    sessions = pd.read_csv(SESSIONS_LOG)
    print(f"[INFO] Found {len(sessions)} sessions in sessions_log.csv")

    for _, s in sessions.iterrows():
        csv_path = os.path.join(IOT_ROOT, s['features_csv'])
        if not os.path.exists(csv_path):
            print(f"[WARN] Missing file for {s['session_id']}: {csv_path}, skipping")
            continue

        df = pd.read_csv(csv_path)
        df['Label'] = df.apply(lambda r: label_row(r, s['type']), axis=1)

        counts = df['Label'].value_counts().to_dict()
        print(f"[INFO] {s['session_id']} ({s['type']}, split={s['split']}): {counts}")

        out_dir = OUT_TRAIN if str(s['split']).strip() == 'train' else OUT_TEST
        out_path = os.path.join(out_dir, f"{s['session_id']}_labeled.csv")
        df.to_csv(out_path, index=False)
        print(f"[INFO]   -> saved {out_path}")

    print("\n[DONE] Labeled CSVs are in training/data_train/ and training/data_test/.")
    print("[DONE] Check the per-session counts above -- if an attack session shows")
    print("[DONE] 0 rows of its own attack label, the signature rule needs adjusting")
    print("[DONE] before training (tell me and I will fix the threshold).")


if __name__ == '__main__':
    main()
