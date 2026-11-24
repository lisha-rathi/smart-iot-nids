"""
Random Forest on our own labeled sessions. Two classes: BENIGN vs ATTACK.
Trains ONLY on training/data_train. Scores ONLY on training/data_test.
Runs twice: with Destination Port and without it (decision 10, ablation).
Saves to models/live_v1 (never touches the baseline).

Run from the iot_nids root:
    python training\\train_rf.py
"""
import glob
import json
import os

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import StandardScaler

ROOT = os.path.dirname(os.path.abspath(__file__))
IOT_ROOT = os.path.dirname(ROOT)
TRAIN_DIR = os.path.join(ROOT, 'data_train')
TEST_DIR = os.path.join(ROOT, 'data_test')
OUT_DIR = os.path.join(IOT_ROOT, 'models', 'live_v1')

FEATURES = [
    'Flow Duration', 'Flow Bytes/s', 'Flow Packets/s', 'Total Fwd Packets',
    'Total Backward Packets', 'Fwd Packet Length Mean', 'Fwd Packet Length Std',
    'Bwd Packet Length Mean', 'Flow IAT Mean', 'Flow IAT Std',
    'Destination Port', 'Fwd IAT Total',
]


def load(folder, dedupe):
    frames = []
    for path in sorted(glob.glob(os.path.join(folder, '*_labeled.csv'))):
        df = pd.read_csv(path)
        df['session'] = os.path.basename(path).split('_')[0]
        frames.append(df)
    if not frames:
        raise SystemExit(f'No *_labeled.csv files in {folder}')
    df = pd.concat(frames, ignore_index=True)
    df = df.replace([np.inf, -np.inf], np.nan).dropna(subset=FEATURES + ['Label'])
    if dedupe:
        df = df.drop_duplicates(subset=FEATURES + ['Label'])
    return df


def run(train, test, feats, tag):
    scaler = StandardScaler().fit(train[feats])
    model = RandomForestClassifier(
        n_estimators=200, class_weight='balanced', random_state=42, n_jobs=-1)
    y_train = (train['Label'] != 'BENIGN').astype(int)
    model.fit(scaler.transform(train[feats]), y_train)

    y_true = (test['Label'] != 'BENIGN').astype(int).values
    y_pred = model.predict(scaler.transform(test[feats]))
    tp = int(((y_true == 1) & (y_pred == 1)).sum())
    fn = int(((y_true == 1) & (y_pred == 0)).sum())
    fp = int(((y_true == 0) & (y_pred == 1)).sum())
    tn = int(((y_true == 0) & (y_pred == 0)).sum())
    recall = tp / (tp + fn) if tp + fn else 0.0
    precision = tp / (tp + fp) if tp + fp else 0.0
    false_alarm = fp / (fp + tn) if fp + tn else 0.0

    print(f'\n=== {tag} ({len(feats)} features) ===')
    print(f'attacks caught (recall): {recall:.3f}  [{tp} of {tp + fn}]')
    print(f'precision:               {precision:.3f}')
    print(f'false-alarm rate:        {false_alarm:.4f}  [{fp} of {fp + tn} normal flows]')
    per_attack = {}
    for label in sorted(set(test['Label']) - {'BENIGN'}):
        m = (test['Label'] == label).values
        caught = int((y_pred[m] == 1).sum())
        per_attack[label] = {'caught': caught, 'total': int(m.sum())}
        print(f'  {label}: caught {caught} of {int(m.sum())}')
    top = sorted(zip(feats, model.feature_importances_), key=lambda x: -x[1])[:5]
    print('top features: ' + ', '.join(f'{n} {v:.2f}' for n, v in top))

    metrics = {'tag': tag, 'recall': recall, 'precision': precision,
               'false_alarm_rate': false_alarm, 'tp': tp, 'fn': fn, 'fp': fp,
               'tn': tn, 'per_attack': per_attack}
    return model, scaler, metrics


def save(model, scaler, feats, metrics, suffix):
    os.makedirs(OUT_DIR, exist_ok=True)
    joblib.dump(model, os.path.join(OUT_DIR, f'rf_model{suffix}.pkl'))
    joblib.dump(scaler, os.path.join(OUT_DIR, f'scaler{suffix}.pkl'))
    with open(os.path.join(OUT_DIR, f'feature_names{suffix}.json'), 'w') as f:
        json.dump(feats, f)
    with open(os.path.join(OUT_DIR, f'metrics{suffix}.json'), 'w') as f:
        json.dump(metrics, f, indent=2)


def main():
    train = load(TRAIN_DIR, dedupe=True)
    test = load(TEST_DIR, dedupe=False)
    print('TRAIN rows by session and label (after removing duplicates):')
    print(train.groupby(['session', 'Label']).size())
    print('\nTEST rows by session and label:')
    print(test.groupby(['session', 'Label']).size())

    m1, s1, r1 = run(train, test, FEATURES, 'WITH Destination Port')
    save(m1, s1, FEATURES, r1, '')
    no_port = [f for f in FEATURES if f != 'Destination Port']
    m2, s2, r2 = run(train, test, no_port, 'WITHOUT Destination Port')
    save(m2, s2, no_port, r2, '_noport')
    print(f'\nSaved models to {OUT_DIR}')


if __name__ == '__main__':
    main()