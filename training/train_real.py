"""
Trains on training/data_train/*.csv and evaluates on the held-out
training/data_test/*.csv -- i.e. a whole-SESSION train/test split
(decision 10), never a random row split. Run label_sessions.py first.

Run from the iot_nids root:
    python training\\train_real.py
"""
import os
import json
import glob
import joblib
import pandas as pd
import numpy as np
from sklearn.preprocessing import LabelEncoder, StandardScaler
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (accuracy_score, precision_score, recall_score,
                              f1_score, roc_auc_score, confusion_matrix)
from sklearn.preprocessing import label_binarize
from imblearn.over_sampling import SMOTE
import keras
from keras import layers

DL_MODEL_FILENAME = 'dl_model.keras'

SELECTED_FEATURES = [
    'Flow Duration',
    'Flow Bytes/s',
    'Flow Packets/s',
    'Total Fwd Packets',
    'Total Backward Packets',
    'Fwd Packet Length Mean',
    'Fwd Packet Length Std',
    'Bwd Packet Length Mean',
    'Flow IAT Mean',
    'Flow IAT Std',
    'Destination Port',
    'Fwd IAT Total',
]


def load_dir(data_dir):
    csv_files = sorted(glob.glob(os.path.join(data_dir, '*.csv')))
    if not csv_files:
        raise FileNotFoundError(
            f"No labeled CSV files found in {data_dir}. Run training\\label_sessions.py first."
        )
    dfs = []
    for f in csv_files:
        print(f"[INFO] Loading {os.path.basename(f)}...")
        df = pd.read_csv(f)
        df.columns = df.columns.str.strip()
        df.replace([np.inf, -np.inf], np.nan, inplace=True)
        df.dropna(subset=SELECTED_FEATURES + ['Label'], inplace=True)
        dfs.append(df)
    return pd.concat(dfs, ignore_index=True)


def compute_metrics(y_test, y_pred, y_proba, num_classes):
    accuracy = accuracy_score(y_test, y_pred)
    if num_classes == 2:
        precision = precision_score(y_test, y_pred, zero_division=0)
        recall = recall_score(y_test, y_pred, zero_division=0)
        f1 = f1_score(y_test, y_pred, zero_division=0)
        try:
            roc_auc = roc_auc_score(y_test, y_proba[:, 1])
        except ValueError:
            roc_auc = float('nan')
    else:
        precision = precision_score(y_test, y_pred, average='weighted', zero_division=0)
        recall = recall_score(y_test, y_pred, average='weighted', zero_division=0)
        f1 = f1_score(y_test, y_pred, average='weighted', zero_division=0)
        try:
            y_bin = label_binarize(y_test, classes=range(num_classes))
            roc_auc = roc_auc_score(y_bin, y_proba, average='weighted', multi_class='ovr')
        except ValueError:
            roc_auc = float('nan')
    cm = confusion_matrix(y_test, y_pred, labels=range(num_classes))
    return {
        'accuracy': accuracy, 'precision': precision, 'recall': recall,
        'f1_score': f1, 'roc_auc': roc_auc, 'confusion_matrix': cm.tolist()
    }


def scale_metrics(m):
    out = {}
    for k, v in m.items():
        if k == 'confusion_matrix':
            out[k] = v
        else:
            out[k] = round(float(v) * 100, 2) if v == v else None  # NaN check
    return out


def print_metrics(name, m):
    print("\n" + "=" * 50)
    print(name)
    print("=" * 50)
    for k, v in m.items():
        if k != 'confusion_matrix':
            print(f"{k.upper()}: {v:.4f}" if v == v else f"{k.upper()}: N/A")
    print(f"Confusion Matrix:\n{np.array(m['confusion_matrix'])}")
    print("=" * 50)


def main():
    current_dir = os.path.dirname(os.path.abspath(__file__))
    train_dir = os.path.join(current_dir, 'data_train')
    test_dir = os.path.join(current_dir, 'data_test')
    model_dir = os.path.join(current_dir, 'model_esp32_v1')
    os.makedirs(model_dir, exist_ok=True)

    print("[INFO] Loading TRAIN sessions...")
    df_train = load_dir(train_dir)
    print(f"[INFO] Train rows: {len(df_train)}")
    print(df_train['Label'].value_counts())

    print("\n[INFO] Loading TEST sessions (held out, never used for fitting)...")
    df_test = load_dir(test_dir)
    print(f"[INFO] Test rows: {len(df_test)}")
    print(df_test['Label'].value_counts())

    label_encoder = LabelEncoder()
    all_labels = pd.concat([df_train['Label'], df_test['Label']])
    label_encoder.fit(all_labels)
    num_classes = len(label_encoder.classes_)
    print(f"\n[INFO] Classes: {list(label_encoder.classes_)}")
    if num_classes < 2:
        raise ValueError(
            "Only one class present across train+test -- check label_sessions.py output, "
            "the flood signature rule may not be matching any rows."
        )

    X_train = df_train[SELECTED_FEATURES]
    y_train = label_encoder.transform(df_train['Label'])
    X_test = df_test[SELECTED_FEATURES]
    y_test = label_encoder.transform(df_test['Label'])

    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_test_scaled = scaler.transform(X_test)

    class_counts = pd.Series(y_train).value_counts()
    min_count = int(class_counts.min())
    if min_count < 2:
        print(f"[WARN] Smallest training class has only {min_count} row(s); skipping SMOTE.")
        X_train_bal, y_train_bal = X_train_scaled, y_train
    else:
        k = max(1, min(3, min_count - 1))
        print(f"[INFO] Applying SMOTE with k_neighbors={k} (smallest class has {min_count} rows)")
        smote = SMOTE(random_state=42, k_neighbors=k)
        X_train_bal, y_train_bal = smote.fit_resample(X_train_scaled, y_train)

    joblib.dump(scaler, os.path.join(model_dir, 'scaler.pkl'))
    joblib.dump(label_encoder, os.path.join(model_dir, 'label_encoder.pkl'))
    joblib.dump(SELECTED_FEATURES, os.path.join(model_dir, 'feature_names.pkl'))

    # ---- Random Forest ----
    print("\n[INFO] Training Random Forest...")
    rf = RandomForestClassifier(n_estimators=100, random_state=42, n_jobs=-1, verbose=1)
    rf.fit(X_train_bal, y_train_bal)
    y_pred = rf.predict(X_test_scaled)
    y_proba = rf.predict_proba(X_test_scaled)
    rf_metrics = compute_metrics(y_test, y_pred, y_proba, num_classes)
    joblib.dump(rf, os.path.join(model_dir, 'rf_model.pkl'))
    print_metrics("RANDOM FOREST (held-out test sessions)", rf_metrics)

    # ---- Deep learning ----
    print("\n[INFO] Training Deep Learning model...")
    dl = keras.Sequential([
        layers.Input(shape=(X_train_bal.shape[1],)),
        layers.Dense(128, activation='relu'),
        layers.Dropout(0.3),
        layers.Dense(64, activation='relu'),
        layers.Dropout(0.3),
        layers.Dense(32, activation='relu'),
        layers.Dropout(0.2),
        layers.Dense(num_classes, activation='softmax'),
    ])
    dl.compile(loss='sparse_categorical_crossentropy', optimizer='adam', metrics=['accuracy'])
    dl.fit(X_train_bal, y_train_bal, epochs=15, batch_size=32, verbose=1, validation_split=0.1)

    y_proba_dl = dl.predict(X_test_scaled, verbose=0)
    y_pred_dl = np.argmax(y_proba_dl, axis=1)
    dl_metrics = compute_metrics(y_test, y_pred_dl, y_proba_dl, num_classes)
    dl.save(os.path.join(model_dir, DL_MODEL_FILENAME))
    print_metrics("DEEP LEARNING (held-out test sessions)", dl_metrics)

    metrics_data = {
        'random_forest': scale_metrics(rf_metrics),
        'deep_learning': scale_metrics(dl_metrics),
        'classes': list(label_encoder.classes_),
        'train_rows': int(len(df_train)),
        'test_rows': int(len(df_test)),
        'note': 'Trained and evaluated on real ESP32/hotspot captures (sessions01-07), '
                'split by whole session per decision 10, not by row.'
    }
    with open(os.path.join(model_dir, 'metrics.json'), 'w') as f:
        json.dump(metrics_data, f, indent=2)

    print(f"\n[SUCCESS] Saved model + metrics to {model_dir}")
    print("[SUCCESS] This is your REAL model -- use this one for the demo, not baseline_cicids.")


if __name__ == '__main__':
    main()
