import glob
import os

import joblib
import pandas as pd

ROOT = os.path.dirname(os.path.abspath(__file__))
MODELS = os.path.join(os.path.dirname(ROOT), 'models', 'live_v1')
model = joblib.load(os.path.join(MODELS, 'rf_model.pkl'))
scaler = joblib.load(os.path.join(MODELS, 'scaler.pkl'))
feats = pd.read_json(os.path.join(MODELS, 'feature_names.json'), typ='series').tolist()

frames = [pd.read_csv(p).assign(session=os.path.basename(p)[:9])
          for p in sorted(glob.glob(os.path.join(ROOT, 'data_test', '*_labeled.csv')))]
df = pd.concat(frames, ignore_index=True)
df['pred'] = model.predict(scaler.transform(df[feats]))
fa = df[(df['Label'] == 'BENIGN') & (df['pred'] == 1)]
cols = ['session', 'window_start', 'src_ip', 'dst_ip', 'dst_port', 'proto',
        'n_packets', 'Flow Packets/s', 'Flow Bytes/s']
print(fa[cols].to_string(index=False))
