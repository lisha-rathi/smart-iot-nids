import os

import pandas as pd

ROOT = os.path.dirname(os.path.abspath(__file__))
for session, split in (('session01', 'train'), ('session06', 'test')):
    path = os.path.join(ROOT, f'data_{split}', f'{session}_labeled.csv')
    df = pd.read_csv(path)
    mqtt = df[(df['dst_port'] == 1883) & (df['proto'] == 'TCP')]
    print(session)
    print(mqtt.groupby('src_ip')['n_packets'].agg(['count', 'mean']).round(2))
    print()