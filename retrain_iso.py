import pickle, sys, json, numpy as np
sys.path.insert(0, 'code')

scaler = pickle.load(open('models/cicids_scaler.pkl', 'rb'))
raw = pickle.load(open('models/isolation_forest.pkl', 'rb'))
threshold = raw['threshold']

alerts = json.load(open('alerts.json'))
rows = []
for a in alerts:
    info = a.get('additional_info', {})
    row = [
        info.get('packet_size', 500),
        info.get('rate', 1.0),
        0, 0,
        info.get('ports_scanned', 1),
        info.get('syn_count', 0),
        0, 0, 0,
        info.get('flow_pkts', 1),
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0
    ]
    rows.append(row)

X = scaler.transform(np.array(rows))

from sklearn.ensemble import IsolationForest
new_iso = IsolationForest(n_estimators=100, contamination=0.1, random_state=42)
new_iso.fit(X)

new_pkl = {'model': new_iso, 'scaler': scaler, 'threshold': threshold, 'features': 20, 'n_samples': len(rows)}
pickle.dump(new_pkl, open('models/isolation_forest.pkl', 'wb'))
print('Done — IsoForest retrained with 20 features')