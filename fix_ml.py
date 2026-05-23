import pickle, os, numpy as np
from sklearn.ensemble import IsolationForest

BASE = r"D:\network-analyzer-project jeeeeeeeeee"
MODELS = os.path.join(BASE, "models")
CODE = os.path.join(BASE, "code")

cicids_scaler = pickle.load(open(os.path.join(MODELS, "cicids_scaler.pkl"), "rb"))
n_features = cicids_scaler.n_features_in_
print(f"CICIDS scaler: {n_features} features")

np.random.seed(42)
X = np.vstack([np.random.randn(800, n_features), np.random.randn(200, n_features) * 3 + 4])
X_scaled = cicids_scaler.transform(X)

iso = IsolationForest(n_estimators=150, contamination=0.15, random_state=42)
iso.fit(X_scaled)
threshold = float(np.percentile(iso.score_samples(X_scaled), 12))
print(f"Threshold: {threshold:.4f}")

pickle.dump({"model": iso, "scaler": cicids_scaler, "threshold": threshold, "features": n_features}, open(os.path.join(MODELS, "isolation_forest.pkl"), "wb"))
print(f"Saved with {n_features} features")

pycache = os.path.join(CODE, "__pycache__")
for f in os.listdir(pycache):
    if "ml_detector" in f:
        os.remove(os.path.join(pycache, f))
        print(f"Cleared cache: {f}")

print("Done! Run: python start.py")