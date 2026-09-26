"""
Benchmark: onnxruntime vs Treelite (GTIL) vs xgboost-native inference on the
REAL flow/modbus training data, plus a parity check that a retrained native
booster reproduces the shipped ONNX model. Needs: pip install treelite xgboost
(training deps). Result and decision recorded in docs/PRD.md (Treelite section):
Treelite is slower than ORT here, so it is intentionally NOT integrated.

    python scripts/bench_inference_backends.py
"""
import sys, time, json
sys.path.insert(0, '.')
import numpy as np, xgboost as xgb, onnxruntime as ort, treelite
from types import SimpleNamespace
from scripts.train_family import load_labeled
from sklearn.model_selection import train_test_split

def run(family, csv):
    args = SimpleNamespace(label_col="label", malicious_value="malicious", domain_col="domain")
    X, y = load_labeled(csv, family, args)
    Xtr, Xte, ytr, yte = train_test_split(X, y, test_size=0.2, stratify=y, random_state=42)
    spw = float((ytr == 0).sum()) / max(1, int((ytr == 1).sum()))
    clf = xgb.XGBClassifier(n_estimators=300, max_depth=6, learning_rate=0.1, subsample=0.9, colsample_bytree=0.9,
                            eval_metric="logloss", random_state=42, n_jobs=4, scale_pos_weight=spw)
    clf.fit(Xtr, ytr)
    booster = clf.get_booster()

    # shipped ONNX model vs freshly retrained native booster (same data/params/seed)
    sess = ort.InferenceSession(f"models/{family}_xgboost_v1.onnx", providers=["CPUExecutionProvider"])
    inp = sess.get_inputs()[0].name
    onnx_p = sess.run(None, {inp: Xte})[1]
    onnx_p = np.asarray([r[1] if isinstance(r, (list, tuple, np.ndarray)) else r for r in onnx_p]) if onnx_p.ndim == 2 else onnx_p
    if not isinstance(onnx_p, np.ndarray): onnx_p = np.asarray(onnx_p)
    native_p = clf.predict_proba(Xte)[:, 1]
    print(f"[{family}] shipped-ONNX vs retrained: max|dp|={np.max(np.abs(onnx_p.reshape(-1)-native_p)):.2e}  "
          f"decision agreement={np.mean((onnx_p.reshape(-1)>=.5)==(native_p>=.5)):.4f}")

    model = treelite.frontend.from_xgboost(booster)
    import treelite.gtil as gtil
    tl_p = gtil.predict(model, Xte).reshape(-1)
    print(f"[{family}] treelite-GTIL vs xgboost native: max|dp|={np.max(np.abs(tl_p-native_p)):.2e}")

    def bench(fn, X, reps):
        fn(X[:8]); best = 1e9
        for _ in range(reps):
            t = time.perf_counter(); fn(X); best = min(best, time.perf_counter() - t)
        return best / len(X) * 1e6  # us/row
    for n in (1, 32, 1024, 16384):
        Xb = np.tile(Xte, (max(1, n // len(Xte) + 1), 1))[:n].astype(np.float32)
        reps = 200 if n <= 32 else 20
        o = bench(lambda a: sess.run(None, {inp: a}), Xb, reps)
        g = bench(lambda a: gtil.predict(model, a), Xb, reps)
        x = bench(lambda a: booster.inplace_predict(a), Xb, reps)
        print(f"[{family}] batch={n:5d}  onnxruntime {o:8.2f} us/row | treelite-GTIL {g:8.2f} us/row | xgboost-native {x:8.2f} us/row")

run("flow", "models/flow_training_data.csv")
run("modbus", "models/modbus_training_data.csv")
