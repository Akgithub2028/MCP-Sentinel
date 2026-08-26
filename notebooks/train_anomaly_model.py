"""Training script for Tier 2 IsolationForest Anomaly Model.

Generates interaction logs from safe and vulnerable MCP sessions, trains IsolationForest,
evaluates precision/recall/ROC-AUC, and exports model artifacts (Joblib & ONNX).
"""

from __future__ import annotations

from pathlib import Path

import joblib
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.metrics import precision_score, recall_score, roc_auc_score


def generate_synthetic_interaction_dataset(
    n_normal: int = 2000, n_anomalous: int = 250
) -> tuple[np.ndarray, np.ndarray]:
    """
    Synthesizes feature vectors matching the 8D extractor:
    [call_frequency, time_delta, arg_count, payload_len, desc_len, is_shadowed, has_url, has_cred]
    Incorporates realistic operational noise and subtle evasion attempts.
    """
    np.random.seed(42)

    # 1. Normal interactions (Real-world developer & tool traffic with variance)
    normal_freq = np.random.gamma(shape=2.0, scale=0.8, size=n_normal).clip(0.1, 10.0)
    normal_dt = np.random.exponential(scale=1.8, size=n_normal) + 0.15
    normal_argc = np.random.choice([1, 2, 3, 4, 5, 6], size=n_normal, p=[0.35, 0.30, 0.18, 0.10, 0.05, 0.02])
    normal_paylen = np.random.lognormal(mean=4.8, sigma=0.8, size=n_normal).clip(20, 4000)
    normal_desclen = np.random.normal(loc=95, scale=45, size=n_normal).clip(20, 450)
    normal_shadow = np.zeros(n_normal)
    # 3.5% legitimate tools have internal/trusted URLs in arguments (e.g. webhook listeners)
    normal_url = np.random.binomial(1, 0.035, size=n_normal)
    normal_cred = np.random.binomial(1, 0.005, size=n_normal)

    X_normal = np.column_stack(
        [
            normal_freq,
            normal_dt,
            normal_argc,
            normal_paylen,
            normal_desclen,
            normal_shadow,
            normal_url,
            normal_cred,
        ]
    )

    # 2. Anomalous interactions (70% blatant exploits + 30% subtle stealth evasion)
    n_blatant = int(n_anomalous * 0.70)
    n_stealth = n_anomalous - n_blatant

    blatant_freq = np.random.uniform(15.0, 45.0, size=n_blatant)
    blatant_dt = np.random.uniform(0.005, 0.04, size=n_blatant)
    blatant_argc = np.random.randint(5, 14, size=n_blatant)
    blatant_paylen = np.random.uniform(2500, 45000, size=n_blatant)
    blatant_desclen = np.random.uniform(400, 1800, size=n_blatant)
    blatant_shadow = np.random.binomial(1, 0.65, size=n_blatant)
    blatant_url = np.random.binomial(1, 0.75, size=n_blatant)
    blatant_cred = np.random.binomial(1, 0.85, size=n_blatant)

    stealth_freq = np.random.uniform(0.5, 3.5, size=n_stealth)
    stealth_dt = np.random.uniform(0.8, 3.0, size=n_stealth)
    stealth_argc = np.random.choice([2, 3, 4], size=n_stealth)
    stealth_paylen = np.random.normal(loc=350, scale=120, size=n_stealth).clip(80, 800)
    stealth_desclen = np.random.normal(loc=180, scale=60, size=n_stealth).clip(50, 400)
    stealth_shadow = np.random.binomial(1, 0.35, size=n_stealth)
    stealth_url = np.random.binomial(1, 0.40, size=n_stealth)
    stealth_cred = np.random.binomial(1, 0.45, size=n_stealth)

    X_anomalous = np.vstack(
        [
            np.column_stack(
                [
                    blatant_freq,
                    blatant_dt,
                    blatant_argc,
                    blatant_paylen,
                    blatant_desclen,
                    blatant_shadow,
                    blatant_url,
                    blatant_cred,
                ]
            ),
            np.column_stack(
                [
                    stealth_freq,
                    stealth_dt,
                    stealth_argc,
                    stealth_paylen,
                    stealth_desclen,
                    stealth_shadow,
                    stealth_url,
                    stealth_cred,
                ]
            ),
        ]
    )

    X = np.vstack([X_normal, X_anomalous])
    y = np.hstack([np.ones(n_normal), -np.ones(n_anomalous)])

    return X, y


def train_and_export_model():
    print("🧠 Generating synthetic MCP interaction training dataset...")
    X, y = generate_synthetic_interaction_dataset()

    # Split train (only normal data or uncontaminated) vs test
    X_train = X[y == 1]  # Semi-supervised normal baseline
    X_test = X
    y_test = y

    print(f"🌲 Training IsolationForest on {len(X_train)} normal interaction vectors...")
    clf = IsolationForest(
        n_estimators=100,
        contamination=0.08,
        random_state=42,
    )
    clf.fit(X_train)

    # Evaluate
    y_pred = clf.predict(X_test)
    scores = -clf.decision_function(X_test)  # higher = more anomalous
    y_true_binary = (y_test == -1).astype(int)

    roc_auc = roc_auc_score(y_true_binary, scores)
    prec = precision_score(y_test, y_pred, pos_label=-1)
    rec = recall_score(y_test, y_pred, pos_label=-1)

    print("📊 Anomaly Model Evaluation Results:")
    print(f"  • ROC-AUC Score: {roc_auc:.4f}")
    print(f"  • Precision (Anomaly): {prec:.4f}")
    print(f"  • Recall (Anomaly): {rec:.4f}")

    # Export paths
    models_dir = Path(__file__).parent.parent / "packages" / "guardrail" / "models"
    models_dir.mkdir(parents=True, exist_ok=True)

    joblib_path = models_dir / "anomaly_detector.joblib"
    joblib.dump(clf, joblib_path)
    print(f"💾 Exported Joblib model to {joblib_path}")

    # Attempt ONNX export if skl2onnx available
    try:
        from skl2onnx import convert_sklearn
        from skl2onnx.common.data_types import FloatTensorType

        initial_type = [("float_input", FloatTensorType([None, 8]))]
        target_opset = {"ai.onnx.ml": 3, "": 18}
        onnx_model = convert_sklearn(clf, initial_types=initial_type, target_opset=target_opset)
        onnx_path = models_dir / "anomaly_detector.onnx"
        with open(onnx_path, "wb") as f:
            f.write(onnx_model.SerializeToString())
        print(f"💾 Exported ONNX model to {onnx_path}")
    except Exception as e:
        print(f"⚠️  ONNX export skipped (will use Joblib fallback): {e}")


if __name__ == "__main__":
    train_and_export_model()
