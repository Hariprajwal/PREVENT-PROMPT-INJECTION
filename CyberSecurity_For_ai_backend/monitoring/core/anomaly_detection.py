"""
=============================================================================
  Anomaly Detection & Risk Analysis System  v3.1
  Trained on: embedded_system_network_security_dataset.csv
=============================================================================

  All features come directly from the CSV.  No synthetic data anywhere.

  CSV columns used:
    packet_size, inter_arrival_time, src_port, dst_port,
    packet_count_5s, mean_packet_size, spectral_entropy,
    frequency_band_energy, protocol_type_TCP, protocol_type_UDP,
    src_ip_192.168.1.2, src_ip_192.168.1.3,
    dst_ip_192.168.1.5, dst_ip_192.168.1.6,
    tcp_flags_FIN, tcp_flags_SYN, tcp_flags_SYN-ACK

  label column: 0 = normal, 1 = anomaly  (used only for train/test split)
=============================================================================
"""

import numpy as np
import pandas as pd
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
from sklearn.ensemble import IsolationForest
import warnings, os
import joblib

warnings.filterwarnings("ignore")
np.random.seed(42)

# ─── File path ────────────────────────────────────────────────────────────────
CSV_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                        "embedded_system_network_security_dataset.csv")

# ─── Sigmoid steepness for risk conversion ────────────────────────────────────
SIGMOID_K = 15


# =============================================================================
#  STEP 1 — Load the dataset
# =============================================================================

def load_data():
    """
    Read the CSV, normalise ports, convert bools to int, and return
    (dataframe, list_of_feature_column_names).
    """
    df = pd.read_csv(CSV_PATH)

    # --- label to int
    df["label"] = df["label"].astype(int)

    # --- convert True/False columns to 1/0
    for col in df.select_dtypes(include="bool").columns:
        df[col] = df[col].astype(int)

    # --- normalise raw port numbers into 0-1 range
    df["src_port"] = df["src_port"] / 65535.0
    df["dst_port"] = df["dst_port"] / 65535.0

    # --- feature columns = everything except "label"
    feature_cols = [c for c in df.columns if c != "label"]

    # --- drop any column that has zero variance (carries no info)
    to_drop = [c for c in feature_cols if df[c].std() < 1e-9]
    if to_drop:
        print(f"[Info]     Dropping zero-variance columns: {to_drop}")
        df.drop(columns=to_drop, inplace=True)
        feature_cols = [c for c in feature_cols if c not in to_drop]

    n_normal  = (df["label"] == 0).sum()
    n_anomaly = (df["label"] == 1).sum()
    print(f"[Dataset]  {len(df)} rows  |  Normal: {n_normal}  |  Anomaly: {n_anomaly}")
    print(f"[Features] {len(feature_cols)} features:")
    for i, c in enumerate(feature_cols, 1):
        print(f"           {i:>2}. {c}")

    return df, feature_cols


# =============================================================================
#  STEP 2 — Train the Isolation Forest (normal data only)
# =============================================================================

def train_model(df, feature_cols):
    """
    Train an Isolation Forest on label=0 (normal) rows ONLY.
    Returns the trained model.
    """
    normal_df = df[df["label"] == 0]
    X_train   = normal_df[feature_cols].values

    model = IsolationForest(
        n_estimators=300,
        contamination=0.01,
        max_samples="auto",
        random_state=42,
        n_jobs=-1,
    )
    model.fit(X_train)

    # Quick stats on training scores
    scores = model.decision_function(X_train)
    print(f"\n[Model]    Trained on {len(X_train)} normal rows.")
    print(f"[Scores]   mean={scores.mean():.4f}  std={scores.std():.4f}")
    return model


# =============================================================================
#  STEP 3 — Risk scoring (sigmoid, centred on IF decision boundary)
# =============================================================================

def compute_risk(raw_score):
    """
    Convert Isolation Forest raw score to a 0-100% risk value.

    The IF decision boundary is at raw_score = 0:
      positive = normal    -> low risk
      negative = anomalous -> high risk

    Sigmoid centres the mapping so that:
      score +0.10  ->  ~18% risk  (ALLOW)
      score  0.00  ->   50% risk  (borderline)
      score -0.10  ->  ~82% risk  (BLOCK)
    """
    risk = 100.0 / (1.0 + np.exp(SIGMOID_K * raw_score))
    return round(float(np.clip(risk, 0, 100)), 2)


def predict_risk(model, feature_cols, sample_values, verbose=True):
    """
    Score one sample.

    Parameters
    ----------
    model         : trained IsolationForest
    feature_cols  : list of feature names (same order used during training)
    sample_values : list/array of feature values, same order as feature_cols
    verbose       : whether to print a formatted report

    Returns
    -------
    dict with keys: raw_score, risk, classification, decision
    """
    x         = np.array(sample_values, dtype=float).reshape(1, -1)
    raw_score = model.decision_function(x)[0]
    pred      = model.predict(x)[0]           # +1 = normal, -1 = anomaly
    risk      = compute_risk(raw_score)
    decision  = get_decision(risk)

    classification = "NORMAL" if pred == 1 else "ANOMALY"
    # Confidence: 0% at 50% risk, 100% at 0% or 100% risk.
    confidence = round(abs(risk - 50) * 2, 2)

    result = {
        "raw_score":      round(raw_score, 6),
        "risk":           risk,
        "confidence":     confidence,
        "classification": classification,
        "decision":       decision,
    }

    if verbose:
        print_report(feature_cols, sample_values, result)

    return result


# =============================================================================
#  STEP 4 — Decision engine
# =============================================================================

def get_decision(risk):
    """
    0 - 30%  ->  ALLOW
    30 - 60% ->  MONITOR
    60 - 80% ->  STEP-UP AUTH
    80 - 100% -> BLOCK
    """
    if risk < 30:
        return "ALLOW"
    elif risk < 60:
        return "MONITOR"
    elif risk < 80:
        return "STEP-UP AUTH"
    else:
        return "BLOCK"


# =============================================================================
#  STEP 5 — Print formatted report
# =============================================================================

CLASS_STYLE = {
    "NORMAL":  "✅ NORMAL",
    "ANOMALY": "🚨 ANOMALY",
}

ICONS = {"ALLOW": "[OK]", "MONITOR": "[??]", "STEP-UP AUTH": "[!!]", "BLOCK": "[XX]"}

def print_report(feature_cols, values, result):
    bar_len = 40
    filled  = int(result["risk"] / 100 * bar_len)
    bar     = "#" * filled + "-" * (bar_len - filled)
    icon    = ICONS.get(result["decision"], "")
    cls_txt = CLASS_STYLE.get(result["classification"], result["classification"])

    print()
    print("=" * 60)
    print("  SESSION RISK REPORT")
    print("=" * 60)
    for name, val in zip(feature_cols, values):
        print(f"  {name:<30}  {float(val):.4f}")
    print("-" * 60)
    print(f"  Classification : {cls_txt}")
    print(f"  Confidence     : {result.get('confidence', 0.00):>6.2f} %")
    print(f"  Risk Score     : {result['risk']:>6.2f} %")
    print(f"  [{bar}] {result['risk']:.0f}%")
    print(f"  Action         : {icon}  {result['decision']}")
    print("=" * 60)


# =============================================================================
#  STEP 6 — Evaluate entire dataset + visualise
# =============================================================================

def evaluate_all(model, df, feature_cols):
    """Score every row in the dataset and print summary stats."""
    X      = df[feature_cols].values
    scores = model.decision_function(X)
    risks  = np.array([compute_risk(s) for s in scores])
    decs   = [get_decision(r) for r in risks]

    result_df = pd.DataFrame({
        "label":     df["label"].values,
        "raw_score": scores,
        "risk":      risks,
        "decision":  decs,
    })

    print("\n  Decision counts by label:")
    print(result_df.groupby(["label", "decision"]).size()
          .unstack(fill_value=0).to_string())

    for lbl, tag in [(0, "NORMAL"), (1, "ANOMALY")]:
        s = result_df[result_df["label"] == lbl]["risk"]
        print(f"\n  {tag:8}  n={len(s):<4}  "
              f"avg={s.mean():.1f}%   min={s.min():.1f}%   max={s.max():.1f}%")

    return result_df


def save_chart(result_df, path="risk_distribution.png"):
    """Dark-mode histogram of risk scores split by label."""
    BG = "#1A1D2E"; PAN = "#22263A"; TXT = "#E8EAF6"; GRD = "#2E3250"

    fig, ax = plt.subplots(figsize=(12, 5), facecolor=BG)
    ax.set_facecolor(PAN)
    ax.tick_params(colors=TXT)
    for s in ax.spines.values(): s.set_edgecolor(GRD)

    ax.hist(result_df.loc[result_df.label==0, "risk"], bins=40,
            alpha=.75, color="#4CAF93", label="Normal",  edgecolor="none")
    ax.hist(result_df.loc[result_df.label==1, "risk"], bins=40,
            alpha=.75, color="#E05C5C", label="Anomaly", edgecolor="none")

    for th, c in [(30,"#FFD700"),(60,"#FFA500"),(80,"#FF4444")]:
        ax.axvline(th, color=c, ls="--", lw=1.5, alpha=.9)

    ax.set_title("Risk Score Distribution", color=TXT, fontsize=14, fontweight="bold")
    ax.set_xlabel("Risk %", color=TXT); ax.set_ylabel("Count", color=TXT)
    ax.legend(labelcolor=TXT, framealpha=.15)
    ax.grid(color=GRD, ls=":", lw=.5, alpha=.5)
    plt.tight_layout()
    plt.savefig(path, dpi=150, bbox_inches="tight", facecolor=BG)
    plt.close(fig)
    print(f"\n[Chart]    Saved -> {path}")


# =============================================================================
#  STEP 7 — Main
# =============================================================================

def main():
    print("=" * 60)
    print("  ANOMALY DETECTION SYSTEM  v3.1")
    print("  Dataset: embedded_system_network_security_dataset.csv")
    print("=" * 60)

    # 1. Load
    df, feature_cols = load_data()

    # 2. Train
    model = train_model(df, feature_cols)

    # 3. Predict a few samples from the ACTUAL dataset
    print("\n" + "=" * 60)
    print("  SAMPLE PREDICTIONS FROM DATASET")
    print("=" * 60)

    # Pick 3 normal rows and 3 anomaly rows
    normals  = df[df["label"] == 0].sample(3, random_state=42)
    anomalies = df[df["label"] == 1].sample(3, random_state=42)

    for i, (_, row) in enumerate(normals.iterrows(), 1):
        print(f"\n--- Normal sample {i} ---")
        predict_risk(model, feature_cols, row[feature_cols].values)

    for i, (_, row) in enumerate(anomalies.iterrows(), 1):
        print(f"\n--- Anomaly sample {i} ---")
        predict_risk(model, feature_cols, row[feature_cols].values)

    # 4. Evaluate full dataset
    print("\n" + "=" * 60)
    print("  FULL DATASET EVALUATION")
    print("=" * 60)
    result_df = evaluate_all(model, df, feature_cols)

    # 5. Save outputs
    result_df.to_csv("scored_sessions.csv", index=False)
    print("\n[Output]   scored_sessions.csv saved.")

    save_chart(result_df)

    print("\n[DONE]")


# =============================================================================
#  Helper for test_sample.py
# =============================================================================

def get_trained_model():
    """Load data, train model, return (model, feature_cols)."""
    df, feature_cols = load_data()
    model = train_model(df, feature_cols)
    return model, feature_cols


# =============================================================================
#  STEP 8 — Model Persistence & Dataset Updates
# =============================================================================

def save_model(model, feature_cols, filepath="model.pkl"):
    """Export model and feature columns to disk."""
    joblib.dump({"model": model, "feature_cols": feature_cols}, filepath)

def load_model(filepath="model.pkl"):
    """Load model and feature columns from disk."""
    if not os.path.exists(filepath):
        return None, None
    data = joblib.load(filepath)
    return data["model"], data["feature_cols"]

def append_and_retrain(new_values, feature_cols, label):
    """
    Append a new packet array to the CSV via pandas, 
    and train + export a newly updated model.
    """
    # 1. Prepare values (de-normalise ports so they format properly in CSV)
    save_vals = list(new_values)
    save_vals[2] = int(round(save_vals[2] * 65535.0))
    save_vals[3] = int(round(save_vals[3] * 65535.0))
    
    new_row = {"label": int(label)}
    for col, val in zip(feature_cols, save_vals):
        # make nice types for CSV
        if col.startswith(('src_ip_', 'dst_ip_', 'protocol_', 'tcp_')):
            new_row[col] = int(val)
        else:
            new_row[col] = float(val)

    # 2. Append directly to raw CSV (preserving drop cols like mean_packet_size)
    raw_df = pd.read_csv(CSV_PATH)
    if 'mean_packet_size' not in new_row and 'mean_packet_size' in raw_df.columns:
        new_row['mean_packet_size'] = 0.0
        
    raw_df = pd.concat([raw_df, pd.DataFrame([new_row])], ignore_index=True)
    raw_df.to_csv(CSV_PATH, index=False)
    print(f"\n[Dataset]  Appended new row. Total rows: {len(raw_df)}")
    
    # 3. Retrain model with updated CSV
    df, f_cols = load_data()
    updated_model = train_model(df, f_cols)
    
    # 4. Save pickle files (versioned and main)
    import glob
    version = len(glob.glob("model_v*.pkl")) + 1
    versioned_path = f"model_v{version}.pkl"
    
    save_model(updated_model, f_cols, versioned_path)
    save_model(updated_model, f_cols, "model.pkl")
    
    print(f"[Model]    Exported updated models to -> {versioned_path}  &  model.pkl")
    return updated_model, f_cols


# =============================================================================
if __name__ == "__main__":
    main()
