from .anomaly_detection import load_model, predict_risk, get_trained_model, save_model

import os

_THIS_DIR = os.path.dirname(os.path.abspath(__file__))
MODEL_PATH = os.path.join(_THIS_DIR, "model.pkl")

_model = None
_feature_cols = None


def get_model():
    global _model, _feature_cols

    if _model is None:
        _model, _feature_cols = load_model(MODEL_PATH)

        if _model is None:
            print("⚠️ Model not found. Training new model...")

            _model, _feature_cols = get_trained_model()
            save_model(_model, _feature_cols, MODEL_PATH)

    return _model, _feature_cols


def get_ml_risk_score(feature_values):
    """
    feature_values: list of 16 features (same order as training)
    """
    model, feature_cols = get_model()

    result = predict_risk(
        model,
        feature_cols,
        feature_values,
        verbose=False
    )

    return result  # contains risk, decision, etc.


import hashlib
from datetime import datetime


def normalize(value, max_val):
    return min(value / max_val, 1.0)


def hash_to_unit(value):
    """Convert string → deterministic 0-1 float"""
    h = hashlib.md5(value.encode()).hexdigest()
    return int(h[:8], 16) / 0xFFFFFFFF


def build_ml_features(context, profile, flag):
    ip = context.get("ip", "0.0.0.0")
    device = context.get("device", "unknown")
    endpoint = context.get("endpoint", "")
    timestamp = context.get("timestamp")

    if flag == "True":
        return [
            1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1
        ]

    # -----------------------------
    # 1. IP FEATURES
    # -----------------------------
    prefix = ".".join(ip.split(".")[:2])
    ip_data = profile.usual_ip_prefixes or {}
    ip_count = ip_data.get(prefix, 0)

    ip_frequency = normalize(ip_count, 20)
    ip_is_new = 1 if ip_count == 0 else 0

    ip_hash_1 = hash_to_unit(ip)
    ip_hash_2 = hash_to_unit(ip[::-1])

    # -----------------------------
    # 2. DEVICE FEATURES
    # -----------------------------
    known_device = 1 if profile.usual_device == device else 0
    device_hash = hash_to_unit(device)

    # -----------------------------
    # 3. TIME FEATURES
    # -----------------------------
    try:
        hour = datetime.utcnow().hour
    except:
        hour = 12

    time_norm = hour / 24.0

    if profile.usual_login_start is not None:
        is_weird_time = int(
            not (profile.usual_login_start <= hour <= profile.usual_login_end)
        )
    else:
        is_weird_time = 0

    # -----------------------------
    # 4. ENDPOINT FEATURES
    # -----------------------------
    endpoint_hash = hash_to_unit(endpoint)

    sensitive_endpoints = ["/login", "/transfer", "/admin", "/api/chat"]
    endpoint_risk = 1 if endpoint in sensitive_endpoints else 0

    # -----------------------------
    # 5. SYNTHETIC NETWORK-LIKE FEATURES
    # -----------------------------
    packet_size = 0.3 + (0.4 * ip_frequency)
    inter_arrival_time = 0.2 + (0.5 * (1 - ip_frequency))
    src_port = hash_to_unit(ip)
    dst_port = hash_to_unit(endpoint)

    packet_count_5s = normalize(ip_count, 50)

    spectral_entropy = 0.5 + (0.5 * device_hash)
    frequency_band_energy = 0.3 + (0.5 * endpoint_hash)

    TCP = 1
    UDP = 0

    FIN = 0
    SYN = 1 if ip_is_new else 0
    SYN_ACK = 1 if known_device else 0

    # FINAL VECTOR (16 features)
    return [
        packet_size,
        inter_arrival_time,
        src_port,
        dst_port,
        packet_count_5s,
        spectral_entropy,
        frequency_band_energy,
        TCP,
        UDP,
        ip_hash_1,
        ip_hash_2,
        endpoint_hash,
        device_hash,
        FIN,
        SYN,
        SYN_ACK
    ]


def refresh_model():
    global _model, _feature_cols
    _model, _feature_cols = load_model(MODEL_PATH)
