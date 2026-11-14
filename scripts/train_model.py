"""
train_model.py
Builds time-window features from the SQLite alerts database,
trains an Isolation Forest model on normal baseline traffic,
and saves the model to disk.

Run once after collecting enough normal + attack traffic:
    python3 train_model.py
"""

import sqlite3
import pandas as pd
import numpy as np
from sklearn.ensemble import IsolationForest
import joblib
import os

DB_PATH    = "/home/wejdan/idrs/db/idrs.db"
MODEL_PATH = "/home/wejdan/idrs/isolation_forest_model.pkl"
FEATURES_PATH = "/home/wejdan/idrs/features.csv"
COMBINED_PATH = "/home/wejdan/idrs/features_combined.csv"

FEATURE_COLS = ["packet_count", "distinct_ports", "distinct_protocols", "hour_of_day"]
WINDOW_SECONDS = 10
CONTAMINATION  = 0.07   # tuned value — see project report section 1.17


def load_alerts():
    conn = sqlite3.connect(DB_PATH)
    df = pd.read_sql_query(
        "SELECT src_ip, timestamp, dst_port, protocol, signature, label FROM alerts",
        conn
    )
    conn.close()
    return df


def parse_timestamps(df):
    # Snort timestamps arrive as strings like "07/22-19:09:44.921344"
    # or standard ISO format depending on pipeline version
    def parse_one(ts):
        if ts is None:
            return pd.NaT
        for fmt in ("%m/%d-%H:%M:%S.%f", "%Y-%m-%dT%H:%M:%S.%f", "%Y-%m-%d %H:%M:%S"):
            try:
                return pd.to_datetime(ts, format=fmt)
            except ValueError:
                continue
        return pd.NaT

    df["parsed_time"] = df["timestamp"].apply(parse_one)
    df = df.dropna(subset=["parsed_time"])
    return df


def build_features(df):
    df = df.copy()
    df["time_window"] = df["parsed_time"].dt.floor(f"{WINDOW_SECONDS}s")
    df["hour_of_day"] = df["parsed_time"].dt.hour

    features = (
        df.groupby(["src_ip", "time_window", "label"])
        .agg(
            packet_count=("src_ip", "count"),
            distinct_ports=("dst_port", "nunique"),
            distinct_protocols=("protocol", "nunique"),
            hour_of_day=("hour_of_day", "first"),
            signature=("signature", "first"),
        )
        .reset_index()
    )
    return features


def train(features):
    normal = features[features["label"] == "normal"]
    X_train = normal[FEATURE_COLS]

    model = IsolationForest(contamination=CONTAMINATION, random_state=42)
    model.fit(X_train)

    X_all = features[FEATURE_COLS]
    predictions = model.predict(X_all)
    features = features.copy()
    features["predicted"] = predictions
    features["predicted_label"] = features["predicted"].map({1: "normal", -1: "anomaly"})

    return model, features


def print_results(features):
    ct = pd.crosstab(features["label"], features["predicted_label"])
    print("\n=== Isolation Forest Results ===")
    print(ct)

    attack = features[features["label"] == "attack"]
    normal = features[features["label"] == "normal"]

    if len(attack) > 0:
        detected = (attack["predicted_label"] == "anomaly").sum()
        print(f"\nDetection rate  : {detected}/{len(attack)} = {detected/len(attack)*100:.1f}%")

    if len(normal) > 0:
        fp = (normal["predicted_label"] == "anomaly").sum()
        print(f"False-positive  : {fp}/{len(normal)} = {fp/len(normal)*100:.1f}%")

    # Combined detection breakdown
    features2 = features.copy()
    features2["snort_detected"] = features2["label"] == "attack"
    features2["ml_detected"]    = features2["predicted_label"] == "anomaly"

    def method(row):
        if row["snort_detected"] and row["ml_detected"]:
            return "Both"
        elif row["snort_detected"]:
            return "Signature only"
        elif row["ml_detected"]:
            return "Behavioral only"
        else:
            return "None"

    features2["detection_method"] = features2.apply(method, axis=1)
    print("\n=== Combined Detection Breakdown ===")
    print(features2["detection_method"].value_counts())


def main():
    print("Loading alerts from database...")
    df = load_alerts()
    print(f"  {len(df)} rows loaded")

    print("Parsing timestamps...")
    df = parse_timestamps(df)

    print("Building time-window features...")
    features = build_features(df)
    features.to_csv(FEATURES_PATH, index=False)
    print(f"  Saved {len(features)} windows to {FEATURES_PATH}")

    print(f"Training Isolation Forest (contamination={CONTAMINATION})...")
    model, features_with_pred = train(features)

    joblib.dump(model, MODEL_PATH)
    print(f"  Model saved to {MODEL_PATH}")

    features_with_pred.to_csv(COMBINED_PATH, index=False)
    print(f"  Predictions saved to {COMBINED_PATH}")

    print_results(features_with_pred)
    print("\nDone.")


if __name__ == "__main__":
    main()