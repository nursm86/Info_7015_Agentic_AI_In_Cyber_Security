import numpy as np
import pandas as pd
from datetime import timedelta
from typing import Dict

from feature_eng import load_data, KAGGLE_MAP

def append_synthetic_batch(
    csv_path: str,
    n_rows: int = 400,
    attack_rate: float = 0.15,
    seed: int = 123
) -> dict:
    """
    Append ~n_rows to the dataset by cloning/perturbing recent rows and enforcing
    a target malicious rate (attack_rate). Returns metadata for logging.
    Safe against duplicate column labels in the CSV header.
    """
    rng = np.random.default_rng(seed)

    # Load harmonized dataframe (guarantees our schema, including 'ts')
    df = load_data(csv_path)
    if len(df) < 200:
        raise ValueError("Need at least 200 rows to seed synthetic generation.")

    # Recent pool to clone from
    pool = df.iloc[-min(2000, len(df)) : ].copy().reset_index(drop=True)

    # Sample base rows
    k = min(n_rows, len(pool))
    base = pool.sample(n=k, random_state=seed).reset_index(drop=True)

    # Enforce attack rate
    pos = int(round(attack_rate * k))
    mask = np.zeros(k, dtype=bool)
    mask[:pos] = True
    rng.shuffle(mask)
    base["y"] = mask.astype(int)

    # Gentle numeric perturbations (only if the columns exist)
    if "rtt_ms" in base.columns:
        base["rtt_ms"] = (
            base["rtt_ms"].astype(float) * rng.normal(1.0, 0.15, k)
        ).clip(0, None).round().astype(int)
    if "attempts_1m_by_ip" in base.columns:
        base["attempts_1m_by_ip"] = (
            base["attempts_1m_by_ip"].astype(float) + rng.integers(0, 2, k)
        ).astype(int)
    if "attempts_5m_by_ip" in base.columns:
        base["attempts_5m_by_ip"] = (
            base["attempts_5m_by_ip"].astype(float) + rng.integers(0, 3, k)
        ).astype(int)
    if "fail_ratio_10m_by_ip" in base.columns:
        base["fail_ratio_10m_by_ip"] = np.clip(
            base["fail_ratio_10m_by_ip"].astype(float) + rng.normal(0, 0.05, k),
            0, 1
        )

    # Push timestamps forward so they’re newer
    last_ts = df["ts"].max()
    increments = [timedelta(seconds=int(i * (180.0 / max(k, 1)))) for i in range(k)]
    base["ts"] = [last_ts + inc for inc in increments]

    # --- Ensure column order matches current dataframe (canonical schema) ---
    canonical_cols = pd.Index(df.columns).drop_duplicates().tolist()
    base = base.loc[:, ~base.columns.duplicated()].copy()

    missing_cols = [c for c in canonical_cols if c not in base.columns]
    for c in missing_cols:
        base[c] = np.nan

    base = base[canonical_cols]

    # Append to disk: same CSV, no header
    base.to_csv(csv_path, mode="a", index=False, header=False)

    ts_values = base["ts"] if "ts" in base.columns else pd.Series(dtype="datetime64[ns]")

    return {
        "appended": int(len(base)),
        "attack_rate": float(attack_rate),
        "ts_from": str(pd.to_datetime(ts_values).min()) if not ts_values.empty else None,
        "ts_to": str(pd.to_datetime(ts_values).max()) if not ts_values.empty else None,
    }
