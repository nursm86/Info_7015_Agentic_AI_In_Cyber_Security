import json
import os
import sys
from pathlib import Path
from typing import Dict, Any

BASE_DIR = Path(__file__).resolve().parent
VENDOR_PATH = BASE_DIR / 'vendor'
if VENDOR_PATH.exists():
    sys.path.insert(0, str(VENDOR_PATH))

import joblib
import numpy as np
import pandas as pd

from feature_eng import NUM_FEATS, CAT_FEATS

CONF_PATH = os.getenv('RBA_CONF_PATH', './model_store/agent_config.json')
MODEL_PATH = os.getenv('RBA_MODEL_PATH', './model_store/rba_model.joblib')

DEFAULT_CONF = {'tau1': 0.16, 'tau2': 0.22}

NUM_DEFAULTS: Dict[str, float] = {
    'attempts_1m_by_ip': 0.0,
    'attempts_5m_by_ip': 0.0,
    'attempts_1m_by_user': 0.0,
    'attempts_5m_by_user': 0.0,
    'fail_ratio_10m_by_ip': 0.0,
    'burst_length_ip': 1.0,
    'inter_attempt_ms_ip': 60000.0,
    'geo_velocity_user': 0.0,
    'rtt_ms': 0.0,
    'login_success': 0.0,
}

CAT_DEFAULTS: Dict[str, str] = {
    'ua_family': 'Unknown',
    'device_type': 'desktop',
    'country_ip': 'ZZ',
    'asn_ip': 'asn0',
    'device_seen_before_user': '0',
    'cookie_seen_before_user': '0',
}

_PIPELINE_CACHE = None

def _load_conf() -> Dict[str, Any]:
    conf = DEFAULT_CONF.copy()
    if os.path.exists(CONF_PATH):
        try:
            with open(CONF_PATH, 'r', encoding='utf-8') as f:
                conf.update(json.load(f))
        except Exception:
            pass
    return conf


def _load_model():
    global _PIPELINE_CACHE
    if _PIPELINE_CACHE is not None:
        return _PIPELINE_CACHE

    if not os.path.exists(MODEL_PATH):
        raise FileNotFoundError(f"Model file not found at {MODEL_PATH}")
    _PIPELINE_CACHE = joblib.load(MODEL_PATH)
    return _PIPELINE_CACHE


def _prepare_row(features: Dict[str, Any]) -> pd.DataFrame:
    data: Dict[str, Any] = {}

    for feat in NUM_FEATS:
        value = features.get(feat, NUM_DEFAULTS.get(feat, 0.0))
        try:
            data[feat] = float(value)
        except Exception:
            data[feat] = float(NUM_DEFAULTS.get(feat, 0.0))

    for feat in CAT_FEATS:
        value = features.get(feat, CAT_DEFAULTS.get(feat, ''))
        if isinstance(value, (int, float)):
            value = str(int(value))
        data[feat] = str(value)

    return pd.DataFrame([data], columns=NUM_FEATS + CAT_FEATS)


def score(features: Dict[str, Any]) -> Dict[str, Any]:
    conf = _load_conf()
    pipe = _load_model()

    row = _prepare_row(features)
    proba = float(pipe.predict_proba(row)[0, 1])

    tau1 = float(conf.get('tau1', DEFAULT_CONF['tau1']))
    tau2 = float(conf.get('tau2', DEFAULT_CONF['tau2']))

    if proba >= tau2:
        decision = 'block'
    elif proba >= tau1:
        decision = 'step_up'
    else:
        decision = 'allow'

    return {
        'score': proba,
        'decision': decision,
        'tau1': tau1,
        'tau2': tau2,
    }


def main():
    raw = sys.stdin.read() or ''
    if not raw and len(sys.argv) > 1:
        raw = sys.argv[1]

    if not raw:
        raise ValueError("No input payload received")

    payload = json.loads(raw)
    features = payload.get('features')
    if not isinstance(features, dict):
        raise ValueError("Payload must contain a 'features' object")

    result = score(features)
    sys.stdout.write(json.dumps(result))


if __name__ == '__main__':
    try:
        main()
    except Exception as exc:
        sys.stderr.write(json.dumps({'error': str(exc)}))
        sys.exit(1)
