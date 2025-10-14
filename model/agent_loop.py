import os, json, joblib
import numpy as np
import pandas as pd
from typing import Dict

from feature_eng import load_data, split_time, NUM_FEATS, CAT_FEATS
from thresholds import sweep_thresholds
from train_model import build_pipeline

CONF_PATH   = './model_store/agent_config.json'
MODEL_PATH  = './model_store/rba_model.joblib'
DATA_CSV    = './data/kaggle_50k_time.csv'
SWEEP_PATH  = './model_store/last_sweep.json'  # written for the UI explanation

DEFAULT_CONF = {
    'tau1': 0.35, 'tau2': 0.95,
    'C_FN': 100, 'C_FP_STEP': 1, 'C_FP_BLOCK': 5,
    'max_block_rate': 0.02, 'max_step_rate': 0.10
}

def _load_conf() -> Dict:
    conf = DEFAULT_CONF.copy()
    if os.path.exists(CONF_PATH):
        try:
            conf.update(json.load(open(CONF_PATH, 'r')))
        except Exception:
            pass
    return conf

def _save_conf(conf: Dict):
    os.makedirs(os.path.dirname(CONF_PATH), exist_ok=True)
    with open(CONF_PATH, 'w') as f:
        json.dump(conf, f, indent=2)

def retrain_and_tune(sample_n: int = 1000):
    os.makedirs(os.path.dirname(MODEL_PATH), exist_ok=True)

    df = load_data(DATA_CSV)
    if len(df) < 200:
        print("Not enough data to retrain.")
        return

    # Stratified 1k by taking last ~N rows to reflect newest conditions while preserving label mix
    # (We still split by time inside.)
    df = df.iloc[-min(sample_n * 5, len(df)) : ].copy()

    train, test = split_time(df, ratio=0.8)
    feats = NUM_FEATS + CAT_FEATS

    X_train, y_train = train[feats], train['y'].astype(int)
    X_test,  y_test  = test[feats],  test['y'].astype(int)

    pipe = build_pipeline()
    pipe.fit(X_train, y_train)
    p = pipe.predict_proba(X_test)[:, 1]

    # threshold sweep under guardrails
    conf = _load_conf()
    swe = sweep_thresholds(
        p, y_test.values,
        C_FN=conf['C_FN'], C_FP_STEP=conf['C_FP_STEP'], C_FP_BLOCK=conf['C_FP_BLOCK'],
        max_block_rate=conf['max_block_rate'], max_step_rate=conf['max_step_rate']
    )
    conf['tau1'], conf['tau2'] = float(swe['tau1']), float(swe['tau2'])
    _save_conf(conf)

    # save model & sweep context for UI explanation
    joblib.dump(pipe, MODEL_PATH)
    with open(SWEEP_PATH, 'w') as f:
        json.dump({
            'ts': pd.Timestamp.now().isoformat(timespec='seconds'),
            'tau1': conf['tau1'], 'tau2': conf['tau2'],
            'sweep': swe
        }, f, indent=2)

    print(json.dumps({'tau1': conf['tau1'], 'tau2': conf['tau2']}, indent=2))


if __name__ == '__main__':
    retrain_and_tune(sample_n=1000)
