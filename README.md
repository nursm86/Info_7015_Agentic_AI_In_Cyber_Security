# RBA Agentic Model Starter Kit

This pack gives you a minimal, **doable** pipeline for a risk-based authentication (RBA) agent that
scores login attempts, decides actions (ALLOW / STEP_UP / BLOCK), and **adapts** via periodic
retraining + threshold auto-tuning.

## Structure
- `data/sample_logs.csv` — example schema & a few rows
- `model/feature_eng.py` — feature definitions + time split
- `model/train_model.py` — trains calibrated logistic regression (or SGD) and saves model
- `model/thresholds.py` — cost-based threshold sweep
- `model/agent_loop.py` — one-shot retrain + threshold tuning (cron every 10–20 minutes)
- `dashboard/app.py` — Streamlit dashboard to visualize risk & actions
- `requirements.txt` — Python deps

## Quick Start
```bash
pip install -r requirements.txt
python model/train_model.py --csv data/sample_logs.csv --out_model model_store/rba_model.joblib
# run agent loop to tune thresholds & retrain using your data
python model/agent_loop.py
# dashboard
streamlit run dashboard/app.py
```

## Data Schema
Required columns in your CSV (one row per login attempt):
- `ts` (ISO timestamp), `user_id_hash`, `ip_hash`, `ua_family`, `device_type`, `country_ip`, `asn_ip`,
  `device_seen_before_user` (0/1), `cookie_seen_before_user` (0/1),
  `attempts_1m_by_ip`, `attempts_5m_by_ip`, `attempts_1m_by_user`, `attempts_5m_by_user`,
  `fail_ratio_10m_by_ip`, `burst_length_ip`, `inter_attempt_ms_ip`, `geo_velocity_user`,
  `y` (0=benign, 1=malicious) for training/evaluation.

## Agentic Behaviour
- **Autonomy:** decisions made per attempt without human in the loop.
- **Learning:** periodic retrain on rolling buffer (edit agent_loop to plug in your live CSV).
- **Adaptivity:** threshold sweep finds (tau1, tau2) that minimize cost under guardrails.
- **Goal‑oriented:** minimize FN cost while keeping user friction under target caps.

## Notes
- Replace `data/sample_logs.csv` with your logs file path.
- Add cron/systemd to run `agent_loop.py` every 10–20 minutes for continuous learning.
- For production, restrict feature PII, add audit logs, and version models.
