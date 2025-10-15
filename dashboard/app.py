# RBA Agent Demo Dashboard (simple & engaging)
import os, sys, json, time, subprocess
import numpy as np
import pandas as pd
import streamlit as st
import altair as alt

# Access model modules
sys.path.append(os.path.join(os.path.dirname(__file__), '..', 'model'))
from feature_eng import load_data as fe_load_data, NUM_FEATS, CAT_FEATS
from sim_data import append_synthetic_batch

CONF_PATH   = './model_store/agent_config.json'
MODEL_PATH  = './model_store/rba_model.joblib'
DATA_CSV    = './data/kaggle_50k_time.csv'
HIST_PATH   = './model_store/threshold_history.jsonl'   # our UI-only history log
SWEEP_PATH  = './model_store/last_sweep.json'

st.set_page_config(page_title="Agentic AI Cybersecurity Demo", layout="wide")
st.title("🛡️ Agentic AI Cybersecurity Demo")

# ---------------- helpers ----------------
def _load_conf():
    if not os.path.exists(CONF_PATH):
        return {'tau1': 0.35, 'tau2': 0.95}
    return json.load(open(CONF_PATH))

def _append_history(entry: dict):
    os.makedirs(os.path.dirname(HIST_PATH), exist_ok=True)
    with open(HIST_PATH, "a", encoding="utf-8") as f:
        f.write(json.dumps(entry) + "\n")

def _load_history_df(max_rows=120):
    if not os.path.exists(HIST_PATH):
        return pd.DataFrame(columns=['ts','tau1','tau2','kind','attack_rate'])
    rows = []
    with open(HIST_PATH, "r", encoding="utf-8") as f:
        for line in f:
            try: rows.append(json.loads(line))
            except: pass
    if not rows: return pd.DataFrame(columns=['ts','tau1','tau2','kind','attack_rate'])
    df = pd.DataFrame(rows).tail(max_rows).copy()
    df['ts'] = pd.to_datetime(df['ts'], errors='coerce')
    return df.dropna(subset=['ts']).sort_values('ts')

def _retrain():
    subprocess.run(["python", "./model/agent_loop.py"], check=True)

def _explain_from_sweep():
    if not os.path.exists(SWEEP_PATH):
        return "No sweep info yet. Capture baseline or retrain once."
    obj = json.load(open(SWEEP_PATH, 'r'))
    swe = obj.get('sweep', {})
    g   = swe.get('guardrails', {})
    stats = swe.get('stats', {})
    alts  = swe.get('alternatives', [])
    # Deterministic, no-LLM explanation (keeps demo stable everywhere)
    lines = []
    lines.append(f"**Guardrails**: max_block_rate={g.get('max_block_rate', '?')}, "
                 f"max_step_rate={g.get('max_step_rate','?')} — "
                 f"Costs: C_FN={g.get('C_FN','?')}, C_FP_STEP={g.get('C_FP_STEP','?')}, C_FP_BLOCK={g.get('C_FP_BLOCK','?')}.")
    lines.append(f"**Chosen thresholds**: τ1={swe.get('tau1'):.3f}, τ2={swe.get('tau2'):.3f} "
                 f"(total cost={swe.get('cost'):.1f}).")
    lines.append(f"Breakdown at chosen τ: FN={stats.get('fn',0)}, FP(step)={stats.get('fp_step',0)}, FP(block)={stats.get('fp_block',0)}; "
                 f"block_rate={stats.get('block_rate',0):.3f}, step_rate={stats.get('step_rate',0):.3f}.")
    if alts:
        best_alt = min(alts, key=lambda a: a['cost'])
        lines.append(f"**Closest alternative**: τ1={best_alt['tau1']:.3f}, τ2={best_alt['tau2']:.3f} "
                     f"(cost={best_alt['cost']:.1f}). Chosen pair had lower or equal cost under guardrails.")
    return "\n\n".join(lines)

def _capture(kind=None, rate=None):
    conf_before = _load_conf()
    if kind == 'benign':
        meta = append_synthetic_batch(DATA_CSV, n_rows=600, attack_rate=0.02)
    elif kind == 'attack':
        meta = append_synthetic_batch(DATA_CSV, n_rows=600, attack_rate=0.25)
    else:
        meta = {"note": "baseline"}

    _retrain()
    conf_after = _load_conf()

    entry = {
        'ts': pd.Timestamp.now().isoformat(timespec='seconds'),
        'tau1': float(conf_after['tau1']),
        'tau2': float(conf_after['tau2']),
        'kind': ('baseline' if kind is None else kind),
        'attack_rate': (None if kind is None else (0.02 if kind=='benign' else 0.25)),
        'd_tau1': float(conf_after['tau1']) - float(conf_before.get('tau1', conf_after['tau1'])),
        'd_tau2': float(conf_after['tau2']) - float(conf_before.get('tau2', conf_after['tau2'])),
    }
    _append_history(entry)

def _safe_rerun():
    if hasattr(st, "rerun"):
        st.rerun()
    elif hasattr(st, "experimental_rerun"):
        st.experimental_rerun()

# --------------- left controls ---------------
with st.sidebar:
    st.header("Controls")
    if st.button("🔐 Capture Baseline"):
        _capture(kind=None)
        _safe_rerun()
    if st.button("➕ Add Benign Batch + Retrain"):
        _capture(kind='benign')
        _safe_rerun()
    if st.button("⚠️ Add Attack Batch + Retrain"):
        _capture(kind='attack')
        _safe_rerun()
    if st.button("🗑️ Reset History"):
        if os.path.exists(HIST_PATH): os.remove(HIST_PATH)
        _safe_rerun()

# --------------- top KPIs ---------------
conf = _load_conf()
k1, k2, k3, k4 = st.columns(4)
k1.metric("τ1 (allow→step)", f"{float(conf.get('tau1',0.35)):.2f}")
k2.metric("τ2 (step→block)", f"{float(conf.get('tau2',0.95)):.2f}")
# current rows scored (uses recent slice for speed)
try:
    df_preview = fe_load_data(DATA_CSV).tail(2000)
    k3.metric("Rows (preview)", f"{len(df_preview):,}")
except Exception:
    k3.metric("Rows (preview)", "—")
# last kind badge from history
hist_df = _load_history_df()
last_kind = hist_df.iloc[-1]['kind'] if len(hist_df) else "—"
k4.metric("Last retrain kind", last_kind)

st.caption("Baseline shows initial τ1/τ2 from the saved model. Each synthetic **benign/attack** batch triggers retrain + sweep under guardrails; charts update to show the trend.")

# --------------- trend chart + deltas ---------------
st.subheader("Threshold trend")
if len(hist_df) == 0:
    st.info("No history yet. Click **Capture Baseline** first.")
else:
    melt = (
        hist_df[['ts','tau1','tau2','kind']]
        .rename(columns={'tau1':'τ1','tau2':'τ2'})
        .melt(id_vars=['ts','kind'], var_name='threshold', value_name='value')
    )

    color_map = alt.Scale(domain=['baseline','benign','attack'],
                          range=['#6b7280','#22c55e','#ef4444'])

    line = (alt.Chart(melt)
        .mark_line(point=True)
        .encode(
            x=alt.X('ts:T', title='retrain time'),
            y=alt.Y('value:Q', title='threshold'),
            color=alt.Color('threshold:N'),
            tooltip=['ts:T','kind:N','threshold:N', alt.Tooltip('value:Q', format='.3f')]
        )
        .properties(height=260)
    )

    # --- NEW: robust delta computation (works even if d_tau* not in the file) ---
    hist_df = hist_df.copy()
    if 'd_tau1' not in hist_df.columns or 'd_tau2' not in hist_df.columns:
        hist_df['d_tau1'] = hist_df['tau1'].astype(float).diff().fillna(0.0)
        hist_df['d_tau2'] = hist_df['tau2'].astype(float).diff().fillna(0.0)

    delta_df = hist_df[['ts','d_tau1','d_tau2']].copy()
    delta_df = delta_df.rename(columns={'d_tau1':'τ1 Δ', 'd_tau2':'τ2 Δ'})
    melt_d = delta_df.melt(id_vars=['ts'], var_name='threshold', value_name='delta')
    delta_chart = (alt.Chart(melt_d)
        .mark_bar()
        .encode(
            x='ts:T',
            y=alt.Y('delta:Q', title='Δ since previous'),
            color=alt.condition(alt.datum.delta > 0, alt.value('#22c55e'), alt.value('#ef4444')),
            tooltip=['ts:T','threshold:N', alt.Tooltip('delta:Q', format='.3f')]
        )
        .properties(height=150)
    )
    st.altair_chart(line, use_container_width=True)
    st.altair_chart(delta_chart, use_container_width=True)


# --------------- compact table ---------------
st.subheader("Last retrains")
if len(hist_df):
    show = hist_df.copy()
    show['attack_rate'] = show['attack_rate'].apply(lambda v: ('—' if v is None else f"{int(v*100)}%"))
    st.dataframe(show[['ts','kind','attack_rate','tau1','tau2','d_tau1','d_tau2']].tail(12), use_container_width=True)
else:
    st.write("—")

# --------------- explanation ---------------
st.subheader("Why these thresholds?")
st.markdown(_explain_from_sweep())
