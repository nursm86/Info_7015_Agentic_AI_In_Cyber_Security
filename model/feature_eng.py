import pandas as pd
from typing import Tuple, Dict, Any

# =========================
# Public feature lists
# =========================
NUM_FEATS = [
    'attempts_1m_by_ip', 'attempts_5m_by_ip',
    'attempts_1m_by_user', 'attempts_5m_by_user',
    'fail_ratio_10m_by_ip', 'burst_length_ip', 'inter_attempt_ms_ip',
    'geo_velocity_user',
    'rtt_ms',
    'login_success',
]
CAT_FEATS = [
    'ua_family', 'device_type', 'country_ip', 'asn_ip',
    'device_seen_before_user', 'cookie_seen_before_user',
]
ALL_FEATS = NUM_FEATS + CAT_FEATS

# =========================
# Kaggle → our schema mapping (exported)
# Left: our canonical column name  →  Right: Kaggle/raw column
# =========================
KAGGLE_MAP: Dict[str, str] = {
    # time + ids
    'ts': 'Login Timestamp',
    'user_id_hash': 'User ID',
    'ip_hash': 'IP Address',

    # categorical/context
    'country_ip': 'Country',
    'asn_ip': 'ASN',
    'device_type': 'Device Type',

    # numeric
    'rtt_ms': 'Round-Trip Time [ms]',

    # optional input
    'login_success': 'Login Successful',

    # label (pick one)
    # 'y': 'Is Account Takeover',
    'y': 'Is Attack IP',
}

# =========================
# Helpers
# =========================
def _to_binary(series: pd.Series) -> pd.Series:
    if series is None:
        return pd.Series(dtype='int64')
    s = series.astype(str).str.strip().str.lower()
    true_set  = {'1', 'true', 'yes', 'y', 't'}
    false_set = {'0', 'false', 'no', 'n', 'f', ''}
    return s.apply(lambda v: 1 if v in true_set else (0 if v in false_set else 0)).astype('int64')

def _simple_ua_family(df: pd.DataFrame) -> pd.Series:
    if 'Browser Name and Version' in df.columns:
        return df['Browser Name and Version'].astype(str).str.split().str[0].fillna('Unknown')
    if 'User Agent String' in df.columns:
        ua = df['User Agent String'].astype(str)
        fam = ua.str.extract(r'^([A-Za-z]+)')[0]
        return fam.fillna('Unknown')
    return pd.Series(['Unknown'] * len(df))

def _normalize_device_type(s: pd.Series) -> pd.Series:
    x = s.astype(str).str.lower()
    def bucket(v: str) -> str:
        if any(k in v for k in ['mobile', 'android', 'iphone', 'phone']): return 'mobile'
        if any(k in v for k in ['tablet', 'ipad']): return 'tablet'
        if any(k in v for k in ['desktop', 'pc', 'mac', 'windows', 'linux']): return 'desktop'
        return 'other'
    return x.map(bucket)

# =========================
# Harmonization
# =========================
def harmonize_columns(df: pd.DataFrame) -> pd.DataFrame:
    # 1) rename Kaggle/raw → our canonical
    present = {k: v for k, v in KAGGLE_MAP.items() if v in df.columns}
    df = df.rename(columns={present[k]: k for k in present})

    # 2) ids as strings (create if missing)
    for col in ['user_id_hash', 'ip_hash']:
        if col in df.columns:
            df[col] = df[col].astype(str)
        else:
            df[col] = 'unknown'

    # 3) ua_family
    if 'ua_family' not in df.columns:
        df['ua_family'] = _simple_ua_family(df).astype(str)

    # 4) device/country/asn defaults
    if 'device_type' in df.columns:
        df['device_type'] = _normalize_device_type(df['device_type'])
    else:
        df['device_type'] = 'desktop'

    df['country_ip'] = df.get('country_ip', 'ZZ').astype(str).fillna('ZZ')

    if 'asn_ip' in df.columns:
        asn = pd.to_numeric(df['asn_ip'], errors='coerce').fillna(-1).astype('int64').astype(str)
        df['asn_ip'] = 'asn' + asn
    else:
        df['asn_ip'] = 'asn0'

    # 5) seen flags
    for c in ['device_seen_before_user', 'cookie_seen_before_user']:
        df[c] = _to_binary(df[c]) if c in df.columns else 0

    # 6) numeric engineered defaults
    num_defaults = {
        'attempts_1m_by_ip': 0,
        'attempts_5m_by_ip': 0,
        'attempts_1m_by_user': 0,
        'attempts_5m_by_user': 0,
        'fail_ratio_10m_by_ip': 0.0,
        'burst_length_ip': 1,
        'inter_attempt_ms_ip': 8000,
        'geo_velocity_user': 0.0,
    }
    for c, v in num_defaults.items():
        if c not in df.columns:
            df[c] = v

    df['rtt_ms'] = pd.to_numeric(df.get('rtt_ms', 0), errors='coerce').fillna(0).astype('int64')
    df['login_success'] = _to_binary(df.get('login_success', 0))

    # 7) label
    if 'y' not in df.columns:
        raise ValueError("Label column 'y' not found. Set KAGGLE_MAP['y'] correctly.")
    df['y'] = _to_binary(df['y'])

    # 8) timestamp
    if 'ts' not in df.columns:
        # fall back if the source column was never present
        df['ts'] = pd.Timestamp.now().normalize() + pd.to_timedelta(range(len(df)), unit='s')

    return df

# =========================
# Public loaders
# =========================
def load_data(csv_path: str) -> pd.DataFrame:
    raw = pd.read_csv(csv_path)
    df = harmonize_columns(raw)
    df['ts'] = pd.to_datetime(df['ts'], errors='coerce')
    df = df.dropna(subset=['ts'])
    df = df.sort_values('ts').reset_index(drop=True)
    keep = ['ts', 'user_id_hash', 'ip_hash'] + ALL_FEATS + ['y']
    return df[[c for c in keep if c in df.columns]].copy()

def split_time(df: pd.DataFrame, ratio: float = 0.8) -> Tuple[pd.DataFrame, pd.DataFrame]:
    n = int(len(df) * ratio)
    return df.iloc[:n].copy(), df.iloc[n:].copy()
