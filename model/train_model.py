import argparse, joblib, os
import numpy as np
import pandas as pd

from sklearn.preprocessing import OneHotEncoder, StandardScaler
from sklearn.compose import ColumnTransformer
from sklearn.linear_model import LogisticRegression
from sklearn.calibration import CalibratedClassifierCV
from sklearn.pipeline import Pipeline
from sklearn.metrics import roc_auc_score, average_precision_score
from sklearn.impute import SimpleImputer
from sklearn.pipeline import Pipeline as SkPipe
from sklearn.model_selection import StratifiedShuffleSplit

from feature_eng import load_data, split_time, NUM_FEATS, CAT_FEATS


def build_pipeline():
    """Preprocess + calibrated Logistic Regression."""
    num_pipe = SkPipe([
        ('impute', SimpleImputer(strategy='median')),
        ('scale', StandardScaler()),
    ])
    cat_pipe = SkPipe([
        ('impute', SimpleImputer(strategy='most_frequent')),
        ('ohe', OneHotEncoder(handle_unknown='ignore', sparse_output=False)),
    ])

    pre = ColumnTransformer(
        transformers=[
            ('num', num_pipe, NUM_FEATS),
            ('cat', cat_pipe, CAT_FEATS),
        ],
        remainder='drop',
        verbose_feature_names_out=False,
    )

    base = LogisticRegression(
        max_iter=1000,
        class_weight='balanced',
        solver='lbfgs',
        random_state=42,
    )

    clf = CalibratedClassifierCV(base, cv=3, method='isotonic')
    return Pipeline([('prep', pre), ('clf', clf)])


def stratified_sample(df: pd.DataFrame, n_samples: int = 1000, random_state: int = 42) -> pd.DataFrame:
    if 'y' not in df.columns:
        raise ValueError("Expected a 'y' column for stratified sampling.")
    n = min(int(n_samples), len(df))
    if n <= 0 or n == len(df):
        return df.copy()

    y = df['y'].astype(int).values
    sss = StratifiedShuffleSplit(n_splits=1, train_size=n, random_state=random_state)
    idx, _ = next(sss.split(df, y))
    sampled = df.iloc[idx].copy()

    # logs
    orig_counts = pd.Series(y).value_counts(normalize=True).sort_index()
    samp_counts = sampled['y'].astype(int).value_counts(normalize=True).sort_index()
    print(f"[INFO] Stratified sample size: {len(sampled)} (of {len(df)})")
    print(f"[INFO] Class ratio (orig): {orig_counts.to_dict()}  |  (sample): {samp_counts.to_dict()}")
    return sampled


def main(args):
    df = load_data(args.csv)
    df = stratified_sample(df, n_samples=1000, random_state=42)
    train, test = split_time(df, ratio=0.8)

    feats = NUM_FEATS + CAT_FEATS
    X_train, y_train = train[feats], train['y'].astype(int)
    X_test,  y_test  = test[feats],  test['y'].astype(int)

    pipe = build_pipeline()
    pipe.fit(X_train, y_train)

    p = pipe.predict_proba(X_test)[:, 1]
    if len(np.unique(y_test)) > 1:
        roc = float(roc_auc_score(y_test, p))
        pr  = float(average_precision_score(y_test, p))
    else:
        roc, pr = None, None

    print(f"ROC AUC: {roc if roc is not None else 'nan'} | PR AUC: {pr if pr is not None else 'nan'}")
    print("Metrics:", {
        'roc_auc': roc, 'pr_auc': pr,
        'n_train': int(len(train)), 'n_test': int(len(test))
    })

    os.makedirs(os.path.dirname(args.out_model), exist_ok=True)
    joblib.dump(pipe, args.out_model)
    print(f"Saved model to {args.out_model}")


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument('--csv', default='./data/kaggle_50k_time.csv',
                    help='Input CSV (after feature_eng.load_data harmonization)')
    ap.add_argument('--out_model', default='./model_store/rba_model.joblib',
                    help='Path to save trained model pipeline')
    args = ap.parse_args()
    main(args)
