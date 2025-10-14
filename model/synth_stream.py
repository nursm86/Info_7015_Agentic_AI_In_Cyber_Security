"""
Tiny helper to generate a visible trend without clicking:
  python model/synth_stream.py --kind benign --loops 2
  python model/synth_stream.py --kind attack --loops 3
"""
import argparse, subprocess
from sim_data import append_synthetic_batch

DATA_CSV = './data/kaggle_50k_time.csv'

def run(kind: str, loops: int, rows: int):
    rate = 0.02 if kind == 'benign' else 0.25
    for _ in range(loops):
        append_synthetic_batch(DATA_CSV, n_rows=rows, attack_rate=rate)
        subprocess.run(["python", "./model/agent_loop.py"], check=True)

if __name__ == '__main__':
    ap = argparse.ArgumentParser()
    ap.add_argument('--kind', choices=['benign','attack'], default='attack')
    ap.add_argument('--loops', type=int, default=2)
    ap.add_argument('--rows', type=int, default=600)
    args = ap.parse_args()
    run(args.kind, args.loops, args.rows)
