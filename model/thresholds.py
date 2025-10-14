import numpy as np

def eval_policy(p, y, t1, t2):
    allow = p < t1
    step  = (p >= t1) & (p < t2)
    block = p >= t2

    tn        = int(np.sum((y==0) & allow))
    fp_step   = int(np.sum((y==0) & step))
    fp_block  = int(np.sum((y==0) & block))
    tp        = int(np.sum((y==1) & block))
    fn        = int(np.sum((y==1) & allow))

    n         = len(y)
    block_rt  = (fp_block + tp) / n
    step_rt   = (fp_step) / n

    return dict(tn=tn, fp_step=fp_step, fp_block=fp_block, tp=tp, fn=fn,
                block_rate=block_rt, step_rate=step_rt)

def sweep_thresholds(p, y,
                     C_FN=100, C_FP_STEP=1, C_FP_BLOCK=5,
                     max_block_rate=0.02, max_step_rate=0.10):
    grid = np.linspace(0.02, 0.98, 25)
    best = None
    cand = []

    for t1 in grid:
        for t2 in grid:
            if t2 <= t1: 
                continue
            stats = eval_policy(p, y, t1, t2)
            if stats["block_rate"] > max_block_rate or stats["step_rate"] > max_step_rate:
                continue
            cost = C_FN*stats["fn"] + C_FP_STEP*stats["fp_step"] + C_FP_BLOCK*stats["fp_block"]
            cand.append((cost, t1, t2, stats))

    if not cand:
        # fall back if guardrails too strict
        t1, t2 = 0.1, 0.9
        stats = eval_policy(p, y, t1, t2)
        cost  = C_FN*stats["fn"] + C_FP_STEP*stats["fp_step"] + C_FP_BLOCK*stats["fp_block"]
        return {
            "tau1": t1, "tau2": t2, "cost": float(cost),
            "stats": stats, "alternatives": []
        }

    cand.sort(key=lambda z: z[0])
    cost, t1, t2, stats = cand[0]
    alts = [{"tau1": c[1], "tau2": c[2], "cost": float(c[0]), "stats": c[3]} for c in cand[1:4]]

    return {
        "tau1": float(t1), "tau2": float(t2), "cost": float(cost),
        "stats": stats, "alternatives": alts,
        "guardrails": {"max_block_rate": max_block_rate, "max_step_rate": max_step_rate,
                       "C_FN": C_FN, "C_FP_STEP": C_FP_STEP, "C_FP_BLOCK": C_FP_BLOCK}
    }
