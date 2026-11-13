"""Deterministic statistics (standard library only). Same input -> byte-identical output.

All results are descriptive. There are no significance tests, no p-values and no probabilities;
correlation and trend never imply causation. Floats are rounded to 10 places for stable hashing.
"""
from __future__ import annotations
import math
import statistics
from datetime import date
from typing import Optional, Sequence

STATS_VERSION = "stats-v1"
MIN_N = 8                 # minimum points for trend / anomaly / correlation
ANOMALY_Z = 3.5           # modified z-score threshold (Iglewicz and Hoaglin)
FLAT_R2 = 0.10            # below this a fitted line explains <10% of variance: "flat_or_noisy"
MA_WINDOW = 5


def r10(x) -> Optional[float]:
    return None if x is None else round(float(x), 10)


def _days(d: str) -> int:
    return date.fromisoformat(d).toordinal()


def describe(vals: Sequence[float]) -> dict:
    n = len(vals)
    if n == 0:
        return {"n": 0, "min": None, "max": None, "mean": None, "median": None, "stdev": None, "first": None, "last": None}
    return {"n": n, "min": r10(min(vals)), "max": r10(max(vals)), "mean": r10(math.fsum(vals) / n),
            "median": r10(statistics.median(vals)), "stdev": r10(statistics.stdev(vals)) if n > 1 else None,
            "first": r10(vals[0]), "last": r10(vals[-1])}


def pct_change(first: float, last: float) -> dict:
    if first == 0:
        return {"value_pct": None, "reason": "first value is zero; percent change undefined"}
    return {"value_pct": r10((last - first) / abs(first) * 100.0), "reason": None}


def moving_average(vals: Sequence[float], window: int = MA_WINDOW) -> dict:
    if len(vals) < window:
        return {"window": window, "last": None, "n_points": 0, "reason": f"fewer than {window} observations"}
    ma = [math.fsum(vals[i:i + window]) / window for i in range(len(vals) - window + 1)]
    return {"window": window, "last": r10(ma[-1]), "first": r10(ma[0]), "n_points": len(ma), "reason": None}


def _ols(xs: Sequence[float], ys: Sequence[float]):
    n = len(xs)
    mx, my = math.fsum(xs) / n, math.fsum(ys) / n
    sxx = math.fsum((x - mx) ** 2 for x in xs)
    syy = math.fsum((y - my) ** 2 for y in ys)
    sxy = math.fsum((x - mx) * (y - my) for x, y in zip(xs, ys))
    if sxx == 0:
        return None
    slope = sxy / sxx
    icpt = my - slope * mx
    r2 = None if syy == 0 else (sxy * sxy) / (sxx * syy)
    return slope, icpt, r2


def trend(dates: Sequence[str], vals: Sequence[float]) -> dict:
    n = len(vals)
    base = {"method": "OLS on days since first observation; r2 is descriptive; no significance test", "n": n}
    if n < MIN_N:
        return {**base, "slope_per_day": None, "r2": None, "direction": "insufficient_data",
                "reason": f"fewer than {MIN_N} observations"}
    x0 = _days(dates[0])
    fit = _ols([_days(d) - x0 for d in dates], vals)
    if fit is None:
        return {**base, "slope_per_day": None, "r2": None, "direction": "insufficient_data", "reason": "all dates identical"}
    slope, _, r2 = fit
    direction = "flat_or_noisy" if (r2 is None or r2 < FLAT_R2 or slope == 0) else ("up" if slope > 0 else "down")
    return {**base, "slope_per_day": r10(slope), "r2": r10(r2), "direction": direction, "reason": None}


def missing(dates: Sequence[str]) -> dict:
    n = len(dates)
    if n < 3:
        return {"n": n, "expected_interval_days": None, "gaps": [], "estimated_missing_periods": None,
                "coverage_ratio": None, "reason": "fewer than 3 observations"}
    ds = [_days(d) for d in dates]
    gaps = [b - a for a, b in zip(ds, ds[1:])]
    med = statistics.median(gaps)
    out, tot = [], 0
    for (a, b), g in zip(zip(dates, dates[1:]), gaps):
        if med > 0 and g > 1.5 * med:
            k = int(round(g / med)) - 1
            tot += k
            if len(out) < 10:
                out.append({"after": a, "before": b, "estimated_missing_periods": k})
    return {"n": n, "expected_interval_days": r10(med), "gaps": out, "estimated_missing_periods": tot,
            "coverage_ratio": r10(n / (n + tot)), "reason": None}


def anomalies(dates: Sequence[str], vals: Sequence[float]) -> dict:
    meta = {"method": f"modified z-score of OLS residuals (|z| > {ANOMALY_Z}); a flag, not a conclusion"}
    n = len(vals)
    if n < MIN_N:
        return {**meta, "flags": [], "reason": f"fewer than {MIN_N} observations"}
    x0 = _days(dates[0])
    xs = [_days(d) - x0 for d in dates]
    fit = _ols(xs, vals)
    if fit is None:
        return {**meta, "flags": [], "reason": "all dates identical"}
    slope, icpt, _ = fit
    res = [y - (icpt + slope * x) for x, y in zip(xs, vals)]
    med = statistics.median(res)
    mad = statistics.median([abs(r - med) for r in res])
    if mad == 0:
        return {**meta, "flags": [], "reason": "zero median absolute deviation; anomalies not computed"}
    flags = []
    for d, v, r in zip(dates, vals, res):
        z = 0.6745 * (r - med) / mad
        if abs(z) > ANOMALY_Z:
            flags.append({"date": d, "value": r10(v), "modified_z": r10(z)})
    return {**meta, "flags": flags, "reason": None}


def pearson(a: Sequence[float], b: Sequence[float]) -> Optional[float]:
    n = len(a)
    if n < 2:
        return None
    ma, mb = math.fsum(a) / n, math.fsum(b) / n
    sa = math.fsum((x - ma) ** 2 for x in a)
    sb = math.fsum((y - mb) ** 2 for y in b)
    if sa == 0 or sb == 0:
        return None
    return math.fsum((x - ma) * (y - mb) for x, y in zip(a, b)) / math.sqrt(sa * sb)


def correlation(sa: dict, sb: dict) -> dict:
    """sa, sb: {date: value}. Aligned on exact common dates."""
    common = sorted(set(sa) & set(sb))
    meta = {"method": "Pearson r on common dates (levels) and on first differences; association only, not causation",
            "n_common": len(common)}
    if len(common) < MIN_N:
        return {**meta, "r_levels": None, "r_differences": None, "reason": f"fewer than {MIN_N} common dates"}
    a, b = [sa[d] for d in common], [sb[d] for d in common]
    da = [y - x for x, y in zip(a, a[1:])]
    db = [y - x for x, y in zip(b, b[1:])]
    return {**meta, "r_levels": r10(pearson(a, b)), "r_differences": r10(pearson(da, db)), "reason": None}


def analyze_series(dates: Sequence[str], vals: Sequence[float]) -> dict:
    return {"describe": describe(vals),
            "percent_change": pct_change(vals[0], vals[-1]) if vals else {"value_pct": None, "reason": "no data"},
            "moving_average": moving_average(vals), "trend": trend(dates, vals), "missing_data": missing(dates),
            "anomalies": anomalies(dates, vals)}
