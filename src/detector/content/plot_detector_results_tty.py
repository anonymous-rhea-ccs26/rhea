#!/usr/bin/env python3
"""
plot_detector_results_tty.py (TTY-friendly version)

Text-based visualization of detector output for SSH / no-GUI environments.

Reads results.csv from txt_fav.py or content_detector.py (new unified schema) and prints:

- Mode(s) present in the CSV (entropy / chi2 / txt_fav).
- For each class (encrypted / benign / not_evaluated):
    - count
    - min, max
    - mean, stddev
    - percentiles: 5%, 25%, 50%, 75%, 95%
    - ASCII histogram with configurable bin count

Assumed CSV schema (per row)
============================

    file_path,
    window_size,
    stride,
    tail_mode,
    file_size,
    num_windows,
    num_suspicious_windows,
    min_score,
    max_score,
    score_threshold,
    mode,
    verdict,
    note,
    error

Mode-specific score selection
=============================

For each file, we derive a single numeric 'score' used for statistics:

    mode = "entropy"  -> use max_score  (higher entropy => more suspicious)
    mode = "chi2"     -> use min_score  (lower chi2   => more suspicious)
    mode = "txt_fav"  -> use max_score  (more invalid bytes => more suspicious)

Usage
=====

    python plot_detector_results_tty.py --csv /path/to/results.csv

Optional arguments:

    --bins N      # number of bins in ASCII histogram (default: 20)
    --skip-ne     # skip printing stats for not_evaluated rows

This script uses only the Python standard library (no GUI, no numpy).
"""

import argparse
import csv
import math
from typing import Dict, List, Tuple, Optional


def read_csv(csv_path: str) -> List[Dict[str, str]]:
    rows = []
    with open(csv_path, "r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            rows.append(row)
    return rows


def select_score(row: Dict[str, str]) -> Optional[float]:
    """
    Select a single numeric score per file based on the mode.

    Returns:
        float score, or None if no usable value.
    """
    mode = row.get("mode", "").strip().lower()
    min_raw = row.get("min_score", "").strip()
    max_raw = row.get("max_score", "").strip()

    def to_float(s: str) -> Optional[float]:
        if s == "" or s.lower() == "nan":
            return None
        try:
            return float(s)
        except ValueError:
            return None

    min_val = to_float(min_raw)
    max_val = to_float(max_raw)

    if mode == "entropy":
        # Historically used max_entropy
        return max_val
    elif mode == "chi2":
        # Historically used min_chi2 (lower => more suspicious)
        return min_val
    elif mode == "txt_fav":
        # Use worst invalidness (max score per file)
        return max_val
    elif mode == "zip_fav":
        return max_val
    else:
        # Fallback: prefer max_score if present
        return max_val if max_val is not None else min_val


def extract_values(rows: List[Dict[str, str]]) -> Dict[str, List[float]]:
    """
    Extract numeric scores for each verdict class.

    Returns dict:
        {
          "encrypted": [v1, v2, ...],
          "benign": [...],
          "not_evaluated": [...]
        }
    """
    result = {
        "encrypted": [],
        "benign": [],
        "not_evaluated": [],
    }

    for r in rows:
        verdict = r.get("verdict", "").strip().lower()
        if verdict not in result:
            # skip "error" or any other verdicts
            continue

        val = select_score(r)
        if val is None:
            continue

        result[verdict].append(val)

    return result


def basic_stats(values: List[float]) -> Dict[str, float]:
    """
    Compute basic statistics: min, max, mean, stddev, and percentiles.
    Percentiles: 5%, 25%, 50%, 75%, 95%.

    Returns a dict with keys:
        count, min, max, mean, std, p5, p25, p50, p75, p95
    """
    n = len(values)
    if n == 0:
        return {
            "count": 0,
            "min": float("nan"),
            "max": float("nan"),
            "mean": float("nan"),
            "std": float("nan"),
            "p5": float("nan"),
            "p25": float("nan"),
            "p50": float("nan"),
            "p75": float("nan"),
            "p95": float("nan"),
        }

    vals = sorted(values)
    vmin = vals[0]
    vmax = vals[-1]
    mean = sum(vals) / n

    # stddev (population-style)
    var = 0.0
    for v in vals:
        diff = v - mean
        var += diff * diff
    var /= n
    std = math.sqrt(var)

    def percentile(p: float) -> float:
        """
        Simple percentile calculation (p from 0..100).
        Uses linear interpolation between closest ranks.
        """
        if n == 1:
            return vals[0]
        idx = p / 100.0 * (n - 1)
        lo = int(math.floor(idx))
        hi = int(math.ceil(idx))
        if lo == hi:
            return vals[lo]
        frac = idx - lo
        return vals[lo] * (1 - frac) + vals[hi] * frac

    return {
        "count": n,
        "min": vmin,
        "max": vmax,
        "mean": mean,
        "std": std,
        "p5": percentile(5),
        "p25": percentile(25),
        "p50": percentile(50),
        "p75": percentile(75),
        "p95": percentile(95),
    }


def make_histogram(
    values: List[float],
    bins: int,
) -> List[Tuple[float, float, int]]:
    """
    Compute a simple histogram.

    Returns:
        List of (bin_start, bin_end, count) of length 'bins'.

    If all vals are identical, we set a tiny range around that value.
    """
    if not values:
        return []

    vmin = min(values)
    vmax = max(values)
    if vmin == vmax:
        # Add a small epsilon range
        eps = 1e-9 if vmin == 0 else abs(vmin) * 1e-3
        vmin -= eps
        vmax += eps

    width = (vmax - vmin) / bins
    counts = [0] * bins

    for v in values:
        idx = int((v - vmin) / width)
        if idx == bins:  # edge case v == vmax
            idx = bins - 1
        counts[idx] += 1

    hist = []
    for i in range(bins):
        bin_start = vmin + i * width
        bin_end = bin_start + width
        hist.append((bin_start, bin_end, counts[i]))

    return hist


def print_stats(label: str, stats: Dict[str, float]) -> None:
    """
    Pretty-print the summary statistics for a given label (e.g. 'encrypted').
    """
    print(f"=== {label} ===")
    if stats["count"] == 0:
        print("  count: 0 (no data)")
        print()
        return

    def fmt(x: float) -> str:
        return f"{x:.4f}"

    print(f"  count: {stats['count']}")
    print(f"  min:   {fmt(stats['min'])}")
    print(f"  max:   {fmt(stats['max'])}")
    print(f"  mean:  {fmt(stats['mean'])}")
    print(f"  std:   {fmt(stats['std'])}")
    print(f"  p5:    {fmt(stats['p5'])}")
    print(f"  p25:   {fmt(stats['p25'])}")
    print(f"  p50:   {fmt(stats['p50'])}")
    print(f"  p75:   {fmt(stats['p75'])}")
    print(f"  p95:   {fmt(stats['p95'])}")
    print()


def print_ascii_hist(label: str, values: List[float], bins: int, max_width: int = 50) -> None:
    """
    Print a simple ASCII histogram for a given set of values.
    """
    print(f"--- ASCII histogram for {label} (bins={bins}) ---")
    if not values:
        print("  (no data)\n")
        return

    hist = make_histogram(values, bins)
    if not hist:
        print("  (no data)\n")
        return

    max_count = max(count for (_, _, count) in hist)
    if max_count == 0:
        print("  (all counts are zero)\n")
        return

    for (start, end, count) in hist:
        bar_len = int(round(count / max_count * max_width))
        bar = "#" * bar_len
        print(f"[{start:.4f}, {end:.4f}): {bar} ({count})")
    print()


def main():
    parser = argparse.ArgumentParser(
        description="TTY-friendly summary of detector results (entropy/chi2/txt_fav)."
    )
    parser.add_argument(
        "--csv",
        required=True,
        help="Path to results.csv produced by txt_fav.py or content_detector.py.",
    )
    parser.add_argument(
        "--bins",
        type=int,
        default=20,
        help="Number of bins for ASCII histogram (default: 20).",
    )
    parser.add_argument(
        "--skip-ne",
        action="store_true",
        help="Skip stats for not_evaluated entries.",
    )

    args = parser.parse_args()

    rows = read_csv(args.csv)

    modes = sorted({r.get("mode", "").strip().lower() for r in rows if r.get("mode")})
    if modes:
        print(f"[+] Modes present in CSV: {', '.join(modes)}")
    else:
        print("[+] Modes present in CSV: (none / legacy?)")

    vals_by_class = extract_values(rows)
    enc_vals = vals_by_class["encrypted"]
    ben_vals = vals_by_class["benign"]
    ne_vals = vals_by_class["not_evaluated"]

    print(f"[+] Counts (non-error rows with numeric values): "
          f"encrypted={len(enc_vals)}, benign={len(ben_vals)}, not_evaluated={len(ne_vals)}\n")

    # Print stats + histograms
    enc_stats = basic_stats(enc_vals)
    ben_stats = basic_stats(ben_vals)
    ne_stats = basic_stats(ne_vals)

    print_stats("encrypted", enc_stats)
    print_ascii_hist("encrypted", enc_vals, bins=args.bins)

    print_stats("benign", ben_stats)
    print_ascii_hist("benign", ben_vals, bins=args.bins)

    if not args.skip_ne:
        print_stats("not_evaluated", ne_stats)
        print_ascii_hist("not_evaluated", ne_vals, bins=args.bins)


if __name__ == "__main__":
    main()
