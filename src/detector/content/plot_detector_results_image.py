#!/usr/bin/env python3
"""
plot_detector_results.py

Helper script for visualizing distributions from the CSV output of
content_detector.py.

It can automatically detect the detection mode (entropy / chi2)
from CSV content and plots histograms of:

- max_entropy            (entropy mode), OR
- max_chi2_deviation     (chi2 mode)

Use this to tune threshold values for your detector.

Usage
=====

# Basic
python plot_detector_results.py --csv /path/to/results.csv

# Customize bins
python plot_detector_results.py --csv results.csv --bins 200

# Use log-scale y-axis (helpful for χ² mode)
python plot_detector_results.py --csv results.csv --logy

Output
======
Saves a PNG file next to the CSV with a name like:
    results_entropy_hist.png
or:
    results_chi2_hist.png

Requirements
============
- matplotlib
- numpy
"""

import argparse
import csv
import os
import sys
from typing import List, Dict

import numpy as np
import matplotlib.pyplot as plt


def read_csv(csv_path: str) -> List[Dict[str, str]]:
    rows = []
    with open(csv_path, "r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            rows.append(row)
    return rows


def detect_mode(rows: List[Dict[str, str]]) -> str:
    """
    Detect whether the CSV corresponds to entropy or chi2 mode.

    We inspect the columns:
    - If max_entropy has any non-empty value -> entropy
    - Else if max_chi2_deviation has any non-empty value -> chi2
    """
    has_entropy = any(r.get("max_entropy", "").strip() not in ("", "NaN") for r in rows)
    has_chi2 = any(r.get("max_chi2_deviation", "").strip() not in ("", "NaN") for r in rows)

    if has_entropy and not has_chi2:
        return "entropy"
    if has_chi2 and not has_entropy:
        return "chi2"
    if has_entropy and has_chi2:
        print("Warning: CSV contains both entropy and chi2 values. Using entropy.", file=sys.stderr)
        return "entropy"

    raise ValueError("CSV does not contain either entropy or chi2 fields with values.")


def extract_values(rows: List[Dict[str, str]], mode: str):
    """
    Extract numeric values for plotting:
    - max_entropy (if mode='entropy')
    - max_chi2_deviation (if mode='chi2')

    Returns:
        dict:
          encrypted_vals: list of floats
          benign_vals:    list of floats
          not_eval_vals:  list of floats
    """
    encrypted_vals = []
    benign_vals = []
    not_eval_vals = []

    for r in rows:
        verdict = r.get("verdict", "").strip().lower()

        if mode == "entropy":
            field = "max_entropy"
        else:
            field = "max_chi2_deviation"

        raw = r.get(field, "").strip()
        if raw == "" or raw.lower() == "nan":
            continue

        try:
            val = float(raw)
        except ValueError:
            continue

        if verdict == "encrypted":
            encrypted_vals.append(val)
        elif verdict == "benign":
            benign_vals.append(val)
        elif verdict == "not_evaluated":
            not_eval_vals.append(val)
        # ignore 'error' for distribution plotting

    return {
        "encrypted": encrypted_vals,
        "benign": benign_vals,
        "not_evaluated": not_eval_vals,
    }


def plot_histograms(values, mode: str, bins: int, logy: bool, csv_path: str):
    """
    Plot the histogram using matplotlib and save a PNG next to the CSV.
    """
    out_dir = os.path.dirname(os.path.abspath(csv_path))
    basename = os.path.splitext(os.path.basename(csv_path))[0]
    out_file = os.path.join(out_dir, f"{basename}_{mode}_hist.png")

    plt.figure(figsize=(10, 6))

    # Extract lists
    enc = values["encrypted"]
    ben = values["benign"]
    nev = values["not_evaluated"]

    # Plot encrypted
    if len(enc) > 0:
        plt.hist(enc, bins=bins, alpha=0.6, label=f"encrypted (n={len(enc)})")

    # Plot benign
    if len(ben) > 0:
        plt.hist(ben, bins=bins, alpha=0.6, label=f"benign (n={len(ben)})")

    # Optional: not evaluated
    if len(nev) > 0:
        plt.hist(nev, bins=bins, alpha=0.6, label=f"not_evaluated (n={len(nev)})")

    # Title and labels
    if mode == "entropy":
        plt.xlabel("max_entropy (bits/byte)")
        plt.title("Distribution of max_entropy across files")
    else:
        plt.xlabel("max_chi2_deviation = |χ² - 255|")
        plt.title("Distribution of |χ² - df| across files")

    plt.ylabel("count")
    plt.legend()
    if logy:
        plt.yscale("log")

    plt.grid(True, linestyle="--", alpha=0.4)

    plt.tight_layout()
    plt.savefig(out_file, dpi=200)
    plt.close()

    print(f"[+] Saved histogram to: {out_file}")


def main():
    parser = argparse.ArgumentParser(description="Plot entropy/chi2 distributions from detector results CSV.")
    parser.add_argument("--csv", required=True, help="Path to results.csv produced by content_detector.py.")
    parser.add_argument("--bins", type=int, default=100, help="Number of histogram bins. Default: 100.")
    parser.add_argument("--logy", action="store_true", help="Use log scale for y-axis (useful for chi2).")

    args = parser.parse_args()

    rows = read_csv(args.csv)
    mode = detect_mode(rows)
    print(f"[+] Detected mode: {mode}")

    values = extract_values(rows, mode)
    print(f"[+] Extracted: encrypted={len(values['encrypted'])}, benign={len(values['benign'])}, not_evaluated={len(values['not_evaluated'])}")

    plot_histograms(values, mode, args.bins, args.logy, args.csv)


if __name__ == "__main__":
    main()
