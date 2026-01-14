#!/usr/bin/env python3
"""
content_detector.py

Content-based detector for encrypted/compressed data in files using
either:

  - Shannon entropy (mode = "entropy"), or
  - Chi-square (χ²) uniformity heuristic (mode = "chi2").

This version uses a **unified CSV output schema** compatible with
txt_fav.py and plot_detector_results_tty.py.

----------------------------------------------------------------------
Unified CSV schema
----------------------------------------------------------------------

Each analyzed file produces exactly one row with columns:

    file_path,
    mode,
    window_size,
    stride,
    tail_mode,
    file_size,
    num_windows,
    num_suspicious_windows,
    ignored_tail_bytes,
    score_threshold,
    min_score,
    max_score,
    verdict,
    note,
    error

Where:

- file_path: absolute path to the file.

- mode:
    "entropy"  -> this script, entropy-based detection
    "chi2"     -> this script, chi-square-based detection

- window_size:
    Fixed window length in bytes (W).

- stride:
    Step between consecutive window start offsets (S).
    When stride == window_size, windows are non-overlapping (tumbling).
    When stride < window_size, windows overlap.

- tail_mode:
    "ignore"  -> trailing bytes after the last full window are ignored.
    "overlap" -> we add one extra window so that the last window ends at EOF.

- file_size:
    Size of the file in bytes (L).

- num_windows:
    Number of windows actually processed for this file.

- num_suspicious_windows:
    Number of windows classified as "ciphertext-like" under the chosen mode.

- ignored_tail_bytes:
    Number of bytes at the end of the file that are not included in any window
    when tail_mode == "ignore". For "overlap", this is always 0 because the
    last window is forced to end at EOF.

- score_threshold:
    The per-window threshold used to decide if a window is suspicious.

    * mode = "entropy": entropy_threshold (bits/byte)
                        suspicious if score >= score_threshold

    * mode = "chi2":    chi2_threshold (raw χ²)
                        suspicious if score <= score_threshold

- min_score, max_score:
    Aggregated range of per-window scores over the file.

    * mode = "entropy": min/max entropy observed across all windows
    * mode = "chi2":    min/max χ² observed across all windows

- verdict:
    "encrypted"       -> at least one suspicious window (num_suspicious_windows > 0)
    "benign"          -> num_suspicious_windows == 0 and num_windows > 0
    "not_evaluated"   -> no windows processed (e.g., file smaller than window)
    "error"           -> I/O or other runtime error during analysis

- note:
    Optional free-form string describing special cases, e.g.:
        "file_smaller_than_window"
        "no_full_windows_generated"
        "no_windows"

- error:
    If verdict == "error", contains the exception message; otherwise empty.

----------------------------------------------------------------------
Windowing semantics (shared with txt_fav.py)
----------------------------------------------------------------------

Let:
    L = file size in bytes
    W = window_size
    S = stride

Case 1: L < W
    - No windows are processed.
    - num_windows = 0, num_suspicious_windows = 0
    - ignored_tail_bytes = L
    - verdict = "not_evaluated"
    - note = "file_smaller_than_window"

Case 2: L >= W
    - Baseline windows start at:
          0, S, 2S, ... while (start + W) <= L

    tail_mode = "ignore":
        - We use only the baseline windows.
        - ignored_tail_bytes = L - (last_start + W)

    tail_mode = "overlap":
        - Baseline windows as above.
        - If L is not a multiple of W, add one extra window at:
              start = L - W
          so the final window ends exactly at EOF.
        - ignored_tail_bytes = 0 (by definition, all bytes are covered).

----------------------------------------------------------------------
Usage examples
----------------------------------------------------------------------

Entropy mode (default):

    python content_detector.py \
        --input-path /path/to/files \
        --output-path /tmp/rhea_runs

Chi2 mode:

    python content_detector.py \
        --input-path /path/to/files \
        --output-path /tmp/rhea_runs \
        --mode chi2 \
        --window-size 4096 \
        --stride 4096 \
        --tail-mode overlap \
        --chi2-threshold 300

The resulting run directory will look like:

    /tmp/rhea_runs/
        run_YYYYmmdd-HHMMSS_mode-entropy_W-4096_S-4096_tail-ignore/
            results.csv
            config.json

Where results.csv uses the unified schema above.
"""

import argparse
import csv
import json
import math
import os
import sys
from datetime import datetime
from typing import Dict, List, Optional


# --------------------------------------------------------------------
# Default parameter choices
# --------------------------------------------------------------------

# Default window size (bytes).
# 4 KiB is a natural choice: common FS block size and enough samples
# for stable entropy/chi2 statistics.
DEFAULT_WINDOW_SIZE = 4096

# Default stride (bytes).
# When stride == window_size, windows are non-overlapping (tumbling).
DEFAULT_STRIDE = DEFAULT_WINDOW_SIZE

# Default entropy threshold (bits/byte).
# A value around 7.5 is a common heuristic for "very high entropy".
DEFAULT_ENTROPY_THRESHOLD = 7.5

# Default chi-square threshold (raw Pearson χ²).
DEFAULT_CHI2_THRESHOLD = 10000.0

# Precision for writing floating-point values into CSV.
FLOAT_PRECISION = 4


# --------------------------------------------------------------------
# Scoring functions (per-window)
# --------------------------------------------------------------------

def compute_entropy(window: bytes) -> float:
    """
    Compute Shannon entropy in bits/byte for a given window.

    Alphabet: all 256 possible byte values (0..255)
    Log base: 2

    H = - sum_{i : count[i] > 0} p[i] * log2(p[i])

    Where:
        p[i] = count[i] / N
        N    = len(window)

    Returns:
        Entropy H in [0, 8]. Higher values => more uniform distribution.
    """
    if not window:
        return 0.0

    # Count frequency of each byte value.
    counts = [0] * 256
    for b in window:
        counts[b] += 1

    n = len(window)
    entropy = 0.0
    for c in counts:
        if c == 0:
            # Skip symbols that do not appear in the window.
            continue
        p = c / n
        entropy -= p * math.log2(p)

    return entropy


def compute_chi2(window: bytes) -> float:
    """
    Compute raw Pearson chi-square (χ²) statistic for a byte window under
    a uniform(0..255) assumption.

    We use the algebraic form commonly used in SAWA / ERW-Radar:

        Let:
            N      = len(window)
            O[i]   = count of byte value i in the window
            sumsq  = sum_i O[i]^2

        Chi² ≈ 256 * (sumsq / N) - N

    This is equivalent to:

        Chi² = sum_{i=0}^{255} (O[i] - E)^2 / E, where E = N / 256

    Interpretation:

        - Smaller χ² => closer to uniform => more likely ciphertext/compressed
        - Larger χ²  => more skewed distribution => more likely structured/plaintext

    Returns:
        chi2 (float): non-negative χ² value.
    """
    n = len(window)
    if n == 0:
        return 0.0

    counts = [0] * 256
    for b in window:
        counts[b] += 1

    # sumsq = sum(O[i]^2)
    sumsq = 0
    for c in counts:
        sumsq += c * c

    chi2 = 256.0 * (sumsq / n) - n
    return chi2


# --------------------------------------------------------------------
# File discovery and run directory helpers
# --------------------------------------------------------------------

def discover_files(input_path: str) -> List[str]:
    """
    Given an input path, return a list of file paths to analyze.

    Behavior:
      - If input_path is a file:
            return [abs(input_path)]
      - If input_path is a directory:
            return all regular files directly under that directory
            (non-recursive).
      - Otherwise:
            raise ValueError.
    """
    if os.path.isfile(input_path):
        return [os.path.abspath(input_path)]

    if os.path.isdir(input_path):
        files: List[str] = []
        for entry in os.scandir(input_path):
            if entry.is_file():
                files.append(os.path.abspath(entry.path))
        return files

    raise ValueError(f"input-path is neither a file nor a directory: {input_path}")


def create_run_directory(
    output_root: str,
    mode: str,
    window_size: int,
    stride: int,
    tail_mode: str,
) -> str:
    """
    Create a unique run directory inside output_root based on:
        - current timestamp
        - detection mode
        - window size
        - stride
        - tail_mode

    Example directory name:

        run_20251203-101530_mode-entropy_W-4096_S-4096_tail-ignore

    If a directory with the same name exists, a numeric suffix (_1, _2, ...)
    is appended to ensure uniqueness.

    Returns:
        Absolute path to the created run directory.
    """
    os.makedirs(output_root, exist_ok=True)

    timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    base_name = f"run_{timestamp}_mode-{mode}_W-{window_size}_S-{stride}_tail-{tail_mode}"
    run_dir = os.path.join(output_root, base_name)

    # Ensure uniqueness if somehow a directory with same name already exists.
    suff = 1
    unique_run_dir = run_dir
    while os.path.exists(unique_run_dir):
        unique_run_dir = f"{run_dir}_{suff}"
        suff += 1

    os.makedirs(unique_run_dir, exist_ok=False)
    return unique_run_dir


# --------------------------------------------------------------------
# Core per-file analysis
# --------------------------------------------------------------------

def analyze_file(
    file_path: str,
    mode: str,
    window_size: int,
    stride: int,
    tail_mode: str,
    entropy_threshold: float,
    chi2_threshold: float,
) -> Dict[str, Optional[str]]:
    """
    Analyze a single file and return a dict of results matching
    the unified CSV schema.

    Steps:
      1. Read file contents in binary.
      2. If file size < window_size:
            - mark as not_evaluated.
      3. Otherwise, compute window start offsets according to stride and
         tail_mode.
      4. For each window:
            - compute score (entropy or chi2),
            - update min_score and max_score,
            - increment num_suspicious_windows if score crosses threshold.
      5. Derive file-level verdict from num_windows and num_suspicious_windows.

    Returns:
        dict ready to be written as a CSV row.
    """
    # Initialize result with default values and metadata.
    result: Dict[str, Optional[str]] = {
        "file_path": file_path,
        "mode": mode,
        "window_size": window_size,
        "stride": stride,
        "tail_mode": tail_mode,
        "file_size": None,
        "num_windows": 0,
        "num_suspicious_windows": 0,
        "ignored_tail_bytes": 0,
        "score_threshold": "",
        "min_score": "",
        "max_score": "",
        "verdict": "error",   # pessimistic default; changed below
        "note": "",
        "error": "",
    }

    # Store the score threshold according to the selected mode.
    if mode == "entropy":
        result["score_threshold"] = f"{entropy_threshold:.{FLOAT_PRECISION}f}"
    elif mode == "chi2":
        result["score_threshold"] = f"{chi2_threshold:.{FLOAT_PRECISION}f}"
    else:
        # This shouldn't happen because CLI restricts allowed modes,
        # but we keep a defensive check.
        result["error"] = f"unknown_mode:{mode}"
        result["verdict"] = "error"
        return result

    # --- Step 1: Read file contents (binary) --------------------------------
    try:
        file_size = os.path.getsize(file_path)
        result["file_size"] = file_size

        with open(file_path, "rb") as f:
            data = f.read()
    except Exception as e:  # noqa: BLE001
        # Record the error and bail out.
        result["error"] = str(e)
        result["verdict"] = "error"
        return result

    n_bytes = len(data)
    if file_size is None:
        # Fallback: if os.path.getsize failed, use len(data).
        file_size = n_bytes
        result["file_size"] = n_bytes

    # --- Step 2: Handle small files (L < W) ---------------------------------
    if n_bytes < window_size:
        # No windows can be formed.
        result["num_windows"] = 0
        result["num_suspicious_windows"] = 0
        result["ignored_tail_bytes"] = n_bytes
        result["verdict"] = "not_evaluated"
        result["note"] = "file_smaller_than_window"
        return result

    # --- Step 3: Compute window start positions -----------------------------
    window_starts: List[int] = []
    pos = 0
    while pos + window_size <= n_bytes:
        window_starts.append(pos)
        pos += stride

    if not window_starts:
        # Defensive: This should not occur if n_bytes >= window_size and stride > 0.
        result["num_windows"] = 0
        result["num_suspicious_windows"] = 0
        result["ignored_tail_bytes"] = n_bytes
        result["verdict"] = "not_evaluated"
        result["note"] = "no_full_windows_generated"
        return result

    # Tail handling depends on tail_mode.
    if tail_mode == "ignore":
        # Ignored tail is whatever is after the last full window.
        last_start = window_starts[-1]
        processed_bytes_end = last_start + window_size
        ignored_tail_bytes = max(0, n_bytes - processed_bytes_end)
    elif tail_mode == "overlap":
        # Ensure the last window ends at EOF.
        desired_last_start = n_bytes - window_size
        last_start = window_starts[-1]
        if desired_last_start > last_start:
            # Add one extra overlapping window at the end.
            window_starts.append(desired_last_start)
        ignored_tail_bytes = 0
    else:
        # Should not happen due to argparse choices.
        raise ValueError(f"Unknown tail_mode: {tail_mode}")

    num_windows = len(window_starts)
    num_suspicious = 0

    # Track min_score and max_score across all windows in this file.
    min_score_val: Optional[float] = None
    max_score_val: Optional[float] = None

    # --- Step 4: Per-window scoring and suspicious flag ---------------------
    for start in window_starts:
        # Each window is exactly window_size bytes by construction
        # (because we only used starts such that start + window_size <= n_bytes).
        w = data[start : start + window_size]

        # Compute score according to the mode.
        if mode == "entropy":
            score = compute_entropy(w)
            # In entropy mode, high scores are more suspicious.
            suspicious = (score >= entropy_threshold)
        elif mode == "chi2":
            score = compute_chi2(w)
            # In chi2 mode, low scores are more suspicious (closer to uniform).
            suspicious = (score <= chi2_threshold)
        else:
            # Defensive: mode already validated above.
            result["error"] = f"unknown_mode:{mode}"
            result["verdict"] = "error"
            return result

        # Update min_score and max_score over all windows.
        if min_score_val is None or score < min_score_val:
            min_score_val = score
        if max_score_val is None or score > max_score_val:
            max_score_val = score

        # Count suspicious windows.
        if suspicious:
            num_suspicious += 1

    # Store aggregated per-file statistics in the result dict.
    result["num_windows"] = num_windows
    result["num_suspicious_windows"] = num_suspicious
    result["ignored_tail_bytes"] = ignored_tail_bytes

    if min_score_val is not None:
        result["min_score"] = f"{min_score_val:.{FLOAT_PRECISION}f}"
    if max_score_val is not None:
        result["max_score"] = f"{max_score_val:.{FLOAT_PRECISION}f}"

    # --- Step 5: File-level verdict (any-window rule) -----------------------
    if num_windows == 0:
        # Should not happen here because n_bytes >= window_size and we had
        # at least one window, but keep the case for completeness.
        result["verdict"] = "not_evaluated"
        result["note"] = "no_windows"
    else:
        if num_suspicious > 0:
            result["verdict"] = "encrypted"
        else:
            result["verdict"] = "benign"

    return result


# --------------------------------------------------------------------
# Config + CLI wiring
# --------------------------------------------------------------------

def write_config_json(run_dir: str, args: argparse.Namespace) -> None:
    """
    Serialize the run configuration into config.json within the
    given run directory.

    This is purely for reproducibility / auditability; the detector
    itself does not read this file.
    """
    config_path = os.path.join(run_dir, "config.json")
    config = {
        "input_path": os.path.abspath(args.input_path),
        "mode": args.mode,
        "window_size": args.window_size,
        "stride": args.stride,
        "tail_mode": args.tail_mode,
        "entropy_threshold": args.entropy_threshold,
        "chi2_threshold": args.chi2_threshold,
        "timestamp": datetime.now().isoformat(),
    }
    with open(config_path, "w", encoding="utf-8") as f:
        json.dump(config, f, indent=2)


def parse_args(argv: Optional[List[str]] = None) -> argparse.Namespace:
    """
    Parse command-line arguments and perform basic validation.

    Important: the CLI here is still backward-compatible with the
    previous content_detector.py in terms of flags, even though the
    CSV schema is now unified.
    """
    parser = argparse.ArgumentParser(
        description=(
            "Content-based detector for encrypted/compressed data using "
            "either Shannon entropy or chi-square uniformity heuristic, "
            "with a unified output schema."
        )
    )

    parser.add_argument(
        "--input-path",
        required=True,
        help="Path to a file or a flat directory containing files to analyze.",
    )

    parser.add_argument(
        "--output-path",
        required=True,
        help="Root directory where a timestamped run directory will be created.",
    )

    parser.add_argument(
        "--mode",
        choices=["entropy", "chi2"],
        default="entropy",
        help=(
            "Detection mode: "
            "'entropy' = Shannon entropy (high score => suspicious), "
            "'chi2' = chi-square uniformity (low score => suspicious). "
            "Default: entropy."
        ),
    )

    parser.add_argument(
        "--window-size",
        type=int,
        default=DEFAULT_WINDOW_SIZE,
        help=f"Window size in bytes (W). Default: {DEFAULT_WINDOW_SIZE}.",
    )

    parser.add_argument(
        "--stride",
        type=int,
        default=None,
        help=(
            "Stride in bytes between windows (S). "
            "Default: equal to --window-size (tumbling windows)."
        ),
    )

    parser.add_argument(
        "--tail-mode",
        choices=["ignore", "overlap"],
        default="ignore",
        help=(
            "How to handle bytes after the last full window: "
            "'ignore' = ignore trailing bytes, "
            "'overlap' = add an extra window so the last window ends at EOF. "
            "Default: ignore."
        ),
    )

    parser.add_argument(
        "--entropy-threshold",
        type=float,
        default=DEFAULT_ENTROPY_THRESHOLD,
        help=(
            "Entropy threshold (bits/byte) for entropy mode. "
            "Windows with H >= threshold are treated as ciphertext-like. "
            f"Default: {DEFAULT_ENTROPY_THRESHOLD}."
        ),
    )

    parser.add_argument(
        "--chi2-threshold",
        type=float,
        default=DEFAULT_CHI2_THRESHOLD,
        help=(
            "Chi-square threshold (raw χ²) for chi2 mode. "
            "Windows with χ² <= threshold are treated as ciphertext-like. "
            f"Default: {DEFAULT_CHI2_THRESHOLD}."
        ),
    )

    args = parser.parse_args(argv)

    # If stride is not explicitly set, use window_size (tumbling).
    if args.stride is None:
        args.stride = args.window_size

    if args.window_size <= 0:
        parser.error("--window-size must be a positive integer.")
    if args.stride <= 0:
        parser.error("--stride must be a positive integer.")

    return args


def main(argv: Optional[List[str]] = None) -> None:
    """
    Entry point.

    - Parse arguments.
    - Discover files under input_path.
    - Create a timestamped run directory.
    - Write config.json.
    - Analyze each file and write one row per file to results.csv.
    """
    args = parse_args(argv)

    # Discover files to analyze.
    try:
        files = discover_files(args.input_path)
    except Exception as e:  # noqa: BLE001
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)

    if not files:
        print("No files found to analyze.", file=sys.stderr)
        sys.exit(1)

    # Create run directory.
    run_dir = create_run_directory(
        output_root=args.output_path,
        mode=args.mode,
        window_size=args.window_size,
        stride=args.stride,
        tail_mode=args.tail_mode,
    )

    # Dump configuration snapshot.
    write_config_json(run_dir, args)

    # Prepare CSV writer.
    csv_path = os.path.join(run_dir, "results.csv")
    fieldnames = [
        "file_path",
        "mode",
        "window_size",
        "stride",
        "tail_mode",
        "file_size",
        "num_windows",
        "num_suspicious_windows",
        "ignored_tail_bytes",
        "score_threshold",
        "min_score",
        "max_score",
        "verdict",
        "note",
        "error",
    ]

    with open(csv_path, "w", newline="", encoding="utf-8") as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()

        for path in files:
            res = analyze_file(
                file_path=path,
                mode=args.mode,
                window_size=args.window_size,
                stride=args.stride,
                tail_mode=args.tail_mode,
                entropy_threshold=args.entropy_threshold,
                chi2_threshold=args.chi2_threshold,
            )
            writer.writerow(res)

    print(f"Analysis complete. Results written to: {csv_path}")


if __name__ == "__main__":
    main()
