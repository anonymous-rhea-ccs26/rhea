#!/usr/bin/env python3
"""
txt_fav.py

Simple format-aware validator for text files using multi-encoding validation
(UTF-8 / UTF-16LE / UTF-16BE / CP1252) on fixed windows, inspired by the
Rhea text handler and content_detector.py.

Unified schema with content_detector.py
=======================================

Each CSV row has:

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

- mode: "txt_fav" for this tool.
- score_threshold: per-run threshold used to classify windows as suspicious.
- score (per window, aggregated as min_score / max_score):
    * txt_fav: 0 for any window that decodes cleanly as one of the
      supported encodings (UTF-8 / UTF-16LE / UTF-16BE / CP1252) and looks
      text-like; otherwise, score = utf8_error_count(window_bytes).
- A window is suspicious for txt_fav iff score > score_threshold.

File-level verdict:
    - "encrypted"   if any window is suspicious.
    - "benign"      if all windows are non-suspicious.
    - "not_evaluated" if file is empty, smaller than window, or no windows.
    - "error"       on read/stat failure.

Windowing semantics
===================

Let:
    L = file size in bytes
    W = window size
    S = stride

Case 1: L == 0
    - No windows, file_size = 0.
    - verdict = "not_evaluated", note = "empty_file".

Case 2: 0 < L < W
    - For apples-to-apples comparison with content_detector.py,
      we IGNORE such files.
    - verdict = "not_evaluated", note = "file_smaller_than_window".

Case 3: L == W
    - Single window covering entire file [0, W).

Case 4: L > W
    - Baseline windows: starts at 0, S, 2S, ... while (start + W) <= L.

    tail-mode = "ignore":
        - Only baseline windows are used.
        - Tail bytes after the last full window are ignored.

    tail-mode = "overlap":
        - Baseline windows as above.
        - Additionally, if L is not a multiple of W, add a final window
          starting at (L - W), so that the last window ends exactly at EOF.
        - This final window may overlap the previous one.
"""

# ------------------------------------------------------------
# How to run txt_fav.py (examples)
# ------------------------------------------------------------
#
# 1) Analyze a single text file:
#   python3 txt_fav.py \
#     --input-path /path/to/sample.txt \
#     --output-path /path/to/out/
#
# 2) Analyze all files in a *flat* directory (no recursion):
#   python3 txt_fav.py \
#     --input-path /path/to/text_dir/ \
#     --output-path /path/to/out/
#
# Output:
#   A new run directory will be created under --output-path, e.g.
#     out/run_20251226-235959_mode-txt_fav_W-4096_S-4096_tail-ignore/
#   It will contain:
#     - config.json    (the exact run configuration)
#     - results.csv    (one row per analyzed file)
#
# txt_fav v1 semantics (important):
#   - Fixed-size window scanning (default: 4096 bytes, tumbling windows)
#   - Each window is validated against multiple encodings:
#       UTF-8 (strict)
#       UTF-16LE / UTF-16BE (heuristic detection)
#       CP1252 (legacy Windows text)
#   - A window is considered *benign* if it decodes cleanly
#     under ANY supported encoding and looks text-like.
#   - A window is *suspicious* only if ALL encodings fail.
#
# Scoring model:
#   - Window score: 0 (benign) or >0 (utf8 error count)
#   - score_threshold default: 0
#   - File verdict:
#       benign        : all windows score == 0
#       encrypted     : any window score > 0
#       not_evaluated : empty file or file smaller than window
#
# Common knobs:
#   Change window size / stride:
#     python3 txt_fav.py \
#       --input-path ... \
#       --output-path ... \
#       --window-size 8192 \
#       --stride 4096
#
#   Enable overlapping tail window (to force EOF coverage):
#     python3 txt_fav.py \
#       --input-path ... \
#       --output-path ... \
#       --tail-mode overlap
#
# Notes:
#   - Files smaller than --window-size are ignored
#     (verdict=not_evaluated) for apples-to-apples comparison
#     with other Rhea detectors.
#   - txt_fav performs *content-only, format-aware* validation:
#     it does NOT rely on entropy thresholds or I/O patterns.
# ------------------------------------------------------------


import argparse
import csv
import codecs
import json
import os
import sys
from datetime import datetime
from typing import Dict, List, Optional, Tuple


# ----------------------------
# Default parameter choices
# ----------------------------

DEFAULT_WINDOW_SIZE = 4096
DEFAULT_STRIDE = DEFAULT_WINDOW_SIZE

# Maximum allowed "score" per window before it is considered suspicious.
# For txt_fav, score is utf8_error_count for windows that fail all encodings;
# 0 for windows that are valid in any encoding.
DEFAULT_SCORE_THRESHOLD = 0

FLOAT_PRECISION = 4  # reserved for any future float output


# ----------------------------
# UTF-8 validation primitives
# ----------------------------

def utf8_error_scan(b: bytes) -> int:
    """
    Strict UTF-8 validation on the given bytes.

    Returns:
        error_count (int)

    Similar spirit to your Rhea text handler's _utf8_error_scan, but we only
    return the count for simplicity.
    """
    if not b:
        return 0
    dec = codecs.getincrementaldecoder("utf-8")("strict")
    errors, offset = 0, 0
    mv = memoryview(b)
    n = len(b)
    while offset < n:
        try:
            dec.decode(mv[offset:], final=True)
            break
        except UnicodeDecodeError as ex:
            errors += 1
            pos = offset + int(getattr(ex, "start", 0) or 0)
            offset = max(pos + 1, offset + 1)
            dec = codecs.getincrementaldecoder("utf-8")("strict")
    return errors


# ----------------------------
# Other encodings / heuristics
# ----------------------------

def printable_ratio_unicode(s: str) -> float:
    """
    Heuristic: how 'text-like' a decoded Unicode string is.

    We count letters, digits, whitespace, and common punctuation as 'good'.
    """
    if not s:
        return 0.0
    good = 0
    for ch in s:
        if ch.isalnum() or ch.isspace() or ch in ".,;:!?-_/\\'\"()[]{}<>@#$%^&*+=|":
            good += 1
    return good / len(s)


def looks_like_utf16(b: bytes) -> str:
    """
    Return 'utf-16-le', 'utf-16-be', or '' if unlikely.

    Heuristics:
      - Check BOM.
      - Or check for lots of 0x00 bytes in even/odd positions on a prefix.
    """
    if len(b) < 4:
        return ""

    # BOM checks
    if b.startswith(b"\xff\xfe"):
        return "utf-16-le"
    if b.startswith(b"\xfe\xff"):
        return "utf-16-be"

    # No BOM: heuristic scan.
    prefix = b[:512]
    even_zeros = 0
    odd_zeros = 0
    even_total = 0
    odd_total = 0

    for i, ch in enumerate(prefix):
        if i % 2 == 0:
            even_total += 1
            if ch == 0:
                even_zeros += 1
        else:
            odd_total += 1
            if ch == 0:
                odd_zeros += 1

    if even_total == 0 or odd_total == 0:
        return ""

    even_ratio = even_zeros / even_total
    odd_ratio = odd_zeros / odd_total

    # Typical UTF-16LE English: lots of zeros in odd positions.
    # Typical UTF-16BE English: lots of zeros in even positions.
    THRESH = 0.3
    if odd_ratio > THRESH and odd_ratio > even_ratio * 1.5:
        return "utf-16-le"
    if even_ratio > THRESH and even_ratio > odd_ratio * 1.5:
        return "utf-16-be"

    return ""


def validate_window(
    data: bytes,
) -> Tuple[bool, int]:
    """
    Decide if a window looks like benign text under supported encodings.

    Returns:
        (is_plain, score)

    Semantics for txt_fav:
      - If ANY supported encoding decodes strictly and looks text-like:
            is_plain = True,  score = 0
      - If ALL supported encodings fail:
            is_plain = False, score = utf8_error_count(window_bytes)

    This satisfies:
      "increase the error count only when all supported encoding schemes are failed"
    at the window level.
    """
    if not data:
        # Empty window: treat as non-plain with score 0 (still safe because
        # 0 <= score_threshold in typical configs).
        return False, 0

    # 1) Try UTF-8 strict, text-likeness
    try:
        txt = data.decode("utf-8", errors="strict")
        if printable_ratio_unicode(txt) > 0.80:
            return True, 0
    except UnicodeDecodeError:
        pass

    # 2) Try UTF-16 if it looks like UTF-16
    enc16 = looks_like_utf16(data)
    if enc16:
        try:
            txt16 = data.decode(enc16, errors="strict")
            if printable_ratio_unicode(txt16) > 0.80:
                return True, 0
        except UnicodeDecodeError:
            pass

    # 3) CP1252 fallback (Windows legacy .txt)
    try:
        txt1252 = data.decode("cp1252", errors="strict")
        if printable_ratio_unicode(txt1252) > 0.85:
            return True, 0
    except UnicodeDecodeError:
        pass

    # 4) If none of the encodings make it look text-like:
    score = utf8_error_scan(data)
    return False, score


# ----------------------------
# File discovery and run dir
# ----------------------------

def discover_files(input_path: str) -> List[str]:
    """
    Given an input path, return a list of file paths to analyze.

    - If input_path is a file: [input_path]
    - If input_path is a directory: all regular files directly under it.
    """
    if os.path.isfile(input_path):
        return [os.path.abspath(input_path)]

    if os.path.isdir(input_path):
        files = []
        for entry in os.scandir(input_path):
            if entry.is_file():
                files.append(os.path.abspath(entry.path))
        return files

    raise ValueError(f"input-path is neither a file nor a directory: {input_path}")


def create_run_directory(
    output_root: str,
    window_size: int,
    stride: int,
    tail_mode: str,
    score_threshold: int,
) -> str:
    """
    Create a unique run directory inside output_root based on timestamp
    and key parameters.

    Example:
        run_20251203-101530_mode-txt_fav_W-4096_S-4096_tail-ignore
    """
    os.makedirs(output_root, exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    base_name = (
        f"run_{timestamp}_mode-txt_fav_W-{window_size}_S-{stride}_"
        f"tail-{tail_mode}"
    )
    run_dir = os.path.join(output_root, base_name)

    suff = 1
    unique_run_dir = run_dir
    while os.path.exists(unique_run_dir):
        unique_run_dir = f"{run_dir}_{suff}"
        suff += 1

    os.makedirs(unique_run_dir, exist_ok=False)
    return unique_run_dir


def write_config_json(run_dir: str, args: argparse.Namespace) -> None:
    """
    Dump run configuration to config.json in the run directory.
    """
    config_path = os.path.join(run_dir, "config.json")
    config = {
        "input_path": os.path.abspath(args.input_path),
        "window_size": args.window_size,
        "stride": args.stride,
        "tail_mode": args.tail_mode,
        "score_threshold": args.score_threshold,
        "mode": "txt_fav",
        "timestamp": datetime.now().isoformat(),
    }
    with open(config_path, "w", encoding="utf-8") as f:
        json.dump(config, f, indent=2)


# ----------------------------
# Core analysis
# ----------------------------

def analyze_file(
    file_path: str,
    window_size: int,
    stride: int,
    tail_mode: str,
    score_threshold: int,
) -> Dict[str, Optional[str]]:
    """
    Analyze a single file and return a dict suitable for writing as a CSV row.

    We:
      - read the entire file in binary,
      - generate windows according to (window_size, stride, tail_mode),
      - for each window perform multi-encoding validation,
      - classify file as benign/encrypted/not_evaluated/error.
    """
    result: Dict[str, Optional[str]] = {
        "file_path": file_path,
        "window_size": window_size,
        "stride": stride,
        "tail_mode": tail_mode,
        "file_size": None,
        "num_windows": 0,
        "num_suspicious_windows": 0,
        "min_score": "",
        "max_score": "",
        "score_threshold": score_threshold,
        "mode": "txt_fav",
        "verdict": "error",
        "note": "",
        "error": "",
    }

    # Read file
    try:
        file_size = os.path.getsize(file_path)
        result["file_size"] = file_size
        with open(file_path, "rb") as f:
            data = f.read()
    except Exception as e:  # noqa: BLE001
        result["error"] = str(e)
        result["verdict"] = "error"
        return result

    n_bytes = len(data)
    if file_size is None:
        file_size = n_bytes
        result["file_size"] = n_bytes

    # Empty file
    if n_bytes == 0:
        result["num_windows"] = 0
        result["num_suspicious_windows"] = 0
        result["verdict"] = "not_evaluated"
        result["note"] = "empty_file"
        return result

    # For apple-to-apple with content_detector.py: ignore small files
    if n_bytes < window_size:
        result["num_windows"] = 0
        result["num_suspicious_windows"] = 0
        result["verdict"] = "not_evaluated"
        result["note"] = "file_smaller_than_window"
        return result

    # Window start positions
    window_starts: List[int] = []
    tail_bytes = 0

    if n_bytes == window_size:
        # Single full-window file
        window_starts.append(0)
        tail_bytes = 0
    else:
        # Baseline windows
        pos = 0
        while pos + window_size <= n_bytes:
            window_starts.append(pos)
            pos += stride

        if not window_starts:
            # Defensive; shouldn't happen with proper window_size/stride.
            result["num_windows"] = 0
            result["num_suspicious_windows"] = 0
            result["verdict"] = "not_evaluated"
            result["note"] = "no_full_windows_generated"
            return result

        if tail_mode == "ignore":
            last_start = window_starts[-1]
            processed_bytes_end = last_start + window_size
            tail_bytes = max(0, n_bytes - processed_bytes_end)
        elif tail_mode == "overlap":
            desired_last_start = n_bytes - window_size
            last_start = window_starts[-1]
            if desired_last_start > last_start:
                window_starts.append(desired_last_start)
            tail_bytes = 0
        else:
            raise ValueError(f"Unknown tail_mode: {tail_mode}")

    num_windows = len(window_starts)
    result["num_windows"] = num_windows

    if num_windows == 0:
        result["verdict"] = "not_evaluated"
        result["note"] = "no_windows"
        return result

    num_suspicious = 0
    min_score: Optional[int] = None
    max_score: Optional[int] = None

    for start in window_starts:
        end = min(start + window_size, n_bytes)
        w = data[start:end]

        is_plain, score = validate_window(w)

        if min_score is None or score < min_score:
            min_score = score
        if max_score is None or score > max_score:
            max_score = score

        # Suspicious if score > threshold (for txt_fav)
        if score > score_threshold:
            num_suspicious += 1

    result["num_suspicious_windows"] = num_suspicious
    if min_score is not None:
        result["min_score"] = str(min_score)
    if max_score is not None:
        result["max_score"] = str(max_score)

    # File-level verdict
    if num_suspicious > 0:
        result["verdict"] = "encrypted"
        result["note"] = "has_suspicious_windows"
    else:
        result["verdict"] = "benign"
        # Only mention tail when we actually ignored some bytes
        if tail_bytes > 0:
            result["note"] = "tail_ignored_but_windows_all_valid"

    return result


# ----------------------------
# CLI parsing and main
# ----------------------------

def parse_args(argv: Optional[List[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Format-aware detector for text files using multi-encoding validation on fixed windows."
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
        "--window-size",
        type=int,
        default=DEFAULT_WINDOW_SIZE,
        help=f"Window size in bytes. Default: {DEFAULT_WINDOW_SIZE}.",
    )

    parser.add_argument(
        "--stride",
        type=int,
        default=None,
        help="Stride in bytes between windows. Default: equal to --window-size (tumbling windows).",
    )

    parser.add_argument(
        "--tail-mode",
        choices=["ignore", "overlap"],
        default="ignore",
        help="How to handle remaining bytes at the end of a file: "
             "'ignore' = process only full windows, ignore the tail; "
             "'overlap' = ensure the last window ends at EOF (allow overlap). "
             "Default: ignore.",
    )

    parser.add_argument(
        "--score-threshold",
        type=int,
        default=DEFAULT_SCORE_THRESHOLD,
        help="Maximum allowed window score before it is considered suspicious. "
             "For txt_fav, score is utf8_error_count for windows that fail "
             "all supported encodings; 0 for windows that decode cleanly. "
             f"Default: {DEFAULT_SCORE_THRESHOLD}.",
    )

    args = parser.parse_args(argv)

    if args.stride is None:
        args.stride = args.window_size

    if args.window_size <= 0:
        parser.error("--window-size must be a positive integer.")
    if args.stride <= 0:
        parser.error("--stride must be a positive integer.")
    if args.score_threshold < 0:
        parser.error("--score-threshold must be >= 0.")

    return args


def main(argv: Optional[List[str]] = None) -> None:
    args = parse_args(argv)

    try:
        files = discover_files(args.input_path)
    except Exception as e:  # noqa: BLE001
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)

    if not files:
        print("No files found to analyze.", file=sys.stderr)
        sys.exit(1)

    run_dir = create_run_directory(
        output_root=args.output_path,
        window_size=args.window_size,
        stride=args.stride,
        tail_mode=args.tail_mode,
        score_threshold=args.score_threshold,
    )
    write_config_json(run_dir, args)

    csv_path = os.path.join(run_dir, "results.csv")
    fieldnames = [
        "file_path",
        "window_size",
        "stride",
        "tail_mode",
        "file_size",
        "num_windows",
        "num_suspicious_windows",
        "min_score",
        "max_score",
        "score_threshold",
        "mode",
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
                window_size=args.window_size,
                stride=args.stride,
                tail_mode=args.tail_mode,
                score_threshold=args.score_threshold,
            )
            writer.writerow(res)

    print(f"Analysis complete. Results written to: {csv_path}")


if __name__ == "__main__":
    main()
