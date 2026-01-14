#!/usr/bin/env python3
# Rhea Detection Evaluator (explicit-directory; cmp_audit non-recursive)
# Adds GT augmentation from fileaware_files_<start epoch>_<end epoch>_csv:
#   - If keep_file==True and fileaware_reason contains "metadata encrypted" -> GT true
#
# Universe of block_ids (non-recursive, exactly these three under --gt-base):
#   <gt-base>/cmp_audit_vs_latest_at_end_match_csv/*.csv
#   <gt-base>/cmp_audit_vs_latest_at_end_audit_only_csv/*.csv
#   <gt-base>/cmp_audit_vs_latest_at_end_latest_only_csv/*.csv
#
# Ground truth sources (non-recursive, kept as two separate columns):
#   gt_device     <- <gt-base>/audit_device_blocks_csv/*.csv
#   gt_untrusted  <- <gt-base>/audit_untrusted_immutable_block_mappings_csv/*.csv
#
# Rhea decision:
#   --rhea-dir points to suspicious_block_mappings_*_csv (recursive)
#   If a universe block_id appears in ANY CSV there => rhea_decision = True; else False.
#   We also try to pick up file_path and byte_offsets for those suspicious blocks.
#
# File-aware GT augmentation:
#   Look under sibling directory of --rhea-dir:
#     <detect-root>/fileaware_files_<start epoch>_<end epoch>_csv/part-000*
#   Build a set of file paths for which:
#     (keep_file==True) and
#     (reason contains "metadata encrypted" OR (is PDF and reason contains "suspicious regions kept"))
#   Any suspicious block whose mapping points to one of these files is treated as GT-true in the
#   "combined" metric (gt_combined_aug).
#
# Outputs:
#   - eval_out/summary_table.csv
#   - eval_out/metrics.json (primary, combined_aug)
#   - eval_out/metrics.txt
#   - eval_out/confusion_details_primary.csv
#   - eval_out/confusion_details_combined.csv
#
import argparse
import json
import sys
from pathlib import Path
from typing import Iterable, Optional, Set, Dict, Tuple

import pandas as pd

# ---- NTFS block->file mapping (reuse your detector code) ----
try:
    from detector.ntfs_b2fm import extract_file_extents, build_interval_tree, map_blocks_to_files
except Exception as _e:
    extract_file_extents = None
    build_interval_tree = None
    map_blocks_to_files = None

def csvs_in_dir(dir_path: Path) -> Iterable[Path]:
    """Yield CSV files directly under dir_path (non-recursive)."""
    if not dir_path.exists():
        return []
    return sorted([p for p in dir_path.glob("*.csv") if p.is_file()])

def _normalize_nt_path(p: str, strip_stream: bool = True) -> str:
    """
    Normalize NT-style path for robust set comparisons:
      - convert backslashes to forward slashes
      - ensure leading slash
      - collapse duplicate slashes
      - lowercase (NTFS is case-preserving but case-insensitive)
      - optionally strip alternate-data-stream suffix (e.g., ':Zone.Identifier', ':$DATA')
    """
    if p is None:
        return ""
    s = str(p).strip()
    if not s:
        return ""
    s = s.replace("\\", "/")
    if not s.startswith("/"):
        s = "/" + s
    while "//" in s:
        s = s.replace("//", "/")
    if strip_stream and ":" in s[1:]:
        # split at first ':' after the leading slash
        s = s.split(":", 1)[0]
        if not s:
            s = "/"
    return s.lower()

def iter_csv_files_recursive(dir_path: Path) -> Iterable[Path]:
    """Yield all CSV files under the provided directory (recursively). Used for --rhea-dir."""
    if not dir_path.exists():
        return []
    return sorted([p for p in dir_path.rglob("*.csv") if p.is_file()])

def _read_file_paths_from_csvs(csv_paths: Iterable[Path]) -> Set[str]:
    """
    Collect a set of file paths from CSVs that may use any of the common column names:
    file_path / filepath / path. Returns normalized, non-empty strings.
    """
    files: Set[str] = set()
    for csv_path in csv_paths:
        try:
            df = pd.read_csv(csv_path, low_memory=False)
        except Exception as e:
            print(f"[warn] Failed to read CSV {csv_path}: {e}", file=sys.stderr)
            continue
        if df.empty:
            continue
        # normalize header casing
        cols = {c.lower(): c for c in df.columns}
        fp_col = cols.get("file_path") or cols.get("filepath") or cols.get("path")
        if not fp_col or fp_col not in df.columns:
            # no file path column in this CSV; skip silently (expected for some inputs)
            continue
        s = (df[fp_col].astype(str)
                       .str.strip()
                       .replace({"": pd.NA})
                       .dropna()
                       .unique())
        for v in s:
            if isinstance(v, str) and v:
                files.add(v)
    return files

def read_block_ids_from_csvs(csv_paths: Iterable[Path], block_id_col: Optional[str]) -> Set[int]:
    """Read a set of block IDs from a collection of CSV files."""
    ids: Set[int] = set()
    for csv_path in csv_paths:
        try:
            df = pd.read_csv(csv_path, low_memory=False)
        except Exception as e:
            print(f"[warn] Failed to read CSV {csv_path}: {e}", file=sys.stderr)
            continue

        if df.empty:
            continue

        col = block_id_col
        if col is None:
            # Try common candidates
            candidates = [c for c in df.columns if c.lower() in ("block_id", "blockid", "block", "id")]
            if candidates:
                col = candidates[0]
            else:
                # Fallback: first integer-like column
                for c in df.columns:
                    if pd.api.types.is_integer_dtype(df[c]):
                        col = c
                        break

        if col is None or col not in df.columns:
            print(f"[warn] No usable block id column found in {csv_path}. Columns={list(df.columns)}", file=sys.stderr)
            continue

        s = pd.to_numeric(df[col], errors="coerce").dropna().astype("int64")
        ids.update(s.tolist())

    return ids


def load_ground_truth_from_base(gt_base: Path, block_id_col: Optional[str]) -> pd.DataFrame:
    """
    Construct universe from the three cmp_audit* dirs (non-recursive).
    Provide two separate GT flags:
      - gt_device:     membership in audit_device_blocks_csv
      - gt_untrusted:  membership in audit_untrusted_immutable_block_mappings_csv
    """
    if not gt_base.exists():
        print(f"[error] --gt-base not found: {gt_base}", file=sys.stderr)
        return pd.DataFrame(columns=["block_id", "gt_device", "gt_untrusted"], dtype=object)

    dirs_cmp = [
        gt_base / "cmp_audit_vs_latest_at_end_match_csv",
        gt_base / "cmp_audit_vs_latest_at_end_audit_only_csv",
        gt_base / "cmp_audit_vs_latest_at_end_latest_only_csv",
    ]

    # Universe: union of block_ids from those three dirs (only *.csv directly under them)
    universe_ids: Set[int] = set()
    for d in dirs_cmp:
        universe_ids |= read_block_ids_from_csvs(csvs_in_dir(d), block_id_col)

    if not universe_ids:
        print("[warn] Universe from cmp_audit* is empty (checked three non-recursive dirs).", file=sys.stderr)

    # Ground truth sources (non-recursive)
    audit_device_blocks_dir = gt_base / "audit_device_blocks_csv"
    device_ids = read_block_ids_from_csvs(csvs_in_dir(audit_device_blocks_dir), block_id_col)

    untrusted_blocks_dir = gt_base / "audit_untrusted_immutable_block_mappings_csv"
    untrusted_ids = read_block_ids_from_csvs(csvs_in_dir(untrusted_blocks_dir), block_id_col)

    # Build DF over the universe only
    all_ids = sorted(universe_ids)
    gt = pd.DataFrame({"block_id": all_ids})
    gt["gt_device"] = gt["block_id"].isin(device_ids)
    gt["gt_untrusted"] = gt["block_id"].isin(untrusted_ids)
    return gt


def load_rhea_decisions_and_mapping(
    rhea_dir: Path,
    block_id_col: Optional[str]
) -> Tuple[Set[int], Dict[int, Tuple[str, str]]]:
    """
    Return:
      - set of block_ids Rhea flagged as suspicious (True).
      - mapping dict { block_id -> (file_path, byte_offsets) } when available.
    """
    suspicious_ids: Set[int] = set()
    mapping: Dict[int, Tuple[str, str]] = {}

    for csv_path in iter_csv_files_recursive(rhea_dir):
        try:
            df = pd.read_csv(csv_path, low_memory=False)
        except Exception as e:
            print(f"[warn] Failed to read CSV {csv_path}: {e}", file=sys.stderr)
            continue
        if df.empty:
            continue

        # Find a block id column
        col = block_id_col
        if col is None:
            candidates = [c for c in df.columns if c.lower() in ("block_id", "blockid", "block", "id")]
            if candidates:
                col = candidates[0]
            else:
                for c in df.columns:
                    if pd.api.types.is_integer_dtype(df[c]):
                        col = c
                        break
        if col is None or col not in df.columns:
            print(f"[warn] No usable block id column found in {csv_path}. Columns={list(df.columns)}", file=sys.stderr)
            continue

        # Normalize/optional columns for path & offsets if present
        path_col = None
        for c in df.columns:
            if c.lower() in ("file_path", "filepath", "path"):
                path_col = c
                break
        offsets_col = None
        for c in df.columns:
            if c.lower() in ("byte_offsets", "byteoffsets", "offsets", "byte_ranges", "byteranges"):
                offsets_col = c
                break

        # Collect
        for _, row in df.iterrows():
            try:
                bid = int(row[col])
            except Exception:
                continue
            suspicious_ids.add(bid)
            if path_col is not None:
                fp = str(row[path_col]) if pd.notna(row[path_col]) else ""
            else:
                fp = ""
            if offsets_col is not None:
                bo = str(row[offsets_col]) if pd.notna(row[offsets_col]) else ""
            else:
                bo = ""
            # Prefer first non-empty mapping (keep earliest)
            if bid not in mapping or (fp or bo):
                mapping[bid] = (fp, bo)

    return suspicious_ids, mapping


def _fileaware_dir_for_rhea_dir(rhea_dir: Path) -> Path:
    """
    From .../detect/suspicious_block_mappings_<start>_<end>_csv
    derive .../detect/fileaware_files_<start>_<end>_csv
    Fallback: .../detect/fileaware_files_4_4_csv if pattern not recognized.
    """
    detect_root = rhea_dir.parent  # .../detect
    name = rhea_dir.name
    # expected: suspicious_block_mappings_<a>_<b>_csv
    if name.startswith("suspicious_block_mappings_") and name.endswith("_csv"):
        suffix = name[len("suspicious_block_mappings_"):]  # "<a>_<b>_csv"
        return detect_root / f"fileaware_files_{suffix}"
    # fallback
    return detect_root / "fileaware_files_4_4_csv"


def load_fileaware_keep_all_files(rhea_dir: Path) -> Set[str]:
    """
    Read fileaware_files_<start>_<end>_csv/part-000* (sibling of --rhea-dir) and
    return a set of file paths for which:
      - keep_file == True, and
      - (reason contains "metadata encrypted")
        OR (is a PDF AND reason contains "suspicious regions kept")
    Matching on reason is case-insensitive. Repeated header rows are ignored.
    """
    keep_all: Set[str] = set()
    faf_dir = _fileaware_dir_for_rhea_dir(rhea_dir)

    parts = sorted(faf_dir.glob("part-000*"))
    if not parts:
        print(f"[warn] No fileaware parts found at: {faf_dir}", file=sys.stderr)
        return keep_all

    frames = []
    for p in parts:
        try:
            df = pd.read_csv(p, low_memory=False)
        except Exception as e:
            print(f"[warn] Failed to read {p}: {e}", file=sys.stderr)
            continue
        if df.empty:
            continue
        # Drop repeated header rows (common in these part files)
        if "file_path" in df.columns:
            df = df[df["file_path"] != "file_path"]
        frames.append(df)

    if not frames:
        return keep_all

    all_df = pd.concat(frames, ignore_index=True)

    # Normalize column names
    cols = {c.lower(): c for c in all_df.columns}
    fp_col = cols.get("file_path")
    kf_col = cols.get("keep_file")
    fr_col = cols.get("fileaware_reason") or cols.get("reason")

    if not fp_col or not kf_col or not fr_col:
        print(f"[warn] fileaware parts missing required columns; got: {list(all_df.columns)}", file=sys.stderr)
        return keep_all

    # Vectorized truth mask for keep_file that tolerates bools/strings/ints
    kcol = all_df[kf_col]
    truthy_str = kcol.astype(str).str.strip().str.lower()
    ktrue = (kcol == True) | truthy_str.isin({"true", "t", "1", "yes", "y"})  # noqa: E712

    if not ktrue.any():
        print(f"[info] fileaware keep_file had no true rows at {faf_dir}")
        return keep_all

    sel = all_df.loc[ktrue, [fp_col, fr_col]].copy()
    sel[fp_col] = sel[fp_col].astype(str).str.strip()
    sel[fr_col] = sel[fr_col].astype(str).str.strip().str.lower()

    meta_mask = sel[fr_col].str.contains("metadata encrypted", na=False)

    final = sel.loc[meta_mask, fp_col]
    
    uniq = final.dropna().unique()
    for fp in uniq:
        if fp:
            keep_all.add(fp)

    print(f"[info] fileaware keep_all loaded: {len(keep_all)} from {faf_dir}")
    return keep_all

def _load_gt_encrypted_files(gt_base: Path) -> Set[str]:
    """
    Legacy helper no longer used for metrics (we now map gt_device blocks -> files).
    Kept for backward compatibility; returns empty to avoid accidental mixing.
    """
    return set()

def _load_rhea_alarm_files(rhea_dir: Path) -> Set[str]:
    """
    File-level 'alarms' from detect.py: scan suspicious_block_mappings_*_csv (recursively)
    and collect file_path values that survived file-aware/trust filtering.
    """
    raw = _read_file_paths_from_csvs(iter_csv_files_recursive(rhea_dir))
    return {_normalize_nt_path(p) for p in raw if p}

def _compute_file_level_metrics(gt_files: Set[str], alarm_files: Set[str], universe_files: Optional[Set[str]] = None) -> Tuple[Dict[str, Optional[float]], pd.DataFrame]:
    """
    Build a file-level universe and compute TP/TN/FP/FN and metrics.
    If 'universe_files' is provided, the universe is exactly that set.
    Otherwise we fall back to union(gt_files, alarm_files).
    Returns (metrics_dict, confusion_df).
    """
    if universe_files is not None:
        # Constrain both GT and alarms to the declared universe.
        gt_files = set(f for f in gt_files if f in universe_files)
        alarm_files = set(f for f in alarm_files if f in universe_files)
        all_files = sorted(universe_files)
    else:
        all_files = sorted(gt_files | alarm_files)
    if not all_files:
        return ({
            "TP": 0, "TN": 0, "FP": 0, "FN": 0,
            "Accuracy": None, "Precision": None, "Recall": None, "F1": None, "Support": 0
        }, pd.DataFrame(columns=["file_path","gt_encrypted","rhea_alarm","class"]))

    df = pd.DataFrame({"file_path": all_files})
    df["gt_encrypted"] = df["file_path"].isin(gt_files)
    df["rhea_alarm"]   = df["file_path"].isin(alarm_files)

    # Confusion class
    def _cls(row):
        g = bool(row["gt_encrypted"]); r = bool(row["rhea_alarm"])
        if g and r:   return "TP"
        if (not g) and (not r): return "TN"
        if (not g) and r:  return "FP"
        return "FN"
    df["class"] = df.apply(_cls, axis=1)

    tp = int((df["class"] == "TP").sum())
    tn = int((df["class"] == "TN").sum())
    fp = int((df["class"] == "FP").sum())
    fn = int((df["class"] == "FN").sum())
    support = int(len(df))
    acc = (tp + tn) / support if support > 0 else None
    prec = tp / (tp + fp) if (tp + fp) > 0 else None
    rec = tp / (tp + fn) if (tp + fn) > 0 else None
    f1 = (2 * prec * rec / (prec + rec)) if (prec is not None and rec is not None and (prec + rec) > 0) else None

    metrics = {"TP": tp, "TN": tn, "FP": fp, "FN": fn,
               "Accuracy": acc, "Precision": prec, "Recall": rec, "F1": f1, "Support": support}
    return metrics, df[["file_path","gt_encrypted","rhea_alarm","class"]]

def _map_blocks_to_fileset(image_path: Path, block_ids: Iterable[int], sector_size: int = 512) -> Set[str]:
    """
    Use detector.ntfs_b2fm to map a set of device block IDs (sectors) to normalized file paths.
    Returns a de-duplicated set of normalized paths.
    """
    if extract_file_extents is None:
        raise RuntimeError("detector.ntfs_b2fm not available. Ensure it's importable in this environment.")
    fexts, cluster_size = extract_file_extents(str(image_path))
    itree = build_interval_tree(fexts)
    # map_blocks_to_files expects a set/list of sector IDs
    rows = map_blocks_to_files(set(int(b) for b in block_ids), itree, cluster_size, sector_size=sector_size)
    paths = {_normalize_nt_path(r.get("file_path", "")) for r in rows if r.get("file_path")}
    return {p for p in paths if p}

def build_summary_table(gt_df: pd.DataFrame, rhea_true_ids: Set[int]) -> pd.DataFrame:
    """
    Return a table with:
      - block_id
      - gt_device
      - gt_untrusted
      - gt_primary  (== gt_device)
      - gt_combined (gt_device OR gt_untrusted)   # base combined
      - rhea_decision
    """
    if gt_df.empty:
        return pd.DataFrame(columns=[
            "block_id", "gt_device", "gt_untrusted",
            "gt_primary", "gt_combined", "rhea_decision"
        ])

    df = gt_df.copy()
    df["rhea_decision"] = df["block_id"].isin(rhea_true_ids)
    df["gt_primary"] = df["gt_device"]  # legacy behavior
    df["gt_combined"] = df["gt_device"] | df["gt_untrusted"]
    return df[[
        "block_id", "gt_device", "gt_untrusted",
        "gt_primary", "gt_combined", "rhea_decision"
    ]]


def compute_metrics_for_gt(summary: pd.DataFrame, gt_col: str) -> Dict[str, Optional[float]]:
    """Compute confusion matrix + metrics using the specified GT column."""
    if summary.empty or gt_col not in summary.columns:
        return {
            "GT_Column": gt_col, "TP": 0, "TN": 0, "FP": 0, "FN": 0,
            "Accuracy": None, "Precision": None, "Recall": None, "F1": None,
            "Support": 0,
        }

    gt = summary[gt_col]
    rh = summary["rhea_decision"]

    tp = int(((gt == True) & (rh == True)).sum())
    tn = int(((gt == False) & (rh == False)).sum())
    fp = int(((gt == False) & (rh == True)).sum())
    fn = int(((gt == True) & (rh == False)).sum())

    support = int(len(summary))

    accuracy  = (tp + tn) / support if support > 0 else None
    precision = tp / (tp + fp) if (tp + fp) > 0 else None
    recall    = tp / (tp + fn) if (tp + fn) > 0 else None
    f1        = (2 * precision * recall / (precision + recall)) if precision is not None and recall is not None and (precision + recall) > 0 else None

    return {
        "GT_Column": gt_col,
        "TP": tp, "TN": tn, "FP": fp, "FN": fn,
        "Accuracy": accuracy, "Precision": precision, "Recall": recall, "F1": f1,
        "Support": support,
    }


def write_confusion_details(
    summary: pd.DataFrame,
    gt_col: str,
    out_csv: Path,
    mapping: Dict[int, Tuple[str, str]]
) -> None:
    """
    Write per-block confusion with columns:
      block_id, gt, rhea_decision, class (TP/TN/FP/FN), file_path, byte_offsets
    file_path/byte_offsets are attached only when rhea_decision=True and mapping exists.
    """
    rows = []
    for _, r in summary.iterrows():
        bid = int(r["block_id"])
        gt = bool(r[gt_col])
        rh = bool(r["rhea_decision"])
        if gt and rh:
            cls = "TP"
        elif (not gt) and (not rh):
            cls = "TN"
        elif (not gt) and rh:
            cls = "FP"
        else:
            cls = "FN"

        fp = ""
        bo = ""
        if rh and bid in mapping:
            fp, bo = mapping.get(bid, ("", ""))

        rows.append({
            "block_id": bid,
            "gt": gt,
            "rhea_decision": rh,
            "class": cls,
            "file_path": fp,
            "byte_offsets": bo,
        })

    df = pd.DataFrame(rows, columns=["block_id", "gt", "rhea_decision", "class", "file_path", "byte_offsets"])
    out_csv.parent.mkdir(parents=True, exist_ok=True)
    df.to_csv(out_csv, index=False)


def write_outputs(summary: pd.DataFrame, metrics_primary: dict, metrics_combined: dict, out_dir: Path) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)

    summary_csv = out_dir / "summary_table.csv"
    summary.to_csv(summary_csv, index=False)

    metrics_json = out_dir / "metrics.json"
    with open(metrics_json, "w") as f:
        # Only keep PRIMARY in JSON; no full relabeling metrics dump
        json.dump({"primary": metrics_primary}, f, indent=2)

    def fmt(x):
        if isinstance(x, float):
            return f"{x:.6f}"
        return str(x)

    metrics_txt = out_dir / "metrics.txt"
    with open(metrics_txt, "w") as f:
        f.write("=== PRIMARY (legacy: GT = gt_device) ===\n")
        f.write(f"Confusion Matrix Counts:\n")
        f.write(f"  TP: {metrics_primary['TP']}\n")
        f.write(f"  TN: {metrics_primary['TN']}\n")
        f.write(f"  FP: {metrics_primary['FP']}\n")
        f.write(f"  FN: {metrics_primary['FN']}\n\n")
        f.write("Metrics:\n")
        f.write(f"  Accuracy:  {fmt(metrics_primary['Accuracy'])}\n")
        f.write(f"  Precision: {fmt(metrics_primary['Precision'])}\n")
        f.write(f"  Recall:    {fmt(metrics_primary['Recall'])}\n")
        f.write(f"  F1-Score:  {fmt(metrics_primary['F1'])}\n")
        f.write(f"  Support:   {metrics_primary['Support']}\n\n")

    print(f"[ok] Wrote summary to: {summary_csv}")
    print(f"[ok] Wrote metrics to: {metrics_txt}")
    print(f"[ok] JSON metrics:     {metrics_json}")
    # file-level metrics are written separately (see main) to keep this function focused on block-level outputs.

def main():
    ap = argparse.ArgumentParser(description="Rhea detection evaluator (explicit-directory; cmp_audit non-recursive)")
    ap.add_argument("--gt-base", type=str, required=True, help="Base directory for ground truth inputs")
    ap.add_argument("--rhea-dir", type=str, required=True, help="Directory containing suspicious_block_mappings_*_csv files")
    ap.add_argument("--block-id-col", type=str, default=None, help="Column name for block IDs (default: auto-detect)")
    ap.add_argument("--out-dir", type=str, default="./eval_out", help="Where to write outputs")
    ap.add_argument("--device-image", type=str, required=True, help="Path to NTFS device image (.img) for file-level mapping")
    ap.add_argument("--block-size", type=int, default=512, help="Detector sector size (bytes). Must match detect.py block_size.")

    args = ap.parse_args()

    gt_base = Path(args.gt_base).expanduser().resolve()
    rhea_dir = Path(args.rhea_dir).expanduser().resolve()
    out_dir = Path(args.out_dir).expanduser().resolve()
    device_img = Path(args.device_image).expanduser().resolve()

    print(f"[info] GT base:       {gt_base}")
    print(f"[info] Rhea dir:      {rhea_dir}")
    print(f"[info] Block-ID col:  {args.block_id_col or '(auto)'}")
    print(f"[info] Output dir:    {out_dir}")
    print(f"[info] Device image:  {device_img}")

    gt_df = load_ground_truth_from_base(gt_base, args.block_id_col)
    if gt_df.empty:
        print("[error] Could not construct ground truth (universe may be empty). Exiting.", file=sys.stderr)
        sys.exit(2)

    # Rhea decisions + mapping (path/offsets)
    rhea_true_ids, mapping = load_rhea_decisions_and_mapping(rhea_dir, args.block_id_col)

    # Base summary (primary & base-combined)
    summary = build_summary_table(gt_df, rhea_true_ids)

    # Augment GT using file-aware summary located under the detect root (sibling of rhea-dir)
    keep_all_files = load_fileaware_keep_all_files(rhea_dir)

    # For blocks mapped to files in 'keep_all_files', mark as GT-true in the combined variant.
    def _mapped_file_is_keep_all(bid: int) -> bool:
        if bid not in mapping:
            return False
        fp, _ = mapping[bid]
        return bool(fp and fp in keep_all_files)

    mapped_true = summary["block_id"].map(lambda x: _mapped_file_is_keep_all(int(x)))
    summary["gt_combined_aug"] = summary["gt_combined"] | mapped_true
    
    # Now that all GT columns are present, take the copy for confusion-details
    summary_full = summary.copy()

    # --- BEGIN: bucketed diagnostics (no relabeling) ---
    def _load_fileaware_flat(rhea_dir: Path) -> pd.DataFrame:
        faf_dir = _fileaware_dir_for_rhea_dir(rhea_dir)
        parts = sorted(faf_dir.glob("part-000*"))
        if not parts:
            return pd.DataFrame(columns=["file_path","keep_file","fileaware_reason"])
        frames = []
        for p in parts:
            try:
                df = pd.read_csv(p, low_memory=False)
            except Exception:
                continue
            if df.empty:
                continue
            if "file_path" in df.columns:
                df = df[df["file_path"] != "file_path"]  # strip repeated headers
            frames.append(df)
        if not frames:
            return pd.DataFrame(columns=["file_path","keep_file","fileaware_reason"])
        df = pd.concat(frames, ignore_index=True)
        # normalize
        cols = {c.lower(): c for c in df.columns}
        fp = cols.get("file_path"); kf = cols.get("keep_file"); fr = cols.get("fileaware_reason") or cols.get("reason")
        if not (fp and kf and fr):
            return pd.DataFrame(columns=["file_path","keep_file","fileaware_reason"])
        out = df[[fp,kf,fr]].copy()
        out.columns = ["file_path","keep_file","fileaware_reason"]
        # normalize types
        out["file_path"] = out["file_path"].astype(str).str.strip()
        ks = out["keep_file"].astype(str).str.strip().str.lower()
        out["keep_file"] = (out["keep_file"] == True) | ks.isin({"true","t","1","yes","y"})
        out["fileaware_reason"] = out["fileaware_reason"].astype(str).str.strip()
        return out

    # Rhea positives (by block_id), with first-seen mapping (file_path, offsets)
    rhea_pos = summary[summary["rhea_decision"] == True][["block_id"]].copy()
    file_map_rows = []
    for bid in rhea_pos["block_id"]:
        fp, bo = mapping.get(int(bid), ("",""))
        file_map_rows.append({"block_id": int(bid), "file_path": fp, "byte_offsets": bo})
    rhea_pos_map = pd.DataFrame(file_map_rows)

    faf = _load_fileaware_flat(rhea_dir)

    # Join positives to fileaware reasons (file-level; coarse but practical)
    pos_join = rhea_pos_map.merge(faf, on="file_path", how="left")

    # Buckets (feel free to refine regexes)
    reason_l = pos_join["fileaware_reason"].str.lower().fillna("")
    pos_join["bkt_metadata_encrypted"] = reason_l.str.contains("metadata encrypted", na=False)
    pos_join["bkt_decode_failed"]     = reason_l.str.contains("decode|decompress|unsupported|password|crc|xref|trailer|central dir|directory", na=False)
    pos_join["bkt_pdf_suspicious"]    = reason_l.str.contains("suspicious regions kept", na=False)
    # If you log media-structure-OK but uniform payload as a phrase, catch it here:
    pos_join["bkt_media_uniform_valid"] = reason_l.str.contains("media.*uniform|payload.*uniform.*valid", na=False)

    # Add ground truth flag for slicing (PRIMARY GT)
    gt = summary[["block_id","gt_primary"]]
    pos_join = pos_join.merge(gt, on="block_id", how="left")

    # Write per-positive bucket table
    out_dir = Path(args.out_dir).expanduser().resolve()
    out_dir.mkdir(parents=True, exist_ok=True)
    pos_join.to_csv(out_dir / "rhea_positives_buckets.csv", index=False)

    # Summaries you’ll actually read:
    def _count(col): return int(pos_join[col].fillna(False).sum())
    bucket_summary = {
        "total_rhea_positives": int(len(pos_join)),
        "primary_TP": int(((pos_join["gt_primary"] == True)).sum()),
        "primary_FP": int(((pos_join["gt_primary"] == False)).sum()),
        "primary_FP__metadata_encrypted": int(((pos_join["gt_primary"] == False) & (pos_join["bkt_metadata_encrypted"])).sum()),
        "primary_FP__decode_failed": int(((pos_join["gt_primary"] == False) & (pos_join["bkt_decode_failed"])).sum()),
        "primary_FP__pdf_suspicious": int(((pos_join["gt_primary"] == False) & (pos_join["bkt_pdf_suspicious"])).sum()),
        "primary_FP__media_uniform_valid": int(((pos_join["gt_primary"] == False) & (pos_join["bkt_media_uniform_valid"])).sum()),
    }

    with open(out_dir / "bucket_summary.txt", "w") as fh:
        for k,v in bucket_summary.items():
            fh.write(f"{k}: {v}\n")
    print(f"[ok] Wrote bucket diagnostics to: {out_dir}/rhea_positives_buckets.csv and bucket_summary.txt")
    # --- END: bucketed diagnostics ---
    
    # Compute metrics (primary & augmented combined)
    metrics_primary = compute_metrics_for_gt(summary, "gt_primary")
    metrics_combined = compute_metrics_for_gt(summary, "gt_combined_aug")  # used only for FP delta

    # Log nice counts to stdout
    print("\n=== PRIMARY (legacy: GT = gt_device) ===")
    print(f"TP: {metrics_primary['TP']}")
    print(f"TN: {metrics_primary['TN']}")
    print(f"FP: {metrics_primary['FP']}")
    print(f"FN: {metrics_primary['FN']}")
    for k in ["Accuracy", "Precision", "Recall", "F1", "Support"]:
        v = metrics_primary[k]
        print(f"{k}: {v:.6f}" if isinstance(v, float) else f"{k}: {v}")
    # Only show FP reduction from relabeling (file-aware keep/metadata-encrypted)
    fp_primary  = int(metrics_primary["FP"])
    fp_aug      = int(metrics_combined["FP"])
    print("\n=== RELABELING EFFECT (file-aware 'metadata encrypted') ===")
    print(f"FP reduced: {fp_primary} -> {fp_aug}  (Δ = {fp_primary - fp_aug})\n")

    # --- Verify which blocks/files account for the FP reduction ---
    # Sets
    Rh = set(summary.loc[summary["rhea_decision"] == True, "block_id"])
    Gp = set(summary.loc[summary["gt_primary"] == True, "block_id"])
    Gc = set(summary.loc[summary["gt_combined_aug"] == True, "block_id"])

    FP_primary_set = Rh - Gp
    FP_aug_set     = Rh - Gc

    # Blocks that stopped being FP after relabeling (these drove the "FP reduced" delta)
    fp_to_tp_blocks = sorted(FP_primary_set - FP_aug_set)

    # Build a table with file mappings (path + offsets) using the mapping dict you already produced
    rows = []
    for bid in fp_to_tp_blocks:
        fp, bo = mapping.get(int(bid), ("", ""))
        rows.append({"block_id": int(bid), "file_path": fp, "byte_offsets": bo})

    fp_to_tp_df = pd.DataFrame(rows, columns=["block_id","file_path","byte_offsets"])

    # (Optional but helpful) normalize path and join file-aware reason for context
    if not fp_to_tp_df.empty:
        fp_to_tp_df["file_path_norm"] = fp_to_tp_df["file_path"].map(lambda p: _normalize_nt_path(str(p)) if p else "")

        # 'faf' was created earlier with [file_path, keep_file, fileaware_reason] if available
        try:
            fp_to_tp_df = fp_to_tp_df.merge(
                faf[["file_path","keep_file","fileaware_reason"]],
                on="file_path", how="left"
            )
        except Exception:
            pass

    # Write per-block list
    out_dir.mkdir(parents=True, exist_ok=True)
    fp_to_tp_csv = out_dir / "relabel_fp_to_tp_blocks.csv"
    fp_to_tp_df.to_csv(fp_to_tp_csv, index=False)
    print(f"[ok] Wrote relabel FP→TP block list: {fp_to_tp_csv}")

    # Also write a per-file rollup so you can see which files account for most FP reduction
    if not fp_to_tp_df.empty:
        per_file = (fp_to_tp_df
                    .groupby(["file_path"], dropna=False)
                    .size().reset_index(name="n_blocks"))
        per_file = per_file.sort_values("n_blocks", ascending=False)
        per_file_csv = out_dir / "relabel_fp_to_tp_by_file.csv"
        per_file.to_csv(per_file_csv, index=False)
        print(f"[ok] Wrote per-file rollup: {per_file_csv}")

    # --- Remaining false positives after relabeling: FP_primary ∩ FP_aug ---

    # Sets (reuse if already defined)
    Rh = set(summary.loc[summary["rhea_decision"] == True, "block_id"])
    Gp = set(summary.loc[summary["gt_primary"] == True, "block_id"])
    Gc = set(summary.loc[summary["gt_combined_aug"] == True, "block_id"])

    FP_primary_set = Rh - Gp
    FP_aug_set     = Rh - Gc

    # Blocks that stayed FP even after relabeling
    fp_still_blocks = sorted(FP_primary_set & FP_aug_set)

    # Normalize keep_all paths once for robust membership checks
    keep_all_norm = {_normalize_nt_path(p) for p in keep_all_files} if keep_all_files else set()

    rows = []
    for bid in fp_still_blocks:
        fp, bo = mapping.get(int(bid), ("", ""))
        fp_norm = _normalize_nt_path(fp) if fp else ""
        has_map = bool(fp)
        in_keep_all = (fp_norm in keep_all_norm)
        
        rows.append({
            "block_id": int(bid),
            "file_path": fp,
            "file_path_norm": fp_norm,
            "byte_offsets": bo,
            "has_mapping": has_map,
            "in_keep_all_files": in_keep_all,
        })

    fp_still_df = pd.DataFrame(rows, columns=[
        "block_id","file_path","file_path_norm","byte_offsets",
        "has_mapping","in_keep_all_files"
    ])

    # Attach file-aware reason when available (faf was built earlier: [file_path, keep_file, fileaware_reason])
    try:
        if not fp_still_df.empty and 'file_path' in fp_still_df.columns and not faf.empty:
            fp_still_df = fp_still_df.merge(
                faf[["file_path","keep_file","fileaware_reason"]],
                on="file_path", how="left"
            )
    except Exception:
        pass

    # Lightweight diagnosis of why they remained FP
    def _why(row):
        if not row.get("has_mapping"):
            return "no_mapping_for_block"
        if row.get("in_keep_all_files"):
            # mapped into a keep_all file, but still FP under gt_combined_aug → likely path/ADS mismatch or reason not included in augmentation
            return "mapped_to_keep_all_but_not_relabelled"
        # mapped but file wasn’t in keep_all set
        # check reason (if any) to hint at next steps
        reason = (row.get("fileaware_reason") or "").lower()
        if "metadata encrypted" in reason:
            return "reason_says_metadata_encrypted_but_not_in_keep_all"
        if "suspicious regions kept" in reason:
            return "pdf_suspicious_regions_not_whitelisted"
        return "mapped_non_keep_all_file"
    
    if not fp_still_df.empty:
        fp_still_df["diagnosis"] = fp_still_df.apply(_why, axis=1)

    # Write artifacts
    out_dir.mkdir(parents=True, exist_ok=True)
    still_blocks_csv = out_dir / "relabel_fp_still_fp_blocks.csv"
    fp_still_df.to_csv(still_blocks_csv, index=False)
    print(f"[ok] Wrote remaining FP blocks after relabeling: {still_blocks_csv}")

    # Per-file rollup (which files still drive the FPs)
    if not fp_still_df.empty:
        per_file = (fp_still_df
                    .groupby(["file_path"], dropna=False)
                    .size().reset_index(name="n_blocks")
                    .sort_values("n_blocks", ascending=False))
        per_file_csv = out_dir / "relabel_fp_still_fp_by_file.csv"
        per_file.to_csv(per_file_csv, index=False)
        print(f"[ok] Wrote per-file rollup for remaining FPs: {per_file_csv}")

        # Optional: summary by diagnosis to see dominant causes
        by_diag = (fp_still_df
                   .groupby("diagnosis")
                   .size().reset_index(name="count")
                   .sort_values("count", ascending=False))
        by_diag_csv = out_dir / "relabel_fp_still_fp_by_diagnosis.csv"
        by_diag.to_csv(by_diag_csv, index=False)
        print(f"[ok] Wrote diagnosis summary: {by_diag_csv}")
        
    # Write artifacts
    summary_view = summary[[
        "block_id", "gt_device", "gt_untrusted",
        "gt_primary", "gt_combined", "gt_combined_aug", "rhea_decision"
    ]]
    write_outputs(summary_view, metrics_primary, metrics_combined, out_dir)

    # --- Write confusion details (block-level) ---
    # Primary (legacy): GT = gt_device
    write_confusion_details(
        summary_full, "gt_primary",
        out_csv=out_dir / "confusion_details_primary.csv",
        mapping=mapping
    )
    # Combined (augmented): used for diagnostics (optional but handy)
    # Be defensive in case a future run disables augmentation.
    gt_combined_col = "gt_combined_aug" if "gt_combined_aug" in summary_full.columns else "gt_combined"
    write_confusion_details(
        summary_full, gt_combined_col,
        out_csv=out_dir / "confusion_details_combined.csv",
        mapping=mapping
    )

    # --- File-level metrics & artifacts (Universe = NTFS map of block-level universe) ---
    try:
        # Resolve locally to avoid NameError if earlier assignment was skipped/edited
        img_path = Path(args.device_image).expanduser().resolve()
        
        # Universe blocks = union of three cmp_* dirs (already used for block-level universe)
        dirs_cmp = [
            gt_base / "cmp_audit_vs_latest_at_end_match_csv",
            gt_base / "cmp_audit_vs_latest_at_end_audit_only_csv",
            gt_base / "cmp_audit_vs_latest_at_end_latest_only_csv",
        ]
        universe_block_ids: Set[int] = set()
        for d in dirs_cmp:
            universe_block_ids |= read_block_ids_from_csvs(csvs_in_dir(d), args.block_id_col)
        if not universe_block_ids:
            print("[warn] File-level: universe (by blocks) is empty; skipping file-level metrics.")
            universe_files = set()
        else:
            universe_files = _map_blocks_to_fileset(img_path, universe_block_ids, sector_size=int(args.block_size))

        # GT blocks (primary) -> files
        audit_device_blocks_dir = gt_base / "audit_device_blocks_csv"
        gt_device_block_ids = read_block_ids_from_csvs(csvs_in_dir(audit_device_blocks_dir), args.block_id_col)
        gt_files = _map_blocks_to_fileset(img_path, gt_device_block_ids, sector_size=int(args.block_size)) if gt_device_block_ids else set()

        # Alarm files: post–file-aware suspicious mappings
        alarm_files = _load_rhea_alarm_files(rhea_dir)

        # Constrain to universe (so totals add up cleanly)
        file_metrics, file_conf = _compute_file_level_metrics(gt_files, alarm_files, universe_files=universe_files if universe_files else None)

        # ---- Also print FILE-LEVEL metrics to stdout (full section) ----
        def _fmt(x):
            return f"{x:.6f}" if isinstance(x, float) else str(x)
        print("\n=== FILE-LEVEL (Universe = NTFS map of block-level universe) ===")
        print("Confusion Matrix Counts:")
        print(f"  TP: {file_metrics['TP']}")
        print(f"  TN: {file_metrics['TN']}")
        print(f"  FP: {file_metrics['FP']}")  # FP == alarm & not GT (i.e., alarm survived file-aware)
        print(f"  FN: {file_metrics['FN']}")
        print("Metrics:")
        print(f"  Accuracy:  {_fmt(file_metrics['Accuracy'])}")
        print(f"  Precision: {_fmt(file_metrics['Precision'])}")
        print(f"  Recall:    {_fmt(file_metrics['Recall'])}")
        print(f"  F1-Score:  {_fmt(file_metrics['F1'])}")
        print(f"  Support:   {file_metrics['Support']}\n")
 
        # Save file-level confusion
        file_conf_csv = out_dir / "file_level_confusion.csv"
        file_conf.to_csv(file_conf_csv, index=False)

        # ---- Print and save per-class file lists (diagnostics) ----
        def _dump_files_by_class(df, klass, out_path):
            files = sorted(df.loc[df["class"] == klass, "file_path"].astype(str).tolist())
            # Print to stdout
            #print(f"{klass} files ({len(files)}):")
            #for p in files:
            #    print(f"  {p}")
            #print("")  # blank line
            # Save to disk
            with open(out_path, "w") as fh:
                for p in files:
                    fh.write(f"{p}\n")

        _dump_files_by_class(file_conf, "TP", out_dir / "file_level_TP.txt")
        _dump_files_by_class(file_conf, "TN", out_dir / "file_level_TN.txt")
        _dump_files_by_class(file_conf, "FP", out_dir / "file_level_FP.txt")
        _dump_files_by_class(file_conf, "FN", out_dir / "file_level_FN.txt")
        
        # Save file-level metrics (json + pretty txt)
        file_json = out_dir / "file_level_metrics.json"
        with open(file_json, "w") as f:
            json.dump(file_metrics, f, indent=2)

        file_txt = out_dir / "file_level_metrics.txt"
        with open(file_txt, "w") as f:
            f.write("\n=== FILE-LEVEL (Universe = NTFS map of block-level universe) ===")
            f.write("Confusion Matrix Counts:\n")
            f.write(f"  TP: {file_metrics['TP']}\n")
            f.write(f"  TN: {file_metrics['TN']}\n")
            f.write(f"  FP: {file_metrics['FP']}\n")
            f.write(f"  FN: {file_metrics['FN']}\n\n")
            f.write("Metrics:\n")
            f.write(f"  Accuracy:  {_fmt(file_metrics['Accuracy'])}\n")
            f.write(f"  Precision: {_fmt(file_metrics['Precision'])}\n")
            f.write(f"  Recall:    {_fmt(file_metrics['Recall'])}\n")
            f.write(f"  F1-Score:  {_fmt(file_metrics['F1'])}\n")
            f.write(f"  Support:   {file_metrics['Support']}\n")

        print(f"[ok] Wrote file-level confusion: {file_conf_csv}")
        print(f"[ok] Wrote file lists: {out_dir}/file_level_TP.txt | TN.txt | FP.txt | FN.txt")
        print(f"[ok] Wrote file-level metrics:   {file_txt}")
        print(f"[ok] JSON file-level metrics:    {file_json}")
    except Exception as e:
        print(f"[warn] Skipping file-level metrics due to error: {e}")

    
if __name__ == "__main__":
    main()
