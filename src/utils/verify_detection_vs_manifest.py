#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
verify_detection_vs_manifest.py  (v2)

Compare Rhea detection outputs to a PERSim attack manifest.

Inputs
------
1) --suspicious  suspicious_regions.csv  (columns: extent_id,lba_start_block,lba_end_block,start_epoch,end_epoch,chi2_final)
2) --blockmap    block_to_file.csv       (columns: file_path,extent_id,block_id,offset_bytes,start_epoch,end_epoch,keep)
3) --manifest    PERSim manifest (JSON/NDJSON/CSV)
   - Supports your schema:
     files[].out_target (absolute path)
     files[].regions[].actual.start/end (or requested.start/end)

Outputs (in --out-dir, default ./out_verify)
--------------------------------------------
- summary.csv  (per-file stats)
- misses.csv   (expected blocks not flagged)
- extras.csv   (flagged blocks outside expected)

Usage example
-------------
python verify_detection_vs_manifest.py \
  --suspicious /path/to/suspicious_regions.csv \
  --blockmap  /path/to/block_to_file.csv \
  --manifest  /path/to/persim_manifest.json \
  --epoch 3 \
  --file-prefix "/cloned-" \
  --default-prefix-bytes 4096 \
  --path-match basename \
  --out-dir out_verify
"""
import argparse
import json
import math
import os
from typing import Any, Dict, List, Optional, Tuple

import pandas as pd


def read_csv_flex(path: str) -> pd.DataFrame:
    """Read CSV tolerantly (keeps large ints as strings when needed)."""
    return pd.read_csv(path, dtype=str).apply(pd.to_numeric, errors="ignore")


def read_manifest(path: str) -> List[Dict[str, Any]]:
    """
    Read a PERSim manifest from CSV, JSON, or NDJSON.
    Returns a list of dict records (already flattened to file records if needed).
    """
    if not os.path.exists(path):
        raise FileNotFoundError(f"Manifest not found: {path}")

    _, ext = os.path.splitext(path.lower())

    if ext in (".json", ".ndjson", ".jsonl"):
        # Try NDJSON first
        records = []
        with open(path, "r", encoding="utf-8") as f:
            lines = f.read().strip().splitlines()
        is_ndjson = False
        for line in lines:
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
                is_ndjson = True
                records.append(obj)
            except json.JSONDecodeError:
                is_ndjson = False
                break
        if is_ndjson:
            out = []
            for obj in records:
                if isinstance(obj, dict) and "files" in obj and isinstance(obj["files"], list):
                    out.extend(obj["files"])
                else:
                    out.append(obj)
            return out

        # Single JSON (list or dict)
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        if isinstance(data, dict):
            if "files" in data and isinstance(data["files"], list):
                return data["files"]
            return [data]
        if isinstance(data, list):
            return data
        raise ValueError("Unrecognized JSON manifest structure.")

    # CSV fallback
    df = read_csv_flex(path)
    return df.to_dict(orient="records")


def _coerce_int(val: Any, default: int = 0) -> int:
    try:
        return int(val)
    except Exception:
        try:
            return int(float(val))
        except Exception:
            return default


def extract_expected_regions_from_record(
    rec: Dict[str, Any],
    default_prefix_bytes: int,
) -> List[Tuple[int, int]]:
    """
    Extract expected encrypted regions as list of (offset, length).

    Supports:
      - PERSim v1 style:
        rec["regions"] -> [{ "actual": {"start":S,"end":E}, ... }]; falls back to "requested".
      - Prefix fields: encrypted_prefix_bytes / prefix_bytes / header_bytes / first_n_bytes
      - Range fields:  encrypted_ranges / ranges / attack_ranges / encrypted_regions

    If nothing found, default to [(0, default_prefix_bytes)].
    """
    # PERSim regions
    if "regions" in rec and isinstance(rec["regions"], list):
        outs: List[Tuple[int, int]] = []
        for r in rec["regions"]:
            seg = None
            if isinstance(r, dict):
                if "actual" in r and isinstance(r["actual"], dict):
                    seg = r["actual"]
                elif "requested" in r and isinstance(r["requested"], dict):
                    seg = r["requested"]
            if seg and "start" in seg and "end" in seg:
                s = _coerce_int(seg["start"], 0)
                e = _coerce_int(seg["end"], 0)
                if e > s:
                    outs.append((s, e - s))
        if outs:
            return outs

    # Simple prefix
    for key in ["encrypted_prefix_bytes", "prefix_bytes", "header_bytes", "first_n_bytes"]:
        if key in rec and rec[key] not in (None, "", "NaN"):
            n = _coerce_int(rec[key], 0)
            if n > 0:
                return [(0, n)]

    # Generic ranges (array or JSON text)
    for key in ["encrypted_ranges", "ranges", "attack_ranges", "encrypted_regions"]:
        if key in rec and rec[key] not in (None, "", "NaN"):
            parsed = None
            val = rec[key]
            if isinstance(val, list):
                parsed = val
            elif isinstance(val, str):
                try:
                    parsed = json.loads(val)
                except Exception:
                    parts = [p.strip() for p in val.split(",") if p.strip()]
                    arr = []
                    ok = True
                    for p in parts:
                        if ":" in p:
                            a, b = p.split(":", 1)
                            arr.append([_coerce_int(a, 0), _coerce_int(b, 0)])
                        else:
                            ok = False
                            break
                    if ok and arr:
                        parsed = arr
            if parsed:
                outs: List[Tuple[int, int]] = []
                for item in parsed:
                    if isinstance(item, list) and len(item) >= 2:
                        offs, ln = _coerce_int(item[0], 0), _coerce_int(item[1], 0)
                        if ln > 0:
                            outs.append((offs, ln))
                    elif isinstance(item, dict):
                        offs, ln = _coerce_int(item.get("offset", 0), 0), _coerce_int(item.get("length", 0), 0)
                        if ln > 0:
                            outs.append((offs, ln))
                if outs:
                    return outs

    return [(0, default_prefix_bytes)]


def build_suspicious_block_sets(
    suspicious_df: pd.DataFrame,
    epoch: Optional[int] = None,
) -> Dict[int, set]:
    """
    Build a dict: extent_id -> set(block_id) that are suspicious at the given epoch.
    """
    required_cols = {"extent_id", "lba_start_block", "lba_end_block"}
    missing = required_cols - set(suspicious_df.columns)
    if missing:
        raise ValueError(f"suspicious_regions missing columns: {missing}")

    df = suspicious_df.copy()
    for col in ["extent_id", "lba_start_block", "lba_end_block", "start_epoch", "end_epoch"]:
        if col in df.columns:
            df[col] = pd.to_numeric(df[col], errors="coerce")

    if epoch is not None and "start_epoch" in df.columns and "end_epoch" in df.columns:
        df = df[(df["start_epoch"] == epoch) & (df["end_epoch"] == epoch)]

    out: Dict[int, set] = {}
    for extent, grp in df.groupby("extent_id"):
        s = set()
        starts = grp["lba_start_block"].astype("Int64").tolist()
        ends = grp["lba_end_block"].astype("Int64").tolist()
        for a, b in zip(starts, ends):
            if pd.isna(a) or pd.isna(b):
                continue
            a_i, b_i = int(a), int(b)
            if b_i < a_i:
                a_i, b_i = b_i, a_i
            s.update(range(a_i, b_i + 1))
        out[int(extent)] = s
    return out


def normalize_path_for_match(p: str) -> str:
    return os.path.normpath(str(p)).replace("\\", "/")


def basename(p: str) -> str:
    return os.path.basename(normalize_path_for_match(p))


def main():
    ap = argparse.ArgumentParser(description="Verify Rhea detection against PERSim manifest.")
    ap.add_argument("--suspicious", required=True, help="Path to suspicious regions CSV (detection output).")
    ap.add_argument("--blockmap", required=True, help="Path to block-to-file mapping CSV (detection output).")
    ap.add_argument("--manifest", required=True, help="Path to PERSim manifest (CSV/JSON/NDJSON).")
    ap.add_argument("--epoch", type=int, default=None, help="Epoch filter (e.g., 3). Applies to both inputs.")
    ap.add_argument("--file-prefix", default=None, help="Only evaluate files whose *blockmap* path startswith this (e.g., /cloned-).")
    ap.add_argument("--default-prefix-bytes", type=int, default=4096, help="Fallback prefix size when manifest lacks ranges.")
    ap.add_argument("--path-match", choices=["basename", "exact", "suffix"], default="basename",
                    help="How to match manifest out_target to blockmap file_path (default: basename).")
    ap.add_argument("--out-dir", default="out_verify", help="Directory to write summary/misses/extras CSVs.")
    args = ap.parse_args()

    os.makedirs(args.out_dir, exist_ok=True)

    # Load inputs
    susp = read_csv_flex(args.suspicious)
    b2f = read_csv_flex(args.blockmap)
    manifest_records = read_manifest(args.manifest)

    # Normalize blockmap dtypes
    for col in ["extent_id", "block_id", "offset_bytes", "start_epoch", "end_epoch"]:
        if col in b2f.columns:
            b2f[col] = pd.to_numeric(b2f[col], errors="coerce")

    # Filters on blockmap
    bm = b2f.copy()
    if args.epoch is not None and {"start_epoch", "end_epoch"} <= set(bm.columns):
        bm = bm[(bm["start_epoch"] == args.epoch) & (bm["end_epoch"] == args.epoch)]
    if args.file_prefix:
        bm = bm[bm["file_path"].astype(str).str.startswith(args.file_prefix)]

    # Suspicious sets by extent
    susp_sets = build_suspicious_block_sets(susp, epoch=args.epoch)

    # Pre-index blockmap
    bm["__norm_path"] = bm["file_path"].astype(str).map(normalize_path_for_match)
    bm["__base"] = bm["__norm_path"].map(basename)
    bm_by_norm: Dict[str, pd.DataFrame] = {fp: grp.copy() for fp, grp in bm.groupby("__norm_path")}
    bm_by_base: Dict[str, pd.DataFrame] = {fp: grp.copy() for fp, grp in bm.groupby("__base")}

    # Global set of suspicious (extent,block)
    suspicious_pairs = set()
    for extent, s in susp_sets.items():
        for blk in s:
            suspicious_pairs.add((int(extent), int(blk)))

    # Helper to select blockmap rows for a manifest path
    def select_blockmap_rows_for_manifest_fp(man_path: str) -> Optional[pd.DataFrame]:
        man_norm = normalize_path_for_match(man_path)
        man_base = basename(man_norm)

        if args.path_match == "exact":
            return bm_by_norm.get(man_norm)
        if args.path_match == "basename":
            hit = bm_by_base.get(man_base)
            if hit is not None:
                return hit
            return bm[bm["__base"] == man_base]
        if args.path_match == "suffix":
            suf = bm[bm["__norm_path"].apply(lambda s: man_norm.endswith(s))]
            return suf if not suf.empty else None
        return None

    # Build expected set per file (manifest out_target)
    expected_pairs_by_file: Dict[str, set] = {}
    for rec in manifest_records:
        fp = (rec.get("out_target")
              or rec.get("file_path")
              or rec.get("path")
              or rec.get("dst_path")
              or rec.get("dst"))
        if not fp:
            continue
        sub = select_blockmap_rows_for_manifest_fp(str(fp))
        if sub is None or sub.empty:
            continue

        # Extract expected regions
        regions = extract_expected_regions_from_record(rec, default_prefix_bytes=args.default_prefix_bytes)

        expected = set()
        for off, ln in regions:
            end_off = off + ln  # exclusive
            hit = sub[(sub["offset_bytes"] >= off) & (sub["offset_bytes"] < end_off)]
            for _, row in hit.iterrows():
                try:
                    expected.add((int(row["extent_id"]), int(row["block_id"])))
                except Exception:
                    continue

        key = basename(str(fp)) if args.path_match == "basename" else normalize_path_for_match(str(fp))
        expected_pairs_by_file[key] = expected

    # Also evaluate any remaining blockmap files (default prefix) that match file_prefix
    for base_key, sub in bm_by_base.items():
        if args.file_prefix and not any(sub["file_path"].astype(str).str.startswith(args.file_prefix)):
            continue
        key = base_key if args.path_match == "basename" else normalize_path_for_match(sub.iloc[0]["__norm_path"])
        if key in expected_pairs_by_file:
            continue
        end_off = args.default_prefix_bytes
        hit = sub[(sub["offset_bytes"] >= 0) & (sub["offset_bytes"] < end_off)]
        expected = set((int(r["extent_id"]), int(r["block_id"])) for _, r in hit.iterrows())
        expected_pairs_by_file[key] = expected

    # Compute metrics + rows
    summary_rows = []
    misses_rows = []
    extras_rows = []

    for key, expected_pairs in expected_pairs_by_file.items():
        # Get all flagged blocks for this file
        if args.path_match == "basename":
            sub = bm_by_base.get(key)
        elif args.path_match == "exact":
            sub = bm_by_norm.get(key)
        else:  # suffix
            sub = bm[bm["__norm_path"].apply(lambda s: key.endswith(s))]

        flagged_for_file = set()
        if sub is not None and not sub.empty:
            for _, r in sub.iterrows():
                pair = (int(r["extent_id"]), int(r["block_id"]))
                if pair in suspicious_pairs:
                    flagged_for_file.add(pair)

        tp = expected_pairs & suspicious_pairs
        extras = flagged_for_file - expected_pairs
        misses = expected_pairs - tp

        exp_count = len(expected_pairs)
        tp_count = len(tp)
        rec = tp_count / exp_count if exp_count > 0 else float("nan")
        prec_den = len(flagged_for_file) if flagged_for_file else 0
        prec = (tp_count / prec_den) if prec_den > 0 else float("nan")

        summary_rows.append({
            "file_key": key,
            "expected_blocks": exp_count,
            "flagged_in_expected": tp_count,
            "recall_on_expected": round(rec, 6) if not math.isnan(rec) else "",
            "flagged_total_for_file": len(flagged_for_file),
            "precision_like": round(prec, 6) if not math.isnan(prec) else "",
            "extras_flagged_outside_expected": len(extras),
            "misses_expected_not_flagged": len(misses),
        })

        for (e, b) in sorted(misses):
            misses_rows.append({"file_key": key, "extent_id": e, "block_id": b})
        for (e, b) in sorted(extras):
            extras_rows.append({"file_key": key, "extent_id": e, "block_id": b})

    # Write outputs
    os.makedirs(args.out_dir, exist_ok=True)
    summary_df = pd.DataFrame(summary_rows).sort_values("file_key")
    misses_df = pd.DataFrame(misses_rows).sort_values(["file_key", "extent_id", "block_id"])
    extras_df = pd.DataFrame(extras_rows).sort_values(["file_key", "extent_id", "block_id"])

    summary_path = os.path.join(args.out_dir, "summary.csv")
    misses_path = os.path.join(args.out_dir, "misses.csv")
    extras_path = os.path.join(args.out_dir, "extras.csv")

    summary_df.to_csv(summary_path, index=False)
    misses_df.to_csv(misses_path, index=False)
    extras_df.to_csv(extras_path, index=False)

    # Console report
    print(f"[ok] Wrote: {summary_path}")
    print(f"[ok] Wrote: {misses_path}")
    print(f"[ok] Wrote: {extras_path}")
    if not summary_df.empty:
        print("\nTop 15 summary rows:\n", summary_df.head(15).to_string(index=False))
        try:
            macro_recall = summary_df["recall_on_expected"].replace("", float("nan")).astype(float).mean(skipna=True)
            tot_files = len(summary_df)
            print(f"\n[totals] files={tot_files}  macro_recall={macro_recall:.4f}")
        except Exception:
            pass
    else:
        print("\n[warn] Empty summary (no matching files or inputs were empty).")


if __name__ == "__main__":
    main()
