from preprocessor.database import Database
from preprocessor.convert import list2str  # kept for compat (may be used elsewhere)
import pandas as pd
import os
import numpy as np
import argparse
import time
from typing import Tuple
from restorer.restore import pre_restore_device_snapshot

# =========================
# Global flags / singletons
# =========================

DEBUG = False
PROFILE = False
_db_instance = None

# -------------------------
# Utility: logging & timing
# -------------------------

def _ms(s: float) -> str:
    """Format seconds -> milliseconds string with 3 decimals."""
    return f"{s * 1000:.3f} ms"

def _info(msg: str):
    print(msg, flush=True)

# --------------------------------
# Database handle (singleton style)
# --------------------------------

def get_db(debug: bool = False):
    """
    Lazily instantiate (and share) the Database handle.
    - debug: print lifecycle messages.
    """
    global _db_instance
    if _db_instance is None:
        if debug:
            _info("[get_db] _db_instance is None. Instantiating a new Database object.")
        _db_instance = Database()
    else:
        if debug:
            _info("[get_db] _db_instance is NOT None. Skip instantiating a new Database object.")
    return _db_instance

# --------------------------------------------
# Core: persist per-epoch mutation & bitmap IO
# --------------------------------------------

def _epoch_outputs(path: str, epoch: int) -> Tuple[str, str]:
    """Return (mutation_parquet_path, bitmap_bin_path) for convenience."""
    return (
        os.path.join(path, f"mutation_{epoch}.parquet"),
        os.path.join(path, f"bitmap_{epoch}.bin"),
    )

def save_epoch(path: str, epoch: int, debug: bool = False, profile: bool = False):
    """
    Fetch all mutated blocks for a given epoch and save:
      - Parquet: mutation_{epoch}.parquet with schema:
            id: int          (block id)
            block: List[int] (block contents, list of bytes/ints)
            epoch: int
      - Binary: bitmap_{epoch}.bin (np.packbits of the 0/1 dirty bitmap; MSB-first per numpy)
    - debug: enables asserts and extra prints.
    - profile: prints fine-grained timing info for each stage.
    """
    if debug:
        _info(f"[save_epoch] path={path}, epoch={epoch}, debug={debug}, profile={profile}")

    t0 = time.perf_counter() if profile else 0.0

    db = get_db(debug)
    data = db.item_by_epoch(epoch)
    if debug:
        _info(f"[save_epoch] Retrieved {len(data)} items for epoch {epoch}")

    t1 = time.perf_counter() if profile else 0.0

    # Prepare DataFrame rows (robust to empty)
    rows = []
    for idx, item in enumerate(data):
        try:
            # item["key"] is expected like "block:<id>"
            _, block_id = item["key"].split(":")
            # Convert to list[int] explicitly (defensive)
            block = [int(x) for x in item["value"].value]
            rows.append({"id": int(block_id), "block": block})
            if debug and idx < 5:
                _info(f"[save_epoch][debug] Example row {idx}: id={block_id}, block[:4]={block[:4]}...")
        except Exception as e:
            if debug:
                _info(f"[save_epoch][debug] Error processing item {idx}: {e}")
            # Re-raise to make failures visible to callers/tests
            raise

    t2 = time.perf_counter() if profile else 0.0

    # Even if empty, write an *empty* parquet with the expected schema for downstream stability
    df = pd.DataFrame(rows, columns=["id", "block"])
    df["epoch"] = int(epoch)
    mut_out = os.path.join(path, f"mutation_{epoch}.parquet")
    df.to_parquet(mut_out, index=False)
    _info(f"[save_epoch] Mutation snapshot saved to {mut_out} (rows={len(df)})")

    t3 = time.perf_counter() if profile else 0.0
    if profile:
        _info(f"[Profile] DataFrame prep: {_ms(t2 - t1)} | Parquet write: {_ms(t3 - t2)}")

    # Save bitmap as packbits binary
    bitmap = db.item_bitmap(int(epoch))
    if debug:
        preview = bitmap[:8] if len(bitmap) >= 8 else bitmap
        _info(f"[save_epoch] Bitmap length: {len(bitmap)}; sample: {preview}")

    # Optional sanity: ensure bitmap covers max mutated id
    if debug and len(rows) > 0:
        max_block_id = max(row["id"] for row in rows)
        assert len(bitmap) >= max_block_id + 1, f"Bitmap too short: {len(bitmap)} vs {max_block_id + 1}"

    bitmap_bytes = np.packbits(np.array(bitmap, dtype=np.uint8))
    bmp_out = os.path.join(path, f"bitmap_{epoch}.bin")
    with open(bmp_out, "wb") as f:
        f.write(bitmap_bytes)
    _info(f"[save_epoch] Dirty bitmap saved to {bmp_out} (bytes={len(bitmap_bytes)})")

    if profile:
        t4 = time.perf_counter()
        _info(f"[Profile] Bitmap fetch/pack/write: {_ms(t4 - t3)}")
        _info(f"[Profile] Total save_epoch time: {_ms(t4 - t0)}")

# ----------------------------------------------------
# Incremental materialization 1..end (default behavior)
# ----------------------------------------------------

def materialize_epochs_incremental(
    path: str,
    end_epoch: int,
    *,
    debug: bool = False,
    profile: bool = False,
    force_overwrite: bool = False,
):
    """
    Persist epochs in [1..end_epoch] to `path`.

    - If force_overwrite is False (default): skip an epoch when BOTH outputs exist:
        mutation_<ep>.parquet AND bitmap_<ep>.bin.
      If either is missing, (re)write the epoch to ensure consistency.

    - If force_overwrite is True: rewrite all epochs 1..end (fresh snapshots).
    """
    created = 0
    skipped = 0

    if debug:
        mode = "force-overwrite" if force_overwrite else "incremental"
        _info(f"[materialize] Begin 1..{end_epoch} ({mode}) into {path}")

    for ep in range(1, end_epoch + 1):
        mut_p, bmp_p = _epoch_outputs(path, ep)
        have_mut = os.path.exists(mut_p)
        have_bmp = os.path.exists(bmp_p)

        if not force_overwrite and have_mut and have_bmp:
            skipped += 1
            if debug:
                _info(f"[materialize][skip] epoch {ep} (both outputs already present)")
            continue

        t_ep0 = time.perf_counter() if profile else 0.0
        save_epoch(path, ep, debug=debug, profile=profile)
        if profile:
            _info(f"[Profile] save_epoch total (epoch {ep}): {_ms(time.perf_counter() - t_ep0)}")
        created += 1

    _info(f"[materialize] Summary: created={created}, skipped={skipped}, total={end_epoch}")

# ----------------
# CLI arg parsing
# ----------------

def parse_args():
    parser = argparse.ArgumentParser(description="Rhea Preprocessor Runner (incremental 1..N)")
    # Single-parameter API (window removed): process 1..end
    parser.add_argument("--end-epoch", type=int,
                        help="End epoch (inclusive) for this run. Required unless --epoch is provided.")
    # Backward-compat alias: --epoch (maps to --end-epoch)
    parser.add_argument("--epoch", type=int, help=argparse.SUPPRESS)

    parser.add_argument("--output", type=str, required=True,
                        help="Output directory for mutation snapshots and bitmaps")
    parser.add_argument("--device-size", type=int, required=True,
                        help="Size (in bytes) for the reconstructed device image")
    parser.add_argument("--debug", action="store_true",
                        help="Enable debug mode (asserts, extra prints)")
    parser.add_argument("--profile", action="store_true",
                        help="Enable profiling mode (fine-grained timing)")

    # Behavior controls
    parser.add_argument("--skip-restore", action="store_true",
                        help="Do not reconstruct the device image as of end_epoch")
    parser.add_argument("--force-overwrite", action="store_true",
                        help="Rebuild snapshots for ALL epochs 1..end (ignore any existing files)")

    return parser.parse_args()

# ----
# Main
# ----

def main():
    global DEBUG, PROFILE
    args = parse_args()
    DEBUG = args.debug
    PROFILE = args.profile

    # Backward-compat: --epoch -> --end-epoch
    end_epoch = args.end_epoch if args.end_epoch is not None else args.epoch
    if end_epoch is None:
        raise SystemExit("You must provide --end-epoch (or legacy --epoch).")
    if end_epoch < 1:
        raise SystemExit(f"Invalid end epoch: {end_epoch}")

    os.makedirs(args.output, exist_ok=True)

    _info(f"[Preprocessor] Processing epochs 1..{end_epoch} (inclusive)")
    _info(f"[Preprocessor] Output dir: {args.output}")
    if DEBUG:
        _info("[Preprocessor] Debug mode enabled.")
    if PROFILE:
        _info("[Preprocessor] Profiling mode enabled.")

    t0 = time.perf_counter()

    # 1) Persist 1..end_epoch incrementally (skip epochs already materialized)
    materialize_epochs_incremental(
        args.output,
        end_epoch,
        debug=DEBUG,
        profile=PROFILE,
        force_overwrite=args.force_overwrite,
    )

    # 2) Reconstruct device image as of end_epoch (apply 1..end); detector can still use parquet-only baseline.
    if not args.skip_restore:
        t_r0 = time.perf_counter() if PROFILE else 0.0
        pre_restore_device_snapshot(
            epoch=end_epoch,
            size=args.device_size,
            directory=args.output,
            debug=DEBUG,
            profile=PROFILE
        )
        if PROFILE:
            _info(f"[Profile] restore_device_snapshot_image_file: {_ms(time.perf_counter() - t_r0)}")

    # 3) Done
    t1 = time.perf_counter()
    _info(f"[Preprocessor] Done. Total time taken: {_ms(t1 - t0)}")

if __name__ == "__main__":
    main()
