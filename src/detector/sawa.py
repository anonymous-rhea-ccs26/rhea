#!/usr/bin/env python3
"""
sawa.py: Sliding Adaptive Window Analysis

Usage:
    python sawa.py <delta_snapshots.csv> [output_suspicious.csv]

- <delta_snapshots.csv>: CSV written by your delta snapshot pipeline
- [output_suspicious.csv]: (Optional) Output CSV for suspicious regions (default: suspicious_regions.csv)

The script will print detected suspicious regions and output them to the specified CSV file.
"""

import sys
import csv
import base64
import uuid
import json
import numpy as np


# Import DeltaBlock, DeltaExtent from your shared common repo
from detector.delta_types import DeltaBlock, DeltaExtent, SuspiciousRegion

try:
    from numba import njit
    _HAVE_NUMBA = True
except Exception:
    _HAVE_NUMBA = False

if _HAVE_NUMBA:
    @njit(cache=True)
    def chi2_from_counts_numba(counts, W):
        sumsq = 0.0
        for i in range(256):
            c = counts[i]
            sumsq += c * c
        return 256.0 * (sumsq / W) - W

    @njit(cache=True)
    def bincount256_numba(buf):
        counts = np.zeros(256, dtype=np.int64)
        for b in buf:
            counts[b] += 1
        return counts


def as_uint8_array(data) -> np.ndarray:
    """
    Convert bytes/bytearray/memoryview/list/ndarray to a NumPy uint8 array.
    - Uses zero-copy views for bytes/bytearray/memoryview and already-uint8 arrays.
    - Falls back to np.asarray(..., dtype=np.uint8) which may copy if needed (NumPy 2 safe).
    """
    if isinstance(data, (bytes, bytearray)):
        return np.frombuffer(data, dtype=np.uint8)            # zero-copy view
    if isinstance(data, memoryview):
        return np.frombuffer(data, dtype=np.uint8)            # zero-copy view
    if isinstance(data, np.ndarray):
        return data if data.dtype == np.uint8 else data.astype(np.uint8, copy=False)
    # NumPy 2.0: prefer asarray (no “copy=False” hard requirement)
    return np.asarray(data, dtype=np.uint8)

# --- replace chi2_entropy with this ---
def chi2_entropy_fast(arr_view: np.ndarray) -> float:
    # arr_view: np.uint8 1-D view (NO Python bytes here)
    n = arr_view.size
    if n == 0:
        return 0.0
    # bincount on a VIEW is fine; far cheaper than bytes->array every time
    counts = np.bincount(arr_view, minlength=256)
    # sum of squares of counts
    sumsq = np.dot(counts, counts)  # (counts*counts).sum() is also fine
    # χ² = 256 * (sumsq / n) - n
    return (256.0 * (sumsq / n)) - n

# NOTE: the old seeds_below_threshold() helpers are removed. We’ll scan adaptively
# inside sliding_adaptive_window_analysis() and, on a hit, jump past the accepted
# window to avoid re-seeding within the same region.

def _var_over_large(chi2_vals, widths, min_width):
    """
    Return population variance of chi2_vals, but only using entries whose
    corresponding window width >= min_width. If fewer than 2 such entries
    exist, fall back to using the full series (or 0.0 if length < 2).
    """
    import numpy as _np
    use = [c for c, w in zip(chi2_vals, widths) if w >= min_width]
    if len(use) >= 2:
        x = _np.array(use, dtype=_np.float64)
        return float(x.var(ddof=0))
    # fallback
    if len(chi2_vals) >= 2:
        x = _np.array(chi2_vals, dtype=_np.float64)
        return float(x.var(ddof=0))
    return 0.0

# --- NEW: fixed-window version without any expansion/maximization ---
def sliding_fixed_window_analysis(
        delta_blocks, *,
        extent_id: int,
        width: int = 16,
        stride: int = 8,
        chi2_threshold: float = 350,
        block_size: int = 512,
        debug: bool = False,
        profile: bool = False,
        passthrough_small: bool = True,
):
    """
    Fixed-window SAWA (no expansion):
      - Slides a single window of length `width` by `stride`.
      - If χ² <= threshold, emits that window as a region.
      - No doubling or maximization, so `chi2_var` is 0.0 and
        min/max/final are the same (the seed value).
      - For tiny deltas (< width), optionally pass through so file-aware can decide.
    Output schema matches sliding_adaptive_window_analysis.
    """
    stride = max(1, int(stride))
    suspicious_regions = []

    for db in delta_blocks:
        data_arr = as_uint8_array(db.f_diff)
        data_len = data_arr.size
        # Base device offset of first changed byte (for debug and absolute calc)
        first_block_id = db.block_ids[0] if db.block_ids else 0
        base_abs = first_block_id * block_size + (db.start_offset or 0)

        # Tiny deltas: optional pass-through region [0, data_len)
        if data_len < width:
            if debug:
                print(f"[SAWA-fixed][DB {db.delta_block_id}] "
                      f"{'pass-through' if passthrough_small else 'skip'} tiny delta: {data_len} < width={width}")
            if passthrough_small and data_len > 0:
                start, end = 0, data_len  # bytes within db.f_diff (exclusive end)
                base_off = int(db.start_offset or 0)
                A = base_off + start
                B = base_off + (end - 1)

                block_idx_start = A // block_size
                block_idx_end   = B // block_size
                if db.block_ids:
                    block_idx_start = max(0, min(block_idx_start, len(db.block_ids) - 1))
                    block_idx_end   = max(0, min(block_idx_end,   len(db.block_ids) - 1))

                first_block_offset = A % block_size
                last_block_offset  = B % block_size

                covered_block_ids = (db.block_ids[block_idx_start:block_idx_end + 1]
                                     if db.block_ids and block_idx_start <= block_idx_end else [])
                lba_start_block = db.block_ids[block_idx_start] if covered_block_ids else None
                lba_end_block   = db.block_ids[block_idx_end]   if covered_block_ids else None
                byte_start = (lba_start_block * block_size + first_block_offset) if lba_start_block is not None else None
                byte_end_inclusive = (lba_end_block * block_size + last_block_offset) if lba_end_block is not None else None

                suspicious_regions.append(SuspiciousRegion(
                    extent_id=extent_id,
                    delta_block_id=db.delta_block_id,
                    block_ids=covered_block_ids,
                    start_offset=first_block_offset,
                    end_offset=last_block_offset,
                    block_idx_start=block_idx_start,
                    block_idx_end=block_idx_end,
                    lba_start_block=lba_start_block,
                    lba_end_block=lba_end_block,
                    byte_start=byte_start,
                    byte_end_inclusive=byte_end_inclusive,
                    chi2_min=0.0, chi2_max=0.0, chi2_var=0.0, chi2_final=0.0,
                ))
            continue

        # Main fixed-window scan
        pos = 0
        while pos + width <= data_len:
            view = data_arr[pos:pos + width]
            if _HAVE_NUMBA:
                c = bincount256_numba(view)
                chi2 = float(chi2_from_counts_numba(c, width))
            else:
                chi2 = float(chi2_entropy_fast(view))

            if chi2 <= chi2_threshold:
                # Map [pos, pos+width) back to device coords
                start, end = pos, pos + width
                base_off = int(db.start_offset or 0)
                A = base_off + start
                B = base_off + (end - 1)

                block_idx_start = A // block_size
                block_idx_end   = B // block_size
                if db.block_ids:
                    block_idx_start = max(0, min(block_idx_start, len(db.block_ids) - 1))
                    block_idx_end   = max(0, min(block_idx_end,   len(db.block_ids) - 1))

                first_block_offset = A % block_size
                last_block_offset  = B % block_size

                covered_block_ids = (db.block_ids[block_idx_start:block_idx_end + 1]
                                     if db.block_ids and block_idx_start <= block_idx_end else [])
                lba_start_block = db.block_ids[block_idx_start] if covered_block_ids else None
                lba_end_block   = db.block_ids[block_idx_end]   if covered_block_ids else None
                byte_start = (lba_start_block * block_size + first_block_offset) if lba_start_block is not None else None
                byte_end_inclusive = (lba_end_block * block_size + last_block_offset) if lba_end_block is not None else None

                suspicious_regions.append(SuspiciousRegion(
                    extent_id=extent_id,
                    delta_block_id=db.delta_block_id,
                    block_ids=covered_block_ids,
                    start_offset=first_block_offset,
                    end_offset=last_block_offset,
                    block_idx_start=block_idx_start,
                    block_idx_end=block_idx_end,
                    lba_start_block=lba_start_block,
                    lba_end_block=lba_end_block,
                    byte_start=byte_start,
                    byte_end_inclusive=byte_end_inclusive,
                    chi2_min=chi2,
                    chi2_max=chi2,
                    chi2_var=0.0,
                    chi2_final=chi2,
                ))

                if debug:
                    abs_start = base_abs + start
                    abs_end   = base_abs + end - 1
                    print(f"[SAWA-fixed] ACCEPT abs=[{abs_start}..{abs_end}] "
                          f"w={width} chi2={chi2:.3f}")

                # Jump past the accepted window (avoid reseeding within it)
                pos = end
            else:
                pos += stride

        # Tail pass-through (optional): leftover < width bytes at the end
        if passthrough_small and pos < data_len and (data_len - pos) > 0 and (data_len - pos) < width:
            start, end = pos, data_len
            base_off = int(db.start_offset or 0)
            A = base_off + start
            B = base_off + (end - 1)

            block_idx_start = A // block_size
            block_idx_end   = B // block_size
            if db.block_ids:
                block_idx_start = max(0, min(block_idx_start, len(db.block_ids) - 1))
                block_idx_end   = max(0, min(block_idx_end,   len(db.block_ids) - 1))

            first_block_offset = A % block_size
            last_block_offset  = B % block_size

            covered_block_ids = (db.block_ids[block_idx_start:block_idx_end + 1]
                                 if db.block_ids and block_idx_start <= block_idx_end else [])
            lba_start_block = db.block_ids[block_idx_start] if covered_block_ids else None
            lba_end_block   = db.block_ids[block_idx_end]   if covered_block_ids else None
            byte_start = (lba_start_block * block_size + first_block_offset) if lba_start_block is not None else None
            byte_end_inclusive = (lba_end_block * block_size + last_block_offset) if lba_end_block is not None else None

            suspicious_regions.append(SuspiciousRegion(
                extent_id=extent_id,
                delta_block_id=db.delta_block_id,
                block_ids=covered_block_ids,
                start_offset=first_block_offset,
                end_offset=last_block_offset,
                block_idx_start=block_idx_start,
                block_idx_end=block_idx_end,
                lba_start_block=lba_start_block,
                lba_end_block=lba_end_block,
                byte_start=byte_start,
                byte_end_inclusive=byte_end_inclusive,
                chi2_min=0.0, chi2_max=0.0, chi2_var=0.0, chi2_final=0.0,
            ))

    return suspicious_regions


def sliding_adaptive_window_analysis(
        delta_blocks, *,
        extent_id,
        width=16,
        stride=8,
        chi2_threshold=350,
        block_size=512,
        min_expansions=0,
        max_chi2_var=3000,
        debug=False,
        profile=False,
        var_min_width=512,   # NEW: only windows >= this size are used in the variance gate
        passthrough_small=True,  # NEW: emit tiny delta blocks (< width) so fileaware can decide
):
    """
    Sliding Adaptive Window Analysis (SAWA)
    --------------------------------------

    PURPOSE
    -------
    Given a list of DeltaBlock objects (byte diffs inside one extent), scan the
    changed bytes at *byte* granularity to find "near-uniform" regions (typical
    of encryption/compression) using a χ² statistic over 256-byte symbols.

    High level:
      1) Convert the delta bytes to a NumPy uint8 view.
      2) Seed scan: run a sliding window (width bytes, step=stride) and record
         *only* those seed windows whose χ² <= chi2_threshold.
      3) For each seed, repeatedly double the window size (power-of-two
         expansion) as long as χ² <= threshold; require at least min_expansions
         successful doublings.
      4) Starting from the largest power-of-two size that passed, *maximize*
         the window (binary/greedy search in bytes) under two constraints:
           - χ²(window) <= chi2_threshold
           - variance of the χ² series (seed + expansions + final candidate)
             <= max_chi2_var (keeps the curve "flat"/stable).
         NEW: For the stability gate, compute the variance using only those
              stages whose window size >= `var_min_width` (default: 512 B).
              If fewer than 2 such stages exist, fall back to the full series.
      5) Map the final byte window back to:
           - covered block indices within db.block_ids
           - in-block byte offsets (first & last blocks)
           - absolute device LBAs and byte offsets
      6) Emit a SuspiciousRegion for each accepted window.

    IMPORTANT SEMANTICS
    -------------------
    - `width` and `stride` are **bytes** (NOT blocks).
    - All scanning, expansion, and maximization are performed in **bytes**.
    - `block_size` is used **only** when mapping a chosen byte window to
      (block_idx_start/end) and in-block offsets (first/last_block_offset).

    PARAMETERS
    ----------
    delta_blocks : Iterable[DeltaBlock]
        Each DeltaBlock carries:
          - f_diff: the changed bytes (list[int] or bytes)
          - block_ids: the sequence of *device block IDs* (LBAs) that the
            aggregated data spans, in order
          - start_offset / end_offset: byte offsets within the first/last block
    extent_id : int
        Logical extent identifier (carried through to outputs).
    width : int (bytes)
        Initial seed window length in BYTES.
    stride : int (bytes)
        Sliding step in BYTES for seed search and during some shrink/expand steps.
    chi2_threshold : float
        Upper bound for the χ² statistic that qualifies a window as "uniform".
    block_size : int (bytes)
        Size of a *device block* used to compute block indices and in-block offsets.
    min_expansions : int
        Minimum number of successful **doublings** after the seed (e.g., 2 means:
        width→2*width→4*width all pass) before we attempt maximization.
    max_chi2_var : float
        Upper bound on the variance of chi2 across expansion+final for the window.
        (Population variance in *raw* χ² units.)
    var_min_width : int
        Only stages with window >= this size are used for the variance gate.
        If fewer than 2 such stages exist, fall back to variance over the full
        chi2 series (or 0.0 if series length < 2).
    debug, profile : bool
        Optional verbosity flags (debug prints within expansion/maximization).

    RETURNS
    -------
    List[SuspiciousRegion]

    FIXES: Adaptive seeding (jump past accepted window) and cross-block growth.
        Each region includes:
          - covered block IDs (`block_ids`)
          - in-block byte offsets (`first_block_offset`, `last_block_offset`)
          - absolute LBA range (`lba_start_block`, `lba_end_block`)
          - absolute device bytes (`byte_start`, `byte_end_inclusive`)
          - χ² diagnostics (min/max/var/final)

    NOTES ON PERFORMANCE
    --------------------
    - We convert to an np.uint8 *view* once per DeltaBlock (zero-copy for bytes).
    - Seed scan uses a rolling histogram (bincount update) to avoid re-counting.
    - If numba is available, χ² for expansions is accelerated.
    """
    # Safety: never allow a zero/negative stride (would cause an infinite loop)
    stride = max(1, int(stride))

    if debug:
        print(f"[SAWA] ===== Extent {extent_id} =====")
        print(f"[SAWA] params: width={width} stride={stride} chi2_thr={chi2_threshold} "
              f"min_exp={min_expansions} max_var={max_chi2_var} var_min_w={var_min_width} "
              f"block_size={block_size}")

    suspicious_regions = []

    # Local helper to compute population variance over large stages, with fallback.
    def _var_over_large(chi2_vals, widths, min_width):
        import numpy as _np
        use = [c for c, w in zip(chi2_vals, widths) if w >= min_width]
        if len(use) >= 2:
            x = _np.array(use, dtype=_np.float64)
            return float(x.var(ddof=0))
        # fallback to full series if large-stage coverage is too small
        if len(chi2_vals) >= 2:
            x = _np.array(chi2_vals, dtype=_np.float64)
            return float(x.var(ddof=0))
        return 0.0

    for db in delta_blocks:
        # Compute some debug context up-front
        first_block_id = db.block_ids[0] if db.block_ids else 0
        block_offset_in_file = first_block_id * block_size + (db.start_offset or 0)
        if debug:
            last_block_id = db.block_ids[-1] if db.block_ids else None
            # Heuristic absolute end (best effort): we only know the changed byte count inside this block
            _nbytes = len(as_uint8_array(db.f_diff))
            abs_end_excl = block_offset_in_file + _nbytes
            ids_preview = (db.block_ids[:3] if len(db.block_ids) <= 6
                           else db.block_ids[:3] + ["…"] + db.block_ids[-2:])
            print(f"[SAWA][DB] delta_block_id={db.delta_block_id} "
                  f"abs_base={block_offset_in_file} abs_end_excl~={abs_end_excl} "
                  f"bytes={_nbytes} start_off={db.start_offset} end_off={db.end_offset} "
                  f"block_ids={ids_preview}")

        # 1) Prepare data as a 1-D np.uint8 array (zero-copy for bytes/bytearray/memoryview)
        data = db.f_diff
        data_arr = as_uint8_array(data)         # byte-level view
        data_len = data_arr.size
        if data_len < width:
            # Not enough bytes for a seed window.
            # If passthrough_small, emit a minimal suspicious region to defer decision to file-aware.
            if debug:
                print(f"[SAWA][DB] {'pass-through' if passthrough_small else 'skip'}: "
                      f"data_len={data_len} < width={width}")
            if not passthrough_small or data_len == 0:
                continue

            # Map the tiny byte span [0, data_len) back to device blocks using base-offset–aware math.
            start = 0
            end = data_len  # exclusive
            base_off = int(db.start_offset or 0)
            A = base_off + start                 # absolute in-block byte within first db block
            B = base_off + (end - 1)             # absolute in-block byte within last  db block

            block_idx_start = A // block_size
            block_idx_end   = B // block_size
            # Clamp to db.block_ids length
            if db.block_ids:
                block_idx_start = max(0, min(block_idx_start, len(db.block_ids) - 1))
                block_idx_end   = max(0, min(block_idx_end,   len(db.block_ids) - 1))

            first_block_offset = A % block_size
            last_block_offset  = B % block_size

            covered_block_ids = (db.block_ids[block_idx_start:block_idx_end + 1]
                                 if db.block_ids and block_idx_start <= block_idx_end else [])

            lba_start_block = db.block_ids[block_idx_start] if covered_block_ids else None
            lba_end_block   = db.block_ids[block_idx_end]   if covered_block_ids else None

            byte_start = (lba_start_block * block_size + first_block_offset) if lba_start_block is not None else None
            byte_end_inclusive = (lba_end_block * block_size + last_block_offset) if lba_end_block is not None else None

            suspicious_regions.append(SuspiciousRegion(
                extent_id=extent_id,
                delta_block_id=db.delta_block_id,
                block_ids=covered_block_ids,
                start_offset=first_block_offset,
                end_offset=last_block_offset,
                block_idx_start=block_idx_start,
                block_idx_end=block_idx_end,
                lba_start_block=lba_start_block,
                lba_end_block=lba_end_block,
                byte_start=byte_start,
                byte_end_inclusive=byte_end_inclusive,
                # Diagnostics (not meaningful for tiny spans, but keep schema stable)
                chi2_min=0.0,
                chi2_max=0.0,
                chi2_var=0.0,
                chi2_final=0.0,
            ))
            if debug:
                abs_start = (db.block_ids[0] * block_size + (db.start_offset or 0)) if db.block_ids else None
                if abs_start is not None:
                    abs_end_incl = abs_start + (data_len - 1)
                    print(f"[SAWA] ACCEPT (pass-through small) abs=[{abs_start}..{abs_end_incl}] "
                          f"bytes={data_len} blocks={covered_block_ids[:3]}{'…' if len(covered_block_ids)>3 else ''} "
                          f"blk_idx=[{block_idx_start}..{block_idx_end}]")
            # Done with this tiny DeltaBlock; move to next DB
            continue

        # Throttle noisy "seed fail" logging: only every 4 KiB
        _seed_fail_log_period = 4096
        _last_fail_log_abs = None
        
        # Absolute device byte offset of the first changed byte (debug only)
        first_block_id = db.block_ids[0] if db.block_ids else 0
        block_offset_in_file = first_block_id * block_size + (db.start_offset or 0)

        # 2) Adaptive seed scan in BYTES:
        #    - if a seed passes, expand/maximize and then JUMP to end+1
        #    - if it fails, advance by stride
        pos = 0
        while pos + width <= data_len:
            seed_view = data_arr[pos:pos + width]
            chi2_seed = (chi2_entropy_fast(seed_view) if not _HAVE_NUMBA
                         else chi2_from_counts_numba(bincount256_numba(seed_view), width))
            abs_seed = block_offset_in_file + pos
            if chi2_seed > chi2_threshold:
                if debug:
                    if (_last_fail_log_abs is None) or (abs_seed - _last_fail_log_abs >= _seed_fail_log_period):
                        print(f"[SAWA] seed fail @pos={pos} abs={abs_seed} "
                              f"w={width} chi2={chi2_seed:.3f} > thr={chi2_threshold}")
                        _last_fail_log_abs = abs_seed
                pos += stride
                continue

            # Seed accepted → expand and maximize from this pos
            cur_width = width
            start = pos
            if debug:
                print(f"[SAWA] SEED OK  @pos={start} abs={abs_seed} "
                      f"w={width} chi2={chi2_seed:.3f} (thr={chi2_threshold})")

            # 3) Power-of-two expansion in BYTES: width -> 2*width -> 4*width ...
            chi2_series = [float(chi2_seed)]
            width_series = [int(cur_width)]
            expansions = 0
            while pos + cur_width * 2 <= data_len:
                cand_w = cur_width * 2
                cand_view = data_arr[pos:pos + cand_w]
                if _HAVE_NUMBA:
                    counts = bincount256_numba(cand_view)
                    chi2_big = chi2_from_counts_numba(counts, cand_w)
                else:
                    chi2_big = chi2_entropy_fast(cand_view)
                if debug:
                    print(f"[SAWA] expand? abs={abs_seed} w={cand_w} chi2={chi2_big:.3f} thr={chi2_threshold}")
                if chi2_big <= chi2_threshold:
                    cur_width = cand_w
                    expansions += 1
                    chi2_series.append(float(chi2_big))
                    width_series.append(int(cur_width))
                else:
                    break

            # Require at least `min_expansions` successful doublings
            if expansions < min_expansions:
                if debug:
                    print(f"[SAWA] REJECT (expansions) abs={abs_seed} "
                          f"got={expansions} < min_expansions={min_expansions}")
                # move on; do NOT jump, since we didn't accept a region
                pos += stride
                continue

            # Keep min/max to report; final candidate will be added later for var calc
            chi2_min = float(np.min(chi2_series))
            chi2_max = float(np.max(chi2_series))

            # 4) Maximize under constraints (still in BYTES).
            #    Starting from base_w (= largest power-of-two), try to grow as large as possible while keeping:
            #      - χ² <= chi2_threshold
            #      - variance(chi2 over stages with width >= var_min_width) <= max_chi2_var
            def feasible(w: int):
                """Check χ² + variance constraint for a window of length w bytes."""
                if _HAVE_NUMBA:
                    counts = bincount256_numba(data_arr[pos:pos + w])
                    ch = float(chi2_from_counts_numba(counts, w))
                else:
                    ch = float(chi2_entropy_fast(data_arr[pos:pos + w]))
                var_large = _var_over_large(chi2_series + [ch], width_series + [w], var_min_width)
                ok = (ch <= chi2_threshold) and (var_large <= max_chi2_var)
                return ok, ch, var_large

            max_possible = data_len - pos                    # max window length we can take from pos
            base_w = cur_width                               # largest power-of-two that passed
            ok, ch, var_f = feasible(base_w)

            if not ok:
                # Very rare: the power-of-two baseline violates variance when rechecked.
                # Try to shrink (first halving to >= width, then step down by stride) until feasible.
                if debug:
                    print(f"[SAWA] baseline infeasible abs={abs_seed} w={base_w} "
                          f"chi2={ch:.3f} thr={chi2_threshold} var={var_f:.3f} max_var={max_chi2_var} -> shrink")
                w = base_w
                # coarse shrink by halving
                while w > width:
                    w_next = max(width, w // 2)
                    ok2, ch2, var2 = feasible(w_next)
                    if ok2:
                        w = w_next
                        ch, var_f = ch2, var2
                        break
                    if w_next == w:  # safety
                        break
                    w = w_next
                # fine shrink by `stride` if still infeasible
                while not ok and w > width:
                    w = max(width, w - stride)
                    ok, ch, var_f = feasible(w)
                if not ok:
                    # Could not make it feasible
                    if debug:
                        print(f"[SAWA] REJECT (feasible fail) abs={abs_seed} "
                              f"final_try_w={w} chi2={ch:.3f} var={var_f:.3f}")
                    # IMPORTANT: advance before continuing to avoid re-checking same pos forever
                    pos += stride
                    continue
                cur_width = w
            else:
                # Binary/greedy search to grow window as far as feasible.
                # IMPORTANT: do NOT jump by `stride` here, or we can skip the true max near the top end.
                low = base_w
                high = max_possible
                best_w, best_ch, best_var = low, ch, var_f
                while low <= high:
                    mid = (low + high) // 2
                    okm, chm, varm = feasible(mid)
                    if debug:
                        print(f"[SAWA] maximize abs={abs_seed} try_w={mid} "
                              f"ok={okm} chi2={chm:.3f} var={varm:.3f}")
                    if okm:
                        best_w, best_ch, best_var = mid, chm, varm
                        low = mid + 1      # standard binary-search step
                    else:
                        high = mid - 1     # standard binary-search step

                # FINAL STRETCH: linearly probe beyond best_w to the hard end, 1 byte at a time.
                # This prevents off-by-one/rounding leaving feasible bytes on the table (e.g., 719 -> 726).
                w = best_w
                while w < max_possible:
                    ok_more, ch_more, var_more = feasible(w + 1)
                    if not ok_more:
                        break
                    w, best_ch, best_var = w + 1, ch_more, var_more
                cur_width, ch, var_f = w, best_ch, best_var

            # Double-check final constraints
            end = pos + cur_width                              # byte end (exclusive) within db.f_diff
            chi2_final = float(ch)
            chi2_var_full = float(var_f)
            if not (chi2_final <= chi2_threshold and chi2_var_full <= max_chi2_var):
                # Extremely defensive; should already be enforced by feasible()
                if debug:
                    print(f"[SAWA] REJECT (final gate) abs={abs_seed} "
                          f"w={cur_width} chi2={chi2_final:.3f}/{chi2_threshold} "
                          f"var={chi2_var_full:.3f}/{max_chi2_var}")
                pos += stride
                continue

            # 5) Map the final BYTE window [start, end) back to device blocks.
            #    This is the *only* place where we touch block math.
            #    All indices below are w.r.t. db.block_ids, which list the LBAs covered by this delta.
            start = pos
            # --- USE BASE-OFFSET–AWARE (FIX) MAPPING ---
            base_off = int(db.start_offset or 0)
            A = base_off + start            # first in-block byte (absolute within the first db block)
            B = base_off + (end - 1)        # last  in-block byte (absolute within the last  db block)

            block_idx_start = A // block_size
            block_idx_end   = B // block_size
            first_block_offset = A % block_size
            last_block_offset  = B % block_size

            # Clamp defensively in case of any rounding drift
            if db.block_ids:
                block_idx_start = max(0, min(block_idx_start, len(db.block_ids) - 1))
                block_idx_end   = max(0, min(block_idx_end,   len(db.block_ids) - 1))

            if debug:
                base_off = int(db.start_offset or 0)
                A = base_off + start
                B = base_off + (end - 1)
                
                blk_idx_start_bug = start // block_size
                blk_idx_end_bug   = (end - 1) // block_size

                blk_idx_start_fix = A // block_size
                blk_idx_end_fix   = B // block_size

                print(f"[SAWA][MAP] delta_block_id={db.delta_block_id} "
                      f"start={start} end={end} base_off={base_off} -> "
                      f"BUG idx=[{blk_idx_start_bug}..{blk_idx_end_bug}] "
                      f"FIX idx=[{blk_idx_start_fix}..{blk_idx_end_fix}] "
                      f"A={A} B={B} (block_size={block_size})")

                # --- DEBUG: show buggy vs fixed coverage ---
                bug_block_idx_start = start // block_size
                bug_block_idx_end   = (end - 1) // block_size
                bug_covered = db.block_ids[bug_block_idx_start:bug_block_idx_end + 1] if db.block_ids else []

                fix_block_idx_start = A // block_size
                fix_block_idx_end   = B // block_size
                fix_first_off = A % block_size
                fix_last_off  = B % block_size
                fix_covered = db.block_ids[fix_block_idx_start:fix_block_idx_end + 1] if db.block_ids else []

                print(f"[SAWA][COVER] delta_block_id={db.delta_block_id} "
                      f"BUG blocks={bug_covered} BUG off=[{first_block_offset}..{last_block_offset}] "
                      f"FIX blocks={fix_covered} FIX off=[{fix_first_off}..{fix_last_off}]")

                TARGET = 605526
                print(f"[SAWA][HIT?] delta_block_id={db.delta_block_id} "
                      f"BUG_has={TARGET in bug_covered} FIX_has={TARGET in fix_covered}")
                
            # Subset of LBAs covered by the window (inclusive on both ends)
            covered_block_ids = (db.block_ids[block_idx_start:block_idx_end + 1]
                                 if db.block_ids and block_idx_start <= block_idx_end else [])

            # Absolute device LBA range (inclusive)
            lba_start_block = db.block_ids[block_idx_start] if covered_block_ids else None
            lba_end_block   = db.block_ids[block_idx_end]   if covered_block_ids else None

            # Absolute device byte offsets (inclusive end)
            byte_start = (lba_start_block * block_size + first_block_offset) if lba_start_block is not None else None
            byte_end_inclusive = (lba_end_block * block_size + last_block_offset) if lba_end_block is not None else None

            # 6) Emit region
            suspicious_regions.append(SuspiciousRegion(
                extent_id=extent_id,
                delta_block_id=db.delta_block_id,
                block_ids=covered_block_ids,
                start_offset=first_block_offset,
                end_offset=last_block_offset,
                block_idx_start=block_idx_start,
                block_idx_end=block_idx_end,
                lba_start_block=lba_start_block,
                lba_end_block=lba_end_block,
                byte_start=byte_start,
                byte_end_inclusive=byte_end_inclusive,
                chi2_min=float(chi2_min),
                chi2_max=float(chi2_max),
                chi2_var=float(chi2_var_full),
                chi2_final=float(chi2_final),
            ))

            if debug:
                abs_start = block_offset_in_file + start
                abs_end_incl = block_offset_in_file + end - 1
                print(f"[SAWA] ACCEPT abs=[{abs_start}..{abs_end_incl}] "
                      f"bytes={end-start} blocks={covered_block_ids[:3]}{'…' if len(covered_block_ids)>3 else ''} "
                      f"blk_idx=[{block_idx_start}..{block_idx_end}] "
                      f"chi2_final={chi2_final:.3f} var={chi2_var_full:.3f}")
                want = 44032
                contains_want = (abs_start <= want <= abs_end_incl)
                print(f"[SAWA][FILEOFF] abs=[{abs_start}..{abs_end_incl}] contains {want}? {contains_want}")
            
            # --- FIX #1: jump to end+1 after accepting a window (avoid re-seeding inside it)
            # end is exclusive here; next pos is the first byte after the accepted window
            pos = end
            continue
        # while loop end

        # --- Tail handling: if there is a remainder < width that wasn't scanned, surface it.
        # Cases:
        #  - We ended with pos < data_len and the leftover slice is too small for a seed.
        #  - Emit pass-through so file-aware can decide.
        if passthrough_small:
            tail_start = pos if 'pos' in locals() else 0
            if 0 <= tail_start < data_len and (data_len - tail_start) < width and (data_len - tail_start) > 0:
                start = tail_start
                end = data_len  # exclusive
                base_off = int(db.start_offset or 0)
                A = base_off + start
                B = base_off + (end - 1)

                block_idx_start = A // block_size
                block_idx_end   = B // block_size
                if db.block_ids:
                    block_idx_start = max(0, min(block_idx_start, len(db.block_ids) - 1))
                    block_idx_end   = max(0, min(block_idx_end,   len(db.block_ids) - 1))

                first_block_offset = A % block_size
                last_block_offset  = B % block_size

                covered_block_ids = (db.block_ids[block_idx_start:block_idx_end + 1]
                                     if db.block_ids and block_idx_start <= block_idx_end else [])

                lba_start_block = db.block_ids[block_idx_start] if covered_block_ids else None
                lba_end_block   = db.block_ids[block_idx_end]   if covered_block_ids else None

                byte_start = (lba_start_block * block_size + first_block_offset) if lba_start_block is not None else None
                byte_end_inclusive = (lba_end_block * block_size + last_block_offset) if lba_end_block is not None else None

                suspicious_regions.append(SuspiciousRegion(
                    extent_id=extent_id,
                    delta_block_id=db.delta_block_id,
                    block_ids=covered_block_ids,
                    start_offset=first_block_offset,
                    end_offset=last_block_offset,
                    block_idx_start=block_idx_start,
                    block_idx_end=block_idx_end,
                    lba_start_block=lba_start_block,
                    lba_end_block=lba_end_block,
                    byte_start=byte_start,
                    byte_end_inclusive=byte_end_inclusive,
                    chi2_min=0.0, chi2_max=0.0, chi2_var=0.0, chi2_final=0.0,
                ))
                if debug:
                    abs_tail = (db.block_ids[0] * block_size + (db.start_offset or 0)) + start if db.block_ids else None
                    if abs_tail is not None:
                        print(f"[SAWA] ACCEPT (tail pass-through) abs=[{abs_tail}..{abs_tail + (end-start) - 1}] "
                              f"bytes={end-start} blocks={covered_block_ids[:3]}{'…' if len(covered_block_ids)>3 else ''} "
                              f"blk_idx=[{block_idx_start}..{block_idx_end}]")
        
    return suspicious_regions
