import pandas as pd
import numpy as np
import json
import os
from typing import List, Dict, Optional, Any

from detector.delta_types import BlockExtent, AggregBlock, DeltaBlock, DeltaExtent

snapshot_path = "./data/snapshot"
delta_path = "./data/delta"

#############################
#   FUNCTION DEFINITIONS    #
#############################

# ---------- Bitmap helpers ----------

def _load_bitmap_bits(snapshot_path: str, epoch: int) -> Optional[np.ndarray]:
    """
    Load bitmap_<epoch>.bin (created by preprocessor via np.packbits) and return a 1D uint8 array of {0,1}.
    Returns None if file missing.
    """
    fp = os.path.join(snapshot_path, f"bitmap_{epoch}.bin")
    if not os.path.exists(fp):
        return None
    # file contains packed bits -> unpack to 0/1 bits
    packed = np.fromfile(fp, dtype=np.uint8)
    bits = np.unpackbits(packed)
    return bits  # dtype=uint8, values 0 or 1

def collect_mutated_block_ids_from_bitmaps(start_epoch: int, end_epoch: int, snapshot_path: str) -> List[int]:
    """
    OR-reduce bitmap_{i}.bin for i in [start_epoch, end_epoch] to get the union of mutated block IDs.
    Pads shorter bitmaps (if any) to the longest length so OR is well-defined.
    """
    bitmaps: List[np.ndarray] = []
    max_len = 0

    for ep in range(start_epoch, end_epoch + 1):
        bits = _load_bitmap_bits(snapshot_path, ep)
        if bits is None:
            # If a bitmap is missing, just skip it (no mutations recorded for that epoch)
            continue
        bitmaps.append(bits)
        if bits.size > max_len:
            max_len = bits.size

    if not bitmaps:
        return []  # no mutations at all in the window

    # Pad all to the same length, then OR-reduce
    padded = []
    for bits in bitmaps:
        if bits.size < max_len:
            pad = np.zeros(max_len - bits.size, dtype=np.uint8)
            padded.append(np.concatenate([bits, pad], axis=0))
        else:
            padded.append(bits)

    union_bits = np.bitwise_or.reduce(np.stack(padded, axis=0))
    # indices where a bit is set → mutated block IDs
    mutated_ids = np.flatnonzero(union_bits).astype(int).tolist()
    return mutated_ids


# 3. Block Extent Extraction
def extract_block_extents(block_ids, extent_size=4096, block_size=512):
    """
    Group block IDs into BlockExtent objects according to the extent size.
    Returns a list of BlockExtent instances.
    """
    extent_block_count = extent_size // block_size
    block_ids = sorted(block_ids)
    block_extent_snapshot = []
    i = 0
    n_blocks = len(block_ids)
    while i < n_blocks:
        first_block_id = block_ids[i]
        extent_idx = first_block_id // extent_block_count
        extent_start = extent_idx * extent_block_count
        extent_end = extent_start + extent_block_count - 1

        # Collect all block IDs in this extent
        extent_block_ids = []
        while i < n_blocks and extent_start <= block_ids[i] <= extent_end:
            extent_block_ids.append(block_ids[i])
            i += 1

        extent = BlockExtent(
            extent_id=extent_idx,
            extent_size=extent_size,
            extent_block_count=extent_block_count,
            block_ids=extent_block_ids
        )
        block_extent_snapshot.append(extent)
    return block_extent_snapshot

# 4. Forward Difference Computation
def extract_aggreg_blocks(extent, by_blocks, take_blocks, block_size=512):
    """
    For a given BlockExtent, break into contiguous AggregBlock objects
    (for each contiguous run of block IDs within extent.block_ids).
    Returns two lists: aggreg_blocks_old, aggreg_blocks_new.
    """
    aggreg_blocks_old = []
    aggreg_blocks_new = []
    block_ids = sorted(extent.block_ids)
    #print(f"[delta_extract] [extract_aggreg] {extent.__repr__()}")
    #print(f"[delta_extract] [extract_aggreg] {block_ids}")
    if not block_ids:
        return aggreg_blocks_old, aggreg_blocks_new
    start_idx = 0
    while start_idx < len(block_ids):
        end_idx = start_idx
        # Expand end_idx while next block is contiguous
        while (
            end_idx + 1 < len(block_ids)
            and block_ids[end_idx + 1] == block_ids[end_idx] + 1
        ):
            end_idx += 1
        group_block_ids = block_ids[start_idx : end_idx + 1]  # these are contiguous

        # old and new data for the group, as flat lists
        E_old_blocks = [by_blocks.get(bid, [0]*block_size) for bid in group_block_ids]
        E_new_blocks = [take_blocks.get(bid, [0]*block_size) for bid in group_block_ids]
        E_old_bytes = [b for block in E_old_blocks for b in block]
        E_new_bytes = [b for block in E_new_blocks for b in block]

        group_id = f"{extent.extent_id}_{group_block_ids[0]}_{group_block_ids[-1]}"
        aggreg_blocks_old.append(AggregBlock(f"{group_id}_old", extent.extent_id, E_old_bytes, group_block_ids))
        aggreg_blocks_new.append(AggregBlock(f"{group_id}_new", extent.extent_id, E_new_bytes, group_block_ids))
        start_idx = end_idx + 1
    return aggreg_blocks_old, aggreg_blocks_new

def extract_delta_extents(block_extent_snapshot, by_blocks, take_blocks, block_size=512, min_gap_length=16):
    """
    For each BlockExtent, aggregate only contiguous block ID sequences,
    and for each such run, compute delta blocks (forward diffs).
    Returns a list of DeltaExtent instances: each contains DeltaBlock(s) with
    physical block IDs and start/end offsets.
    """
    delta_extents = []
    delta_block_id = 0

    for extent in block_extent_snapshot:
        delta_blocks = []
        # Returns AggregBlocks with block_ids for each contiguous run
        aggreg_blocks_old, aggreg_blocks_new = extract_aggreg_blocks(
            extent, by_blocks, take_blocks, block_size=block_size
        )
        for old_agg, new_agg in zip(aggreg_blocks_old, aggreg_blocks_new):
            #print(f"[delta_extract] [extract_delta] oldlen={len(old_agg.aggreg_data)}, newlen={len(new_agg.aggreg_data)}")
            N = min(len(old_agg.aggreg_data), len(new_agg.aggreg_data))
            block_ids = new_agg.block_ids  # block IDs aggregated for this AggregBlock

            i = 0
            while i < N:
                if old_agg.aggreg_data[i] != new_agg.aggreg_data[i]:
                    delta_start_idx = i
                    f_diff = []
                    gap_run = 0
                    while i < N:
                        if old_agg.aggreg_data[i] != new_agg.aggreg_data[i]:
                            f_diff.append(new_agg.aggreg_data[i])
                            gap_run = 0
                            i += 1
                        else:
                            # count how many consecutive matches
                            gap_run = 1
                            j = i + 1
                            while j < N and old_agg.aggreg_data[j] == new_agg.aggreg_data[j]:
                                gap_run += 1
                                j += 1
                            if gap_run <= min_gap_length:
                                f_diff.extend(new_agg.aggreg_data[i:i+gap_run])
                                i += gap_run
                            else:
                                break
                    delta_end_idx = i  # exclusive

                    # Map aggregation data indices to block indices
                    block_idx_start = delta_start_idx // block_size
                    block_idx_end = (delta_end_idx - 1) // block_size
                    covered_block_ids = block_ids[block_idx_start : block_idx_end + 1]
                    start_offset = delta_start_idx % block_size
                    end_offset = (delta_end_idx - 1) % block_size
                    # No filtering by min_delta_block_size -- keep all delta blocks!
                    delta_block = DeltaBlock(
                        delta_block_id=delta_block_id,
                        delta_block_size=len(f_diff),
                        aggreg_block_id=new_agg.aggreg_block_id,
                        f_diff=f_diff,
                        block_ids=covered_block_ids,
                        start_offset=start_offset,
                        end_offset=end_offset,
                    )
                    delta_blocks.append(delta_block)
                    delta_block_id += 1
                    #print(f"[delta_extract][chk1] {delta_block.__repr__()}")
                else:
                    i += 1

            # Handle extra new data (appended/padded region)
            if len(new_agg.aggreg_data) > N:
                delta_start_idx = N
                delta_end_idx = len(new_agg.aggreg_data)
                f_diff = new_agg.aggreg_data[delta_start_idx:delta_end_idx]
                if f_diff:
                    block_idx_start = delta_start_idx // block_size
                    block_idx_end = (delta_end_idx - 1) // block_size
                    covered_block_ids = block_ids[block_idx_start : block_idx_end + 1]
                    start_offset = delta_start_idx % block_size
                    end_offset = (delta_end_idx - 1) % block_size
                    delta_block = DeltaBlock(
                        delta_block_id=delta_block_id,
                        delta_block_size=len(f_diff),
                        aggreg_block_id=new_agg.aggreg_block_id,
                        f_diff=f_diff,
                        block_ids=covered_block_ids,
                        start_offset=start_offset,
                        end_offset=end_offset,
                    )
                    delta_blocks.append(delta_block)
                    delta_block_id += 1
                    #print(f"[delta_extract][chk2] {delta_block.__repr__()}")

        delta_extent = DeltaExtent(
            extent_id=extent.extent_id,
            delta_blocks=delta_blocks
        )
        #print(f"[delta_extract] [extract_delta] {delta_extent.__repr__()}")
        #for de in delta_extent.delta_blocks:
        #    print(f"[delta_extract] [extract_delta] {de.__repr__()}")
        delta_extents.append(delta_extent)
    return delta_extents

def write_delta_extents_csv(delta_extents, csv_path):
    """
    Write a flat CSV, one row per DeltaBlock (with parent extent info), for classifier input.
    :param delta_extents: list of DeltaExtent objects
    :param csv_path: output file path
    """
    fieldnames = [
        "extent_id",
        "delta_block_id",
        "delta_block_size",
        "aggreg_block_id",
        "f_diff",         # bytes as base64
        "block_ids",      # block IDs as JSON array
        "start_offset",   # int
        "end_offset",     # int
    ]

    with open(csv_path, 'w', newline='') as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames, delimiter=';')
        writer.writeheader()
        for delta_extent in delta_extents:
            for delta_block in delta_extent.delta_blocks:
                row = {
                    "extent_id": delta_extent.extent_id,
                    "delta_block_id": delta_block.delta_block_id,
                    "delta_block_size": delta_block.delta_block_size,
                    "aggreg_block_id": delta_block.aggreg_block_id,
                    "f_diff": base64.b64encode(
                        bytes(delta_block.f_diff)
                        if not isinstance(delta_block.f_diff, bytes)
                        else delta_block.f_diff
                    ).decode('ascii'),
                    "block_ids": json.dumps(delta_block.block_ids),
                    "start_offset": delta_block.start_offset,
                    "end_offset": delta_block.end_offset,
                }
                writer.writerow(row)
    print(f"Wrote {csv_path} with {sum(len(de.delta_blocks) for de in delta_extents)} rows.")
