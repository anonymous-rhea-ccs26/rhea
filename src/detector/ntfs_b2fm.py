"""
ntfs_b2fm.py: Map suspicious NTFS block (cluster) IDs to files *and file offsets* using interval trees.
"""

import os
from typing import List, Tuple, Dict, Any, Iterable
import pytsk3
from intervaltree import Interval, IntervalTree

# ----------------------------------------------------------------------
# 1) Extract NTFS file extents with logical file offsets per run
# ----------------------------------------------------------------------

def extract_file_extents(img_path: str) -> Tuple[List[Tuple[int, int, int, str, int]], int]:
    """
    Walk the NTFS image and collect all non-resident DATA runs (extents) for regular files.
    For each run, record the logical file offset (in bytes) at the start of that run.

    Args:
        img_path: Path to the NTFS image file.

    Returns:
        (file_extents, cluster_size)
        - file_extents: list of tuples
            (start_block, end_block, file_id, file_path_or_stream, file_offset_bytes_at_run_start)
        - cluster_size: bytes per cluster
    """
    img_info = pytsk3.Img_Info(img_path)
    try:
        fs = pytsk3.FS_Info(img_info)
    except OSError:
        fs = pytsk3.FS_Info(img_info, offset=128 * 512)
    cluster_size = fs.info.block_size  # bytes per NTFS cluster

    file_extents: List[Tuple[int, int, int, str, int]] = []

    def walk_directory(directory, parent_path: str):
        for entry in directory:
            try:
                if not hasattr(entry, "info") or not hasattr(entry.info, "name") or not entry.info.name.name:
                    continue
                name = entry.info.name.name.decode("utf-8", errors="replace")
                if name in (".", ".."):
                    continue

                full_path = os.path.join(parent_path, name)
                meta = getattr(entry.info, "meta", None)
                if meta is None:
                    continue

                # Recurse into directories
                if meta.type == pytsk3.TSK_FS_META_TYPE_DIR:
                    subdir = entry.as_directory()
                    walk_directory(subdir, full_path)
                    continue

                # Regular files with content
                if meta.type == pytsk3.TSK_FS_META_TYPE_REG and meta.size > 0:
                    file_id = meta.addr
                    for attr in entry:
                        if attr.info.type in (pytsk3.TSK_FS_ATTR_TYPE_NTFS_DATA, pytsk3.TSK_FS_ATTR_TYPE_DEFAULT):
                            # Build a path that distinguishes alternate data streams when present.
                            stream_name = getattr(attr.info, "name", None)
                            if stream_name:
                                try:
                                    stream_name = stream_name.decode("utf-8", errors="replace")
                                except Exception:
                                    stream_name = str(stream_name)
                            path_or_stream = f"{full_path}:{stream_name}" if stream_name else full_path

                            try:
                                # Logical file offset (bytes) at the start of this attribute's run list.
                                file_off_bytes = 0
                                for run in attr:
                                    # Only non-resident runs with valid address/length map to clusters.
                                    if run.len > 0 and run.addr > 0:
                                        start_block = int(run.addr)
                                        end_block = int(run.addr + run.len - 1)
                                        file_extents.append(
                                            (start_block, end_block, int(file_id), path_or_stream, int(file_off_bytes))
                                        )
                                        file_off_bytes += int(run.len) * cluster_size
                            except Exception:
                                # Skip unparsable attributes (rare)
                                continue
            except Exception:
                # Robust to corrupt entries
                continue

    root_dir = fs.open_dir("/")
    walk_directory(root_dir, "/")
    return file_extents, cluster_size


# ----------------------------------------------------------------------
# 2) Build an interval tree for fast block→file/run lookups
# ----------------------------------------------------------------------

def build_interval_tree(
    file_extents: List[Tuple[int, int, int, str, int]]
) -> IntervalTree:
    """
    Build an interval tree from file extents.

    The payload for each interval is:
      (file_id, file_path_or_stream, file_offset_bytes_at_run_start, run_start_block)

    Args:
        file_extents: Output of extract_file_extents().

    Returns:
        IntervalTree indexed by [start_block, end_block+1).
    """
    tree = IntervalTree()
    for start, end, file_id, file_path, file_off in file_extents:
        tree.add(Interval(int(start), int(end) + 1, (int(file_id), file_path, int(file_off), int(start))))
    return tree


# ----------------------------------------------------------------------
# 3) Map suspicious blocks to files with precise byte offsets
# ----------------------------------------------------------------------

def map_blocks_to_files(
    suspicious_block_ids,        # sector IDs (512-byte)
    interval_tree,               # built on cluster ranges
    cluster_size,                # bytes per cluster from TSK
    sector_size=512,             # your detector block_size
):
    results = []
    # sanity
    assert cluster_size % sector_size == 0, \
        f"cluster_size ({cluster_size}) must be a multiple of sector_size ({sector_size})"
    spc = cluster_size // sector_size  # sectors per cluster

    for sector_id in suspicious_block_ids:
        sector_id = int(sector_id)
        cluster_id = sector_id // spc
        sector_in_cluster = sector_id % spc

        for iv in interval_tree[cluster_id]:
            file_id, file_path, file_off_start, run_start_cluster = iv.data
            offset_bytes = (
                int(file_off_start)
                + (cluster_id - int(run_start_cluster)) * int(cluster_size)
                + sector_in_cluster * int(sector_size)
            )
            results.append({
                "block_id": sector_id,                 # keep original sector ID for reporting
                "file_id": int(file_id),
                "file_path": str(file_path),
                "offset_bytes": int(offset_bytes),
                "extent_start_block": int(iv.begin),   # in clusters
                "extent_end_block": int(iv.end - 1),   # in clusters
            })
    return results
