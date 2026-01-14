import os
import json
from typing import List, Dict, Any, Optional, Tuple, Set
import pandas as pd
from pyspark import StorageLevel
from pyspark.sql.types import (
    IntegerType, ArrayType, StringType, StructType, StructField, LongType,
    DoubleType, BooleanType, 
)
from pyspark.sql import (
     SparkSession, 
)
from pyspark.sql.functions import (
    col, lit, input_file_name, regexp_extract, 
    explode, coalesce, sum as spark_sum, count as spark_count,
    to_json, monotonically_increasing_id, expr,
    array_repeat, 
    floor, sequence, lower, broadcast,
    length, trim,
    desc, size,  # <-- add these
)
import argparse
import hashlib
import time
from contextlib import contextmanager
import uuid
from pathlib import Path

# -- Import your existing logic here --
from detector.delta_types import (
    BlockExtent,
)
from detector.delta_extract import (
    extract_delta_extents,
    collect_mutated_block_ids_from_bitmaps,
)
from detector.sawa import (
    sliding_adaptive_window_analysis,
    sliding_fixed_window_analysis,
)
from detector.ntfs_b2fm import (
    extract_file_extents,
    build_interval_tree,
    map_blocks_to_files,
)

#############################
#   FUNCTION DEFINITIONS    #
#############################

def materialize(df, spark, label: str, storage=StorageLevel.MEMORY_ONLY):
    """
    Persist a DataFrame and time a single action that forces its execution.
    Returns (df_cached, row_count).
    Only call when profiling (to avoid extra jobs in normal runs).
    """
    df_cached = df.persist(storage)
    sc = spark.sparkContext
    try:
        sc.setJobGroup(label, label)
    except Exception:
        pass
    t0 = time.perf_counter()
    n = df_cached.count()   # ACTION → triggers the job
    dt = time.perf_counter() - t0
    print(f"[profile] {label}: {dt:.3f}s, rows={n}")
    try:
        sc.clearJobGroup()
    except Exception:
        pass
    return df_cached, n

def explain_df(df, label: str):
    """
    Dump the (optimized/executed) plan and SQL metrics if available.
    No action is triggered; cheap but super helpful to see shuffles/sorts.
    """
    print(f"[explain] {label} — logical/physical plan:")
    try:
        # Spark 3.x rich explain (formatted)
        df.explain(True)
    except Exception:
        try:
            # Fallback to JVM queryExecution strings
            jqe = df._jdf.queryExecution()
            print(jqe.toString())
            try:
                print(jqe.executedPlan().toStringWithStats())
            except Exception:
                pass
        except Exception:
            pass

def print_ui(spark):
    try:
        ui = spark.sparkContext.uiWebUrl()
        if ui:
            print(f"[profile] Spark UI: {ui}")
    except Exception:
        try:
            ui = spark.sparkContext.uiWebUrl
            if ui:
                print(f"[profile] Spark UI: {ui}")
        except Exception:
            pass

@contextmanager
def job_timer(spark, label: str):
    """Times a Spark *action* (something that triggers a job) and tags it in the UI."""
    sc = spark.sparkContext
    try:
        sc.setJobGroup(label, label)   # groups stages in the Spark UI
    except Exception:
        pass
    t0 = time.perf_counter()
    try:
        yield
    finally:
        dt = time.perf_counter() - t0
        print(f"[profile] {label}: {dt:.3f}s")
        try:
            sc.clearJobGroup()
        except Exception:
            pass

def wall(label: str):
    """Plain wall-clock timer for non-Spark work (e.g., driver-side hashing)."""
    class W:
        def __enter__(self): self.t0 = time.perf_counter(); return self
        def __exit__(self, *a):
            print(f"[profile] {label}: {time.perf_counter() - self.t0:.3f}s")
    return W()

class _Coarse:
    """
    Super-light coarse profiler that timestamps explicit start/end points.
    Use:
         c = _Coarse()
         c.mark("coarse.step1_delta")     # mark the START of step 1
         ... work for step 1 ...
         c.mark("coarse.step2_regions")   # start of step 2 (step 1 ends here)
         ... work ...
         c.finish()                       # final boundary
         c.dump()                         # contiguous step durations
    """
    def __init__(self):
        self.order = [
            "coarse.step1_delta",            # mutated ids -> latest_* -> latest_diff -> _bd_after_latest_diff
            "coarse.step2_regions",          # SAWA/regions applyInPandas + cache + _bd_after_regions
            "coarse.step3_mapping",          # expand kept blocks -> mapInPandas -> _bd_after_mappings
            "coarse.step4_trust_fileaware",  # inventory/trust + file-aware filter + keep regions
            "coarse.step5_outputs",          # write regions + mappings (parquet/csv)
        ]
        self._marks = {}           # name -> ts
        self._seq = []             # ordered names as marked
        self._t0_all = time.perf_counter()
        self._t_end = None
 
    def mark(self, name: str):
        """Mark the START boundary of a step."""
        t = time.perf_counter()
        if name not in self._marks:
            self._seq.append(name)
        self._marks[name] = t
 
    def finish(self):
        """Mark a final terminal boundary for the very last step."""
        self._t_end = time.perf_counter()

    def dump(self):
        print("\n[perf] ===== Coarse Profile (5 steps) =====")
        # Build a list of boundaries in the declared order; skip missing steps.
        boundaries = []
        for name in self.order:
            if name in self._marks:
                boundaries.append((name, self._marks[name]))
        if not boundaries:
            print(f"[perf] {'(no marks)':>30} : {0.000:8.3f s}")
            print(f"[perf] {'coarse.total_all':>30} : {time.perf_counter() - self._t0_all:8.3f} s")
            print("[perf] ======================================\n")
            return
 
        # Sort by the time they were actually marked to respect runtime order.
        boundaries.sort(key=lambda x: x[1])
 
        # Map step name -> contiguous duration (next boundary - this boundary),
        # last step runs until finish() (or now, if finish() wasn't called).
        durations = {name: 0.0 for name in self.order}
        for i, (name, t0) in enumerate(boundaries):
            if i + 1 < len(boundaries):
                t1 = boundaries[i + 1][1]
            else:
                t1 = self._t_end if self._t_end is not None else time.perf_counter()
            durations[name] = max(0.0, t1 - t0)
 
        total_all = (self._t_end if self._t_end is not None else time.perf_counter()) - self._t0_all
        for k in self.order:
            print(f"[perf] {k:>30} : {durations.get(k, 0.0):8.3f} s")
        print(f"[perf] {'coarse.total_all':>30} : {total_all:8.3f} s")
        print("[perf] ======================================\n")

class FineProfiler:
    """
    Generic fine-grained profiler for any coarse step.
    Mirrors _Coarse: each mark(name) starts a sub-step; durations are computed
    to the next boundary; the last runs until finish().
    `order` is advisory for pretty-printing.
    """
    def __init__(self, step_label: str, order=None):
        self.step_label = step_label
        self.order = order or []
        self._marks = {}
        self._seq = []
        self._t0_all = time.perf_counter()
        self._t_end = None

    def mark(self, name: str):
        t = time.perf_counter()
        if name not in self._marks:
            self._seq.append(name)
        self._marks[name] = t

    def finish(self):
        self._t_end = time.perf_counter()

    def dump(self, label=None):
        lbl = label or f"{self.step_label} fine profile"
        print(f"\n[perf] ===== {lbl} =====")
        if not self._marks:
            print(f"[perf] {'(no marks)':>36} : {0.000:8.3f} s")
            print(f"[perf] {'total':>36} : {0.000:8.3f} s")
            print("[perf] ======================================\n")
            return

        boundaries = sorted(self._marks.items(), key=lambda x: x[1])
        durations = {name: 0.0 for name in (self.order or [])}
        seen = [n for n, _ in boundaries]
        for i, (name, t0) in enumerate(boundaries):
            if i + 1 < len(boundaries):
                t1 = boundaries[i + 1][1]
            else:
                t1 = self._t_end if self._t_end is not None else time.perf_counter()
            durations[name] = max(0.0, t1 - t0)

        # Sum of measured sub-steps only (ignores any unmarked gaps)
        total = sum(durations[k] for k in seen)
        printed = set()
        for k in self.order:
            print(f"[perf] {k:>36} : {durations.get(k, 0.0):8.3f} s")
            printed.add(k)
        for k in (n for n in seen if n not in printed):
            print(f"[perf] {k:>36} : {durations.get(k, 0.0):8.3f} s")
        print(f"[perf] {'total':>36} : {total:8.3f}s")
        print("[perf] ======================================\n")        

# Single-source inventory DB:
# {
#   "version": 2,
#   "files": {
#       "/path/to/file": {
#           "sha256": "<hex>|None",
#           "size_bytes": <int>|None,
#           "trusted": <bool>,
#           "first_seen_epoch": <int>,
#           "last_seen_epoch": <int>
#       },
#       ...
#   },
#   "trusted_sha256": ["<hex>", ...]   # union of manifest + any observed trusted items
# }
def _load_inventory_db(inventory_path: str) -> Dict[str, Any]:
    """
    Load inventory JSON if present. If missing/empty/corrupt, return a fresh v2 dict.
    If corrupt, quarantine the bad file to *.bad-<uuid> and proceed fresh.
    """
    default = {"version": 2, "files": {}, "trusted_sha256": []}
    try:
        if not inventory_path or not os.path.exists(inventory_path):
            return default
        # Empty files should be treated as missing/fresh
        if os.path.getsize(inventory_path) == 0:
            return default
        with open(inventory_path, "r", encoding="utf-8") as f:
            db = json.load(f)
        if not isinstance(db, dict) or db.get("version") != 2:
            # Treat unknown/old shapes as fresh
            return default
        db.setdefault("files", {})
        db.setdefault("trusted_sha256", [])
        return db
    except Exception:
        # Quarantine unreadable/corrupt inventory to avoid breaking future runs
        try:
            bad = f"{inventory_path}.bad-{uuid.uuid4().hex}"
            os.replace(inventory_path, bad)
            print(f"[warn] inventory was unreadable; moved to {bad}; starting fresh.")
        except Exception:
            pass
        return default

def _save_inventory_db(inventory_path: str, db: Dict[str, Any]) -> None:
    """
    Atomically write inventory, creating parent dirs as needed.
    Never throws on fsync/replace errors in a way that breaks the pipeline.
    """
    dirp = os.path.dirname(inventory_path) or "."
    os.makedirs(dirp, exist_ok=True)
    tmp = inventory_path + ".tmp"
    db["version"] = 2
    # de-dup + normalize
    db["trusted_sha256"] = sorted({
        (h or "").lower() for h in db.get("trusted_sha256", []) if isinstance(h, str) and h
    })
    try:
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(db, f, ensure_ascii=False, indent=2)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, inventory_path)
    except Exception as e:
        # Best-effort: don't let IO problems kill detection
        print(f"[warn] Could not persist inventory at {inventory_path}: {e} (continuing in-memory)")
        try:
            if os.path.exists(tmp):
                os.remove(tmp)
        except Exception:
            pass

_FILE_MAP_CACHE = {"img": None, "tree": None, "cluster_size": None}

def _get_file_map(image_path):
    global _FILE_MAP_CACHE
    if _FILE_MAP_CACHE["img"] != image_path or _FILE_MAP_CACHE["tree"] is None:
        fe, cs = extract_file_extents(image_path)      # heavy I/O once per executor
        tree = build_interval_tree(fe)                 # heavy CPU once per executor
        _FILE_MAP_CACHE.update({"img": image_path, "tree": tree, "cluster_size": cs})
    return _FILE_MAP_CACHE["tree"], _FILE_MAP_CACHE["cluster_size"]


def process_extent_group_regions(
    pdf,
    extent_size, block_size, min_gap_length,
    width, stride, chi2_threshold,
    min_expansions, max_chi2_var,
    debug=False, profile=False,
    metrics_dir: Optional[str] = None,
    sawa_expand: bool = True,
):
    """
    Per-extent function that returns a summary table of suspicious regions
    (device-absolute offsets, LBA range, χ² diagnostics, etc.).
    NOTE: No file mapping here (lighter/faster).
    """
    import pandas as pd
    from pyspark import TaskContext
    import time, os, json

    def _as_list(v):
        if type(v) is list:           # fastest path
            return v
        try:
            return v.tolist()         # NumPy / Arrow arrays
        except Exception:
            return list(v)            # anything iterable
    
    t_total0 = time.perf_counter()
    t_sawa = 0.0  # initialize!

    extent_id = int(pdf["extent_id"].iloc[0])
    block_ids = list(map(int, pdf["block_id"]))

    # Convert exactly once, no zero padding, no length checks
    by_blocks   = {int(b): _as_list(v) for b, v in zip(pdf["block_id"], pdf["by_block"])}
    take_blocks = {int(b): _as_list(v) for b, v in zip(pdf["block_id"], pdf["take_block"])}

    t_delta0 = time.perf_counter()
    block_extent = BlockExtent(
        extent_id=extent_id,
        extent_size=extent_size,
        extent_block_count=(extent_size // block_size),
        block_ids=block_ids
    )
    delta_extents = extract_delta_extents(
        [block_extent], by_blocks, take_blocks,
        block_size=block_size, min_gap_length=min_gap_length
    )
    t_delta = time.perf_counter() - t_delta0

    rows = []
    for de in delta_extents:
        t0 = time.perf_counter()
        try:
            if sawa_expand:
                srs = sliding_adaptive_window_analysis(
                    de.delta_blocks,
                    extent_id=de.extent_id,
                    width=width, stride=stride,
                    chi2_threshold=chi2_threshold, block_size=block_size,
                    min_expansions=min_expansions, max_chi2_var=max_chi2_var,
                    debug=debug, profile=profile
                )
            else:
                srs = sliding_fixed_window_analysis(
                    de.delta_blocks,
                    extent_id=de.extent_id,
                    width=width, stride=stride,
                    chi2_threshold=chi2_threshold, block_size=block_size,
                    debug=debug, profile=profile
                )
            if srs is None:
                # guard against bad return; keep the job running and log context
                srs = []
        except Exception as e:
            # Re-raise with rich context so Spark shows you which extent/data caused it
            raise RuntimeError(
                f"SAWA failed for extent_id={de.extent_id} with {len(de.delta_blocks)} delta_blocks: {e}"
            ) from e
        t_sawa += time.perf_counter() - t0
        for sr in srs:
            rows.append({
                "extent_id": int(sr.extent_id),
                "delta_block_id": int(sr.delta_block_id),
                "lba_start_block": int(sr.lba_start_block) if sr.lba_start_block is not None else None,
                "lba_end_block":   int(sr.lba_end_block)   if sr.lba_end_block   is not None else None,
                "byte_start": int(sr.byte_start) if sr.byte_start is not None else None,
                "byte_end_inclusive": int(sr.byte_end_inclusive) if sr.byte_end_inclusive is not None else None,
                "block_idx_start": int(sr.block_idx_start) if sr.block_idx_start is not None else None,
                "block_idx_end": int(sr.block_idx_end) if sr.block_idx_end is not None else None,
                "block_ids": [int(b) for b in sr.block_ids],
                "first_block_offset": int(sr.start_offset),
                "last_block_offset": int(sr.end_offset),
                "num_blocks": len(sr.block_ids),
                "chi2_min": float(sr.chi2_min) if sr.chi2_min is not None else None,
                "chi2_max": float(sr.chi2_max) if sr.chi2_max is not None else None,
                "chi2_var": float(sr.chi2_var) if sr.chi2_var is not None else None,
                "chi2_final": float(sr.chi2_final) if sr.chi2_final is not None else None,
            })

    t_total = time.perf_counter() - t_total0

    # ---- write metrics sidecar (one json line per extent) ----
    if profile and metrics_dir:
        try:
            tc  = TaskContext.get()
            tid = tc.taskAttemptId() if tc else -1
            pid = os.getpid()
            outp = os.path.join(metrics_dir, f"part-{tid}-{pid}-{uuid.uuid4().hex}.jsonl")
            metric = {
                "extent_id": extent_id,
                "n_blocks": len(block_ids),
                "n_delta_extents": len(delta_extents),
                "n_regions": len(rows),
                "t_delta": t_delta,
                "t_sawa": t_sawa,
                "t_total": t_total,
                "task": tid,
                "pid": pid,
            }

            # add RSS and delta_blocks_total here (metric now exists)
            try:
                import resource
                rss_kb = int(resource.getrusage(resource.RUSAGE_SELF).ru_maxrss)
            except Exception:
                rss_kb = -1
                metric.update({
                    "rss_kb": rss_kb,
                    "delta_blocks_total": sum(len(de.delta_blocks) for de in delta_extents) if delta_extents else 0,
                })
            
            with open(outp, "a") as fh:
                fh.write(json.dumps(metric) + "\n")
        except Exception:
            pass
            
    columns = [
        "extent_id", "delta_block_id",
        "lba_start_block", "lba_end_block",
        "byte_start", "byte_end_inclusive",
        "block_idx_start", "block_idx_end", "block_ids", 
        "first_block_offset", "last_block_offset",
        "num_blocks",
        "chi2_min", "chi2_max", "chi2_var", "chi2_final",
    ]
    return pd.DataFrame(rows, columns=columns) if rows else pd.DataFrame(columns=columns)

def map_extent_blocks_only(pdf, image_path, block_size, debug=False):
    """
    Input pdf has at least: extent_id, block_id (subset to map).
    No SAWA here. Just map the provided block ids to files using the cached file map.
    """
    import pandas as pd

    if pdf.empty:
        return pd.DataFrame(columns=[
            "extent_id","block_id","file_id","file_path","offset_bytes","extent_start_block","extent_end_block"
        ])

    extent_id = int(pdf["extent_id"].iloc[0])
    block_ids = set(int(b) for b in pdf["block_id"])

    tree, cluster_size = _get_file_map(image_path)
    assert cluster_size % block_size == 0, "cluster_size must be multiple of block_size"

    mappings = map_blocks_to_files(block_ids, tree, cluster_size, sector_size=block_size)
    if debug:
        print(f"[map-only][extent {extent_id}] map {len(block_ids)} blocks -> {len(mappings)} rows")

    rows = [{
        "extent_id": extent_id,
        "block_id": int(m["block_id"]),
        "file_id": int(m["file_id"]),
        "file_path": m["file_path"],
        "offset_bytes": int(m["offset_bytes"]),
        "extent_start_block": int(m["extent_start_block"]),
        "extent_end_block": int(m["extent_end_block"]),
    } for m in mappings]

    return pd.DataFrame(rows, columns=[
        "extent_id","block_id","file_id","file_path","offset_bytes","extent_start_block","extent_end_block"
    ])



def _normalize_nt_path(p: str) -> str:
    p = p.replace('\\','/')
    if not p.startswith('/'):
        p = '/' + p
    while '//' in p:
        p = p.replace('//','/')
    return p


_HASH_CACHE = {}   # {file_path: (sha256_hex, size_int)}

def _fs_sha256(fs_handle, path: str, chunk=1024*1024) -> Tuple[Optional[str], Optional[int]]:
    """
    fs_handle must be ("mount", <mount_root>) for this path.
    """
    if fs_handle is None:
        return (None, None)
    if path in _HASH_CACHE:
        return _HASH_CACHE[path]
    mode, root = fs_handle
    p = _normalize_nt_path(path)  # -> /Windows/System32/...
    hsh = hashlib.sha256()
    total = 0
    try:
        if mode != "mount":
            return (None, None)
        ap = os.path.join(root, p.lstrip('/'))
        size = os.path.getsize(ap)
        with open(ap, 'rb') as f:
            while True:
                b = f.read(chunk)
                if not b: break
                hsh.update(b)
                total += len(b)
        res = (hsh.hexdigest(), size)
    except Exception:
        res = (None, None)
    _HASH_CACHE[path] = res
    return res

def _parse_trusted_manifest(spark: SparkSession, manifest_path: Optional[str]) -> Tuple[Set[str], Set[str]]:
    """
    Returns (component_hashes, file_hashes).

    - component_hashes: ALL sha256 values from the manifest (used by file-aware handlers
      to trust embedded components and also stand-alone media).
    - file_hashes: ONLY sha256 values for stand-alone files (rows where source == 'file'
      or entry is null/empty). Used to drop entire trusted files early.

    Backward compatible:
      * If manifest lacks 'source'/'entry' columns, all hashes are returned in BOTH sets.
      * Accepts CSV (header) or JSON; 'sha256' column is required.
    """
    if not manifest_path:
        return set(), set()

    if manifest_path.lower().endswith(".csv"):
        df = spark.read.option("header", True).csv(manifest_path)
    else:
        df = spark.read.json(manifest_path)

    # normalize columns to lowercase for robustness
    df = df.select([col(c).alias(c.lower()) for c in df.columns])

    # now 'sha256', 'source', 'entry' etc. are all lowercase if present
    if "sha256" not in df.columns:
        raise ValueError("Trusted manifest must contain a 'sha256' column")

    # Lower-case sha256 for consistent set membership
    df = df.withColumn("sha256", lower(col("sha256")))
    df = df.filter(col("sha256").isNotNull() & (length(trim(col("sha256"))) > 0))

    # If the manifest has these columns, use them to separate file vs component entries
    has_source = "source" in df.columns
    has_entry  = "entry" in df.columns

    all_hashes = {r["sha256"] for r in df.select("sha256").dropna().distinct().collect()}

    if has_source or has_entry:
        entry_is_empty = (col("entry").isNull() | (trim(col("entry")) == lit(""))) if has_entry else lit(True)
        is_file_row = (lower(col("source")) == lit("file")) if has_source else entry_is_empty
        file_df = df.filter(is_file_row)
        file_hashes = {r["sha256"] for r in file_df.select("sha256").dropna().distinct().collect()}
    else:
        # Old manifests: treat everything as both file- and component-level
        file_hashes = set(all_hashes)

    return set(all_hashes), set(file_hashes)

def _distinct_by_keys(df, keys):
    """
    DISTINCT for small key-sets without Dataset HashAggregate.
    Converts to RDD[(key_tuple, 1)] -> reduceByKey -> keys back to DF.
    Avoids the 'hashAgg_doAggregateWithKeys' operator that can OOM small executors.
    Assumes 'keys' columns exist and are all hashable/primitives.
    """
    from pyspark.sql import Row, SparkSession
    spark = SparkSession.getActiveSession()
    # pick only the key cols early (keeps rows narrow during shuffle)
    dfk = df.select(*[col(k) for k in keys])
    # RDD of (tuple(keys), 1) → reduceByKey → back to DF
    pair_rdd = dfk.rdd.map(lambda r: (tuple(r), 1))
    uniq_rdd = pair_rdd.reduceByKey(lambda a, b: a).keys()
    # rebuild Row with named fields
    return spark.createDataFrame(uniq_rdd.map(lambda t: Row(**{k: t[i] for i, k in enumerate(keys)})))

def _bd_write_csv(df, outdir: str, name: str):
    """
    Safer CSV writer for tiny block-debug artifacts:
      - repartition by stable keys to avoid skew in a single task
      - break lineage to prevent upstream recomputation
      - keep files small to reduce per-task memory
    """
    from pyspark import StorageLevel
    from pyspark.sql import SparkSession
    from pyspark.sql.functions import col

    spark = SparkSession.getActiveSession()
    os.makedirs(outdir, exist_ok=True)

    key_cols = [c for c in ("extent_id", "block_id", "file_path") if c in df.columns]
    # keep partitions modest; CSV is row-oriented, many small tasks are fine
    target_parts = max(32, min(256, (spark.sparkContext.defaultParallelism or 8) * 2))
    dfw = df
    if key_cols:
        dfw = dfw.repartition(target_parts, *key_cols)
    else:
        dfw = dfw.repartition(target_parts)

    # prefer spillable persistence instead of eager in-mem checkpoint
    dfw = dfw.persist(StorageLevel.MEMORY_AND_DISK)
    _ = dfw.count()  # materialize once
    (dfw.write.mode("overwrite")
     .option("header", True)
     .option("maxRecordsPerFile", 200000)
     .csv(os.path.join(outdir, name)))
    dfw.unpersist()

def _bd_basename(col_expr):
    # last path component for either / or \ separators
    return regexp_extract(col_expr, r'([^/\\]+)$', 1)

def _bd_read_audit_file_offsets(spark: SparkSession, audit_path: str, block_size: int):
    """
    Read persim audit NDJSON and return file-relative, block-aligned offsets:
      columns: file_path, offset_bytes (distinct)
    Uses 'actual.start'..'actual.end' from type=='file_chunk'.
    """
    audit_schema = StructType([
        StructField("type", StringType(), True),
        StructField("path", StringType(), True),
        StructField("out_target", StringType(), True),
        StructField("cipher", StringType(), True),
        StructField("ciphertext_sha256", StringType(), True),
        StructField("iv_or_nonce_hex", StringType(), True),
        StructField("run_id", StringType(), True),
        StructField("actual", StructType([
            StructField("start", LongType(), True),
            StructField("end",   LongType(), True),  # half-open
        ]), True),
        StructField("_corrupt_record", StringType(), True),
    ])

    df = (spark.read
          .schema(audit_schema)
          .option("mode", "PERMISSIVE")
          .option("columnNameOfCorruptRecord", "_corrupt_record")
          .json(audit_path))

    df = df.filter(
        (col("type") == "file_chunk") &
        col("actual").isNotNull() &
        col("actual.start").isNotNull() &
        col("actual.end").isNotNull()
    )

    # Prefer out_target when present; else fallback to path
    df = df.withColumn("file_path", coalesce(col("out_target"), col("path")))

    bs = lit(int(block_size))
    start_idx = floor(col("actual.start") / bs)
    # ceil(end/bs) for integers -> floor((end + bs - 1)/bs)
    end_idx_excl = floor((col("actual.end") + bs - lit(1)) / bs)

    block_idxs = sequence(start_idx, end_idx_excl - lit(1))  # [start_idx, end_idx_excl)
    audit_offsets = (df
        .select("file_path", explode(block_idxs).alias("block_idx"))
        .withColumn("offset_bytes", col("block_idx") * bs)
        .select("file_path", "offset_bytes")
        .dropDuplicates())

    return audit_offsets

def _bd_keyed_offsets(df, path_match: str):
    """
    Given df(file_path, offset_bytes), add a 'key_path' normalized for joining.
    """
    if path_match == "full":
        return df.withColumn("key_path", lower(col("file_path")))
    return df.withColumn("key_path", lower(_bd_basename(col("file_path"))))


def _bd_map_mutated_blocks_to_files(
    spark: SparkSession,
    mutated_ids_df,                   # DF[id: long]
    image_path: str,
    blocks_per_extent: int,
    block_size: int,
    target_parts: int,
    debug: bool,
    job_timer,                        # your existing helper
):
    """
    Build device->file mapping for ALL mutated blocks.
    Returns: bd_mut_block_map_df(extent_id, block_id, file_id, file_path, offset_bytes, extent_start_block, extent_end_block)
    """
    from pyspark import StorageLevel

    bd_mutated_blocks_df = mutated_ids_df.select(
        floor(col("id") / lit(blocks_per_extent)).cast("long").alias("extent_id"),
        col("id").cast("long").alias("block_id"),
    ).dropDuplicates()

    # Partition by extent_id and map to files (re-using your map_extent_blocks_only)
    bd_mutated_blocks_df = bd_mutated_blocks_df.repartition(target_parts, "extent_id").sortWithinPartitions("block_id")

    def _map_partition(pdf_iter):
        import pandas as pd
        cur_eid, seen = None, None

        def flush(eid, seen_blocks):
            if not seen_blocks:
                return None
            blocks = sorted(seen_blocks)
            pdf = pd.DataFrame({"extent_id": [eid]*len(blocks), "block_id": blocks})
            return map_extent_blocks_only(pdf=pdf, image_path=image_path, block_size=block_size, debug=debug)

        for pdf in pdf_iter:
            for r in pdf.itertuples(index=False):
                eid, bid = int(r.extent_id), int(r.block_id)
                if cur_eid is None:
                    cur_eid, seen = eid, set()
                if eid != cur_eid:
                    out = flush(cur_eid, seen)
                    if out is not None: yield out
                    cur_eid, seen = eid, set()
                seen.add(bid)
        out = flush(cur_eid, seen if seen is not None else set())
        if out is not None: yield out

    map_schema = StructType([
        StructField("extent_id", LongType(), False),
        StructField("block_id", LongType(), False),
        StructField("file_id", IntegerType(), False),
        StructField("file_path", StringType(), False),
        StructField("offset_bytes", LongType(), False),
        StructField("extent_start_block", LongType(), False),
        StructField("extent_end_block", LongType(), False),
    ])

    bd_mut_block_map_df = (
        bd_mutated_blocks_df
        .mapInPandas(_map_partition, schema=map_schema)
        .persist(StorageLevel.MEMORY_ONLY)
    )
    with job_timer(spark, "block_debug.mut_block_map.cache"):
        _ = bd_mut_block_map_df.count()

    return bd_mut_block_map_df


def _bd_after_latest_diff(
    spark: SparkSession,
    mutated_ids_df,                   # DF[id]
    latest_at_end,                    # DF(extent_id, block_id, ...)
    latest_diff,                      # DF(extent_id, block_id, ...)
    image_path: str,
    blocks_per_extent: int,
    block_size: int,
    target_parts: int,
    debug: bool,
    job_timer,                        # pass the function
    audit_offsets_df=None,
):
    """
    End-to-end block-debug work that must happen right after latest_diff is available.
    - Maps ALL mutated device blocks to (file_path, offset_bytes)
    - Reads audit NDJSON; converts file offsets -> device (extent_id, block_id)
    - Compares audit vs latest_at_end and latest_diff
    Returns a tiny state dict with 'audit_device_blocks_df' for later use.
    """
    bd_cfg = getattr(run_detection, "_bd_cfg", None)
    state = {"audit_device_blocks_df": None}

    if not (bd_cfg and bd_cfg.get("enabled", False)):
        return state

    bd_outdir = bd_cfg.get("outdir")
    audit_path = bd_cfg.get("audit")
    path_match = bd_cfg.get("path_match", "basename")

    # 1) Mutated device blocks -> file offsets
    bd_mut_block_map_df = _bd_map_mutated_blocks_to_files(
        spark, mutated_ids_df, image_path, blocks_per_extent, block_size, target_parts, debug, job_timer
    )
    _bd_write_csv(bd_mut_block_map_df, bd_outdir, "mutated_block_mappings_csv")

    # --- Fallback: no audit provided → assume "nothing encrypted by persim"
    if bd_cfg.get("assume_no_audit", False):
        from pyspark import StorageLevel as _SL
        from pyspark.sql.functions import col
        import json as _json, os as _os

        # 0) Compute latest_end_keys (universe on detector side)
        latest_end_keys = latest_at_end.select(
            col("extent_id").cast("long").alias("extent_id"),
            col("block_id").cast("long").alias("block_id"),
        ).dropDuplicates().persist(_SL.MEMORY_ONLY)
        with job_timer(spark, "block_debug.latest_end_keys.cache"):
            _ = latest_end_keys.count()

        # 1) Empty audit *sources* (so GT = 0 unless you add untrusted later)
        empty_off_schema = (StructType()
                            .add("file_path", StringType(), True)
                            .add("offset_bytes", LongType(), True))
        empty_offsets = spark.createDataFrame([], schema=empty_off_schema).persist(_SL.MEMORY_ONLY)
        with job_timer(spark, "block_debug.audit_offsets.cache"):
            _ = empty_offsets.count()
        _bd_write_csv(empty_offsets, bd_outdir, "audit_file_offsets_csv")

        empty_dev_schema = (StructType()
                            .add("extent_id", LongType(), False)
                            .add("block_id",  LongType(), False))
        empty_dev = spark.createDataFrame([], schema=empty_dev_schema).persist(_SL.MEMORY_ONLY)
        with job_timer(spark, "block_debug.audit_to_device.cache"):
            _ = empty_dev.count()
        _bd_write_csv(empty_dev, bd_outdir, "audit_device_blocks_csv")

        # Combined metric support: write an empty untrusted mapping too
        empty_untrusted = spark.createDataFrame([], schema=(StructType()
            .add("file_path", StringType(), False)
            .add("block_id",  LongType(),   False)
            .add("offset_bytes", LongType(), False)))
        _bd_write_csv(empty_untrusted, bd_outdir, "audit_untrusted_immutable_block_mappings_csv")

        # 2) Synthesize the three cmp_audit_vs_latest_at_end_* dirs
        #    - match:       empty
        #    - audit_only:  empty
        #    - latest_only: all latest_end_keys
        _bd_write_csv(empty_dev, bd_outdir, "cmp_audit_vs_latest_at_end_match_csv")
        _bd_write_csv(empty_dev, bd_outdir, "cmp_audit_vs_latest_at_end_audit_only_csv")
        _bd_write_csv(latest_end_keys.select("extent_id", "block_id"),
                      bd_outdir, "cmp_audit_vs_latest_at_end_latest_only_csv")

        # 3) Tiny summary
        try:
            _os.makedirs(bd_outdir, exist_ok=True)
            summary_path = _os.path.join(bd_outdir, "block_debug_summary.json")
            _summary = {
                "mode": "no-audit-fallback",
                "message": "Assumed no Persim-encrypted blocks (no audit provided).",
                "mutated_block_mappings": int(bd_mut_block_map_df.count()),
                "audit_offsets": 0,
                "audit_device_blocks": 0,
                "cmp_latest_only_rows": int(latest_end_keys.count())
            }
            with open(summary_path, "w", encoding="utf-8") as fh:
                _json.dump(_summary, fh, ensure_ascii=False, indent=2)
            print(f"[block-debug] Summary: {summary_path}")
        except Exception as _e:
            print(f"[block-debug] Could not write block_debug_summary.json: {_e}")

        # IMPORTANT: Skip heavy comparisons entirely in this mode
        return state

    # 2) Use preloaded audit offsets (file_path, offset_bytes) if available; else read now
    if audit_offsets_df is None:
        if not audit_path or not os.path.exists(audit_path):
            print("[block-debug] Disabled: --block-debug-audit missing or not found.")
            return state

        try:
            audit_offsets_df = _bd_read_audit_file_offsets(spark, audit_path, block_size).persist(StorageLevel.MEMORY_ONLY)
            with job_timer(spark, "block_debug.audit_offsets.cache"):
                _ = audit_offsets_df.count()
            _bd_write_csv(audit_offsets_df, bd_outdir, "audit_file_offsets_csv")
        except Exception as e:
            print(f"[block-debug] Error reading audit NDJSON: {e}")
            return state

    # keep the offsets in state for later helpers
    state["audit_offsets_df"] = audit_offsets_df
        
    # 3) Convert audit file offsets -> device blocks by joining mapping
    det_keyed = _bd_keyed_offsets(
        bd_mut_block_map_df.select("file_path", "offset_bytes").dropDuplicates(),
        path_match
    ).select("key_path", "file_path", "offset_bytes")

    aud_keyed = _bd_keyed_offsets(
        audit_offsets_df.select("file_path", "offset_bytes").dropDuplicates(),
        path_match
    ).select("key_path", "file_path", "offset_bytes")

    audit_device_blocks_df = (
        aud_keyed.join(
            bd_mut_block_map_df.join(det_keyed, on=["file_path","offset_bytes"], how="inner"),
            on=["key_path","offset_bytes"], how="inner"
        )
        .select("extent_id", "block_id")
        .dropDuplicates()
        .persist(StorageLevel.MEMORY_ONLY)
    )
    with job_timer(spark, "block_debug.audit_to_device.cache"):
        _ = audit_device_blocks_df.count()
    _bd_write_csv(audit_device_blocks_df, bd_outdir, "audit_device_blocks_csv")
    state["audit_device_blocks_df"] = audit_device_blocks_df

    # 4) Compare audit blocks to latest_* (device-level)
    latest_end_keys  = latest_at_end.select("extent_id","block_id").dropDuplicates()
    latest_diff_keys = latest_diff.select("extent_id","block_id").dropDuplicates()

    a_end_match       = audit_device_blocks_df.join(latest_end_keys,  ["extent_id","block_id"], "inner")
    a_end_audit_only  = audit_device_blocks_df.join(latest_end_keys,  ["extent_id","block_id"], "left_anti")
    a_end_latest_only = latest_end_keys.join(audit_device_blocks_df,  ["extent_id","block_id"], "left_anti")

    _bd_write_csv(a_end_match,       bd_outdir, "cmp_audit_vs_latest_at_end_match_csv")
    _bd_write_csv(a_end_audit_only,  bd_outdir, "cmp_audit_vs_latest_at_end_audit_only_csv")
    _bd_write_csv(a_end_latest_only, bd_outdir, "cmp_audit_vs_latest_at_end_latest_only_csv")

    a_diff_match       = audit_device_blocks_df.join(latest_diff_keys, ["extent_id","block_id"], "inner")
    a_diff_audit_only  = audit_device_blocks_df.join(latest_diff_keys, ["extent_id","block_id"], "left_anti")
    a_diff_latest_only = latest_diff_keys.join(audit_device_blocks_df, ["extent_id","block_id"], "left_anti")

    _bd_write_csv(a_diff_match,       bd_outdir, "cmp_audit_vs_latest_diff_match_csv")
    _bd_write_csv(a_diff_audit_only,  bd_outdir, "cmp_audit_vs_latest_diff_audit_only_csv")
    _bd_write_csv(a_diff_latest_only, bd_outdir, "cmp_audit_vs_latest_diff_latest_only_csv")

    return state


def _bd_after_regions(
    spark: SparkSession,
    suspicious_regions_df,            # DF with block_ids array
    bd_state: dict
):
    """
    Compare audit device blocks to SAWA-kept regions.
    Call this right after suspicious_regions_df is cached.
    """
    bd_cfg = getattr(run_detection, "_bd_cfg", None)
    if not (bd_cfg and bd_cfg.get("enabled", False)):
        return
    audit_device_blocks_df = bd_state.get("audit_device_blocks_df")
    if audit_device_blocks_df is None:
        return

    bd_outdir = bd_cfg.get("outdir")

    # 1) Narrow to keys early
    reg_keys_df = (
        suspicious_regions_df
        .select("extent_id", explode("block_ids").alias("block_id"))
        .withColumn("block_id", col("block_id").cast("long"))
    )
    aud_keys_df = audit_device_blocks_df.select("extent_id", "block_id")

    # 2) DISTINCT **without** Dataset HashAggregate (use RDD reduceByKey path)
    reg_blocks = _distinct_by_keys(reg_keys_df, ["extent_id", "block_id"])
    aud_blocks = _distinct_by_keys(aud_keys_df, ["extent_id", "block_id"])
 
    # 3) Spread the workload by keys to reduce skew and lower per-task memory.
    reg_blocks = reg_blocks.repartition(64, "extent_id")
    aud_blocks = aud_blocks.repartition(64, "extent_id")

    # 4) Do the compares on the **narrow, deduped** key sets only
    ar_match        = aud_blocks.join(reg_blocks, ["extent_id","block_id"], "inner")
    ar_audit_only   = aud_blocks.join(reg_blocks, ["extent_id","block_id"], "left_anti")
    ar_regions_only = reg_blocks.join(aud_blocks, ["extent_id","block_id"], "left_anti")

    # 5) Materialize once to avoid rebuilding joins during multiple writes.
    from pyspark import StorageLevel
    ar_match        = ar_match.persist(StorageLevel.MEMORY_ONLY)
    ar_audit_only   = ar_audit_only.persist(StorageLevel.MEMORY_ONLY)
    ar_regions_only = ar_regions_only.persist(StorageLevel.MEMORY_ONLY)
    # trigger tiny caches
    _ = ar_match.count(), ar_audit_only.count(), ar_regions_only.count()

    _bd_write_csv(ar_match,        bd_outdir, "cmp_audit_vs_regions_match_csv")
    _bd_write_csv(ar_audit_only,   bd_outdir, "cmp_audit_vs_regions_audit_only_csv")
    _bd_write_csv(ar_regions_only, bd_outdir, "cmp_audit_vs_regions_regions_only_csv")

    # Free small caches quickly
    ar_match.unpersist()
    ar_audit_only.unpersist()
    ar_regions_only.unpersist()

def _bd_after_mappings(
    spark: SparkSession,
    suspicious_mappings_df,          # DF(extent_id, block_id, file_path, offset_bytes, ...)
    bd_state: dict,                  # carries 'audit_device_blocks_df' from earlier
    path_match: str,                 # "full" or "basename"
    bd_outdir: str,
):
    """
    Memory-efficient comparison: audit file offsets vs suspicious_mappings_df.
    - No wide DataFrame join. We broadcast a tiny dict and use mapInPandas to check membership.
    - If path_match == 'basename', we restrict to basenames that are unique on BOTH sides.
    Artifacts written:
      - cmp_audit_vs_maps_match_csv
      - cmp_audit_vs_maps_audit_only_csv
      - cmp_audit_vs_maps_maps_only_csv
    """
    from pyspark import StorageLevel
    from pyspark.sql.functions import lower, regexp_extract, col
    import pandas as pd

    audit_offsets = bd_state.get("audit_offsets_df")  # DF(file_path, offset_bytes)
    if audit_offsets is None:
        # nothing to compare
        return

    # --- 1) Prepare keys on both sides (full path or basename), dedup rows ---
    def _keyed(df):
        if path_match == "full":
            return (df
                    .select(lower(col("file_path")).alias("key_path"),
                            col("file_path"), col("offset_bytes"))
                    .dropDuplicates(["key_path","offset_bytes"]))
        # basename fallback
        base = regexp_extract(col("file_path"), r'([^/\\]+)$', 1)
        return (df
                .select(lower(base).alias("key_path"),
                        col("file_path"), col("offset_bytes"))
                .dropDuplicates(["key_path","offset_bytes"]))

    aud_keyed = _keyed(audit_offsets).persist(StorageLevel.MEMORY_ONLY)
    det_keyed = _keyed(suspicious_mappings_df.select("file_path","offset_bytes")).persist(StorageLevel.MEMORY_ONLY)

    # If using basename, keep only keys that are unique on BOTH sides to avoid N×M blowups
    #if path_match != "full":
    #    from pyspark.sql.functions import count as F_count
    #    aud_uni = aud_keyed.groupBy("key_path").agg(F_count("*").alias("c")).filter(col("c") == 1).select("key_path")
    #    det_uni = det_keyed.groupBy("key_path").agg(F_count("*").alias("c")).filter(col("c") == 1).select("key_path")
    #    uniq_keys = aud_uni.join(det_uni, "key_path", "inner")
    #    aud_keyed = aud_keyed.join(uniq_keys, "key_path", "inner")
    #    det_keyed = det_keyed.join(uniq_keys, "key_path", "inner")
    #aud_keyed = aud_keyed.join(uniq_keys, "key_path", "inner")
    #det_keyed = det_keyed.join(uniq_keys, "key_path", "inner")

    # --- 2) Build a tiny Python dict and broadcast (no DataFrame join) ---
    # dict: key_path -> set(offset_bytes)
    # We use toLocalIterator() to avoid collecting giant rows in one go.
    key_to_offsets = {}
    for r in aud_keyed.select("key_path","offset_bytes").toLocalIterator():
        k = r["key_path"]
        o = int(r["offset_bytes"])
        s = key_to_offsets.get(k)
        if s is None:
            s = set(); key_to_offsets[k] = s
        s.add(o)

    bc_audit = spark.sparkContext.broadcast(key_to_offsets)

    # --- 3) Do membership check via mapInPandas (no shuffle, no join) ---
    det_pre = det_keyed.select("key_path","file_path","offset_bytes").dropDuplicates()

    def _label_matches(pdf_iter):
        # Runs on executor; uses broadcast dict
        audit_map = bc_audit.value
        import pandas as _pd
        for pdf in pdf_iter:
            if pdf.empty:
                yield _pd.DataFrame(columns=["key_path","file_path","offset_bytes","in_audit"])
                continue
            # vectorized-ish check: group by key_path to avoid repeated dict lookups
            rows = []
            for k, grp in pdf.groupby("key_path"):
                offs = audit_map.get(k, None)
                if offs is None:
                    grp["in_audit"] = False
                else:
                    # set membership per row
                    grp["in_audit"] = grp["offset_bytes"].astype("int64").apply(lambda x: x in offs)
                rows.append(grp[["key_path","file_path","offset_bytes","in_audit"]])
            out = _pd.concat(rows, ignore_index=True) if rows else _pd.DataFrame(
                columns=["key_path","file_path","offset_bytes","in_audit"])
            yield out

    schema = (StructType()
              .add("key_path", StringType(), False)
              .add("file_path", StringType(), False)
              .add("offset_bytes", LongType(), False)
              .add("in_audit", BooleanType(), False))

    labeled = det_pre.mapInPandas(_label_matches, schema=schema)

    # --- 4) Split and write CSV artifacts (tiny outputs) ---
    matched      = labeled.filter(col("in_audit") == True).select("file_path","offset_bytes")
    maps_only    = labeled.filter(col("in_audit") == False).select("file_path","offset_bytes")

    # audit_only = audit - matched
    aud_pairs = aud_keyed.select("key_path","file_path","offset_bytes").dropDuplicates()
    mat_pairs = matched.join(_keyed(matched), ["file_path","offset_bytes"], "inner") \
                       .select("key_path","file_path","offset_bytes").dropDuplicates()
    audit_only = aud_pairs.join(mat_pairs, ["key_path","offset_bytes"], "left_anti") \
                          .select("file_path","offset_bytes")

    _bd_write_csv(matched,    bd_outdir, "cmp_audit_vs_maps_match_csv")
    _bd_write_csv(audit_only, bd_outdir, "cmp_audit_vs_maps_audit_only_csv")
    _bd_write_csv(maps_only,  bd_outdir, "cmp_audit_vs_maps_maps_only_csv")

    # cleanup small caches
    aud_keyed.unpersist()
    det_keyed.unpersist()



#############################
#       MAIN PIPELINE       #
#############################

def run_detection(
    start_epoch: int,
    end_epoch: int,
    snapshot_path: str,
    output_path: str,
    extent_size: int,
    block_size: int,
    min_gap_length: int,
    width: int,
    stride: int,
    chi2_threshold: int,
    min_expansions: int,
    max_chi2_var: float,
    trusted_manifest: Optional[str] = None,
    end_mount_root: Optional[str] = None,
    out_formats: Optional[Set[str]] = None,
    audit_formats: Optional[Set[str]] = None,
    debug: bool = False,
    profile: bool = False,
    sawa_expand: bool = True,
):
    """
    Core detection pipeline. Assumes inputs are validated/prepared by main().
    """
    # ---- 0. Setup ----
    event_dir = os.path.abspath(os.environ.get("SPARK_EVENTLOG_DIR", "/tmp/spark-events"))
    os.makedirs(event_dir, exist_ok=True)

    spark = (
        SparkSession.builder
        .appName("DetectionEngine")
        # tune to cluster; avoids giant shuffles with default=200
        .config("spark.sql.shuffle.partitions", "96")
        # prevent driver result-size blowups
        .config("spark.driver.memory", "8g") # default : 4g
        .config("spark.driver.maxResultSize", "1g")
        .config("spark.hadoop.fs.defaultFS", "file:///")
        .config("spark.sql.adaptive.enabled", "true")         # AQE: better joins/shuffles
        .config("spark.sql.adaptive.skewJoin.enabled", "true")
        .config("spark.sql.adaptive.coalescePartitions.enabled", "false")  # don't over-merge partitions
        .config("spark.sql.advisoryPartitionSizeInBytes", "64m")          # gentler coalesce size if re-enabled
        .config("spark.sql.inMemoryColumnarStorage.batchSize", "2048")        # smaller columnar batches
        .config("spark.sql.execution.arrow.maxRecordsPerBatch", "2000")       # lighter Pandas UDF batches
        .config("spark.serializer", "org.apache.spark.serializer.KryoSerializer")
        .config("spark.kryoserializer.buffer", "32m")
        .config("spark.kryoserializer.buffer.max", "256m")
        .config("spark.eventLog.enabled", "true")
        .config("spark.eventLog.dir", Path(event_dir).as_uri())  # yields file:///... correctly
        .config("spark.executor.memory", "8g") # default : 4g
        .config("spark.executor.memoryOverhead", "1024")
        .config("spark.executor.extraJavaOptions",
        "-XX:+UnlockDiagnosticVMOptions -Xlog:gc*=info:file=/tmp/gc-%p-%t.log:tags,uptime,time,level -XX:+HeapDumpOnOutOfMemoryError -XX:HeapDumpPath=/tmp/heapdumps")
.config("spark.driver.extraJavaOptions",
        "-XX:+UnlockDiagnosticVMOptions -Xlog:gc*=info:file=/tmp/gc-driver-%p-%t.log:tags,uptime,time,level")
        .config("spark.eventLog.enabled","true")
        .config("spark.eventLog.dir","file:///tmp/spark-events")
        # -> java.io.FileNotFoundException: File file:/tmp/spark-events does not exist
        # If you can:
        # .config("spark.executor.memoryOverhead", "4096")        
        # optional: smaller input splits for more parallelism
        # .config("spark.sql.files.maxPartitionBytes", "64m")
        .getOrCreate()
    )
    print_ui(spark)

    # create once near the start of run_detection
    def _long_acc(sc, name: str):
        """
        Cross-version long accumulator.
        - Uses sc.longAccumulator(name) when available (Spark 2.x/3.x classic).
        - Falls back to sc.accumulator(0) for older APIs.
        Returns an object with .add(int) and .value.
        """
        try:
            return sc.longAccumulator(name)  # Spark 2.x/3.x classic
        except AttributeError:
            acc0 = sc.accumulator(0)         # legacy API
            class _Wrap:
                def add(self, v): acc0.add(int(v))
                @property
                def value(self): return int(acc0.value)
        return _Wrap()

    regions_acc = _long_acc(spark.sparkContext, "regions_emitted")

    # normalize the Nones into defaults
    out_formats = out_formats or {"parquet"}
    audit_formats = audit_formats or {"parquet"}
    
    try:
        image_path = os.path.join(snapshot_path, f"device_{end_epoch}.img")

        # Coarse profiler instance
        coarse = _Coarse()
        # Fine-grained profilers per coarse step (advisory print orders)
        s1 = FineProfiler("Step 1", order=[
            "s1.mutated_ids","s1.read_mutations","s1.derive_epoch",
            "s1.filter_mutated_ids","s1.filter_end_epoch",
            "s1.latest_before","s1.latest_at_end","s1.latest_diff",
            "s1.block_debug_after_latest"
        ])
        s2 = FineProfiler("Step 2", order=[
            "s2.pre_checks","s2.probes","s2.applyInPandas",
            "s2.cache_regions","s2.region_checkpoint","s2.block_debug_after_regions",
            "s2.materialize"
        ])
        s3 = FineProfiler("Step 3", order=[
            "s3.expand_kept_blocks","s3.repartition_blocks","s3.mapInPandas",
            "s3.materialize","s3.block_debug_after_mappings"
        ])
        s4 = FineProfiler("Step 4", order=[
            "s4.load_inventory","s4.parse_manifest","s4.hash_suspect_files",
            "s4.persist_inventory","s4.drop_trusted_paths","s4.fileaware_collect",
            "s4.fileaware_decide","s4.apply_region_decisions",
            "s4.apply_file_level_decisions","s4.regions_keep_update",
            "s4.audit_artifacts","s4.fileaware_audit_artifacts"
        ])
        s5 = FineProfiler("Step 5", order=[
            "s5.write_regions_parquet","s5.write_regions_csv",
            "s5.write_mappings_parquet","s5.write_mappings_csv"
        ])

        # ---- 1. Load mutation snapshot ----
        coarse.mark("coarse.step1_delta")
        # ---- 1) Union of mutated block IDs via bitmaps (driver does only tiny work) ----
        s1.mark("s1.mutated_ids")
        mutated_ids = collect_mutated_block_ids_from_bitmaps(start_epoch, end_epoch, snapshot_path)
        if debug:
            print(f"[debug] mutated block_ids union [{start_epoch}..{end_epoch}] = {len(mutated_ids)}")

        # EARLY EXIT: nothing changed in this window
        if not mutated_ids:
            s1.finish()
            parquet_out = os.path.join(output_path, f"suspicious_block_mappings_{start_epoch}_{end_epoch}.parquet")
            csv_out_dir  = os.path.join(output_path, f"suspicious_block_mappings_{start_epoch}_{end_epoch}_csv")
            # Create empty outputs with the expected schema
            schema = StructType([
                StructField("extent_id", LongType(), False),
                StructField("block_id", LongType(), False),
                StructField("file_id", IntegerType(), False),
                StructField("file_path", StringType(), False),
                StructField("offset_bytes", LongType(), False),
                StructField("extent_start_block", LongType(), False),
                StructField("extent_end_block", LongType(), False),
                StructField("start_epoch", IntegerType(), True),
                StructField("end_epoch", IntegerType(), True),
            ])
            empty_df = SparkSession.getActiveSession().createDataFrame([], schema=schema)
            empty_df.write.mode("overwrite").parquet(parquet_out)
            if "csv" in out_formats:
                empty_df.write.mode("overwrite").option("header", True).csv(csv_out_dir)

            if debug:
                print("[debug] No mutated blocks; wrote empty outputs.")

            regions_parquet_out = os.path.join(output_path, f"suspicious_regions_{start_epoch}_{end_epoch}.parquet")
            regions_csv_out_dir = os.path.join(output_path, f"suspicious_regions_{start_epoch}_{end_epoch}_csv")
            region_schema = StructType([
                StructField("extent_id", LongType(), False),
                StructField("delta_block_id", IntegerType(), False),
                StructField("lba_start_block", LongType(), True),
                StructField("lba_end_block", LongType(), True),
                StructField("byte_start", LongType(), True),
                StructField("byte_end_inclusive", LongType(), True),
                StructField("block_idx_start", IntegerType(), True),
                StructField("block_idx_end", IntegerType(), True),
                StructField("block_ids", ArrayType(LongType(), containsNull=False), True),
                StructField("first_block_offset", IntegerType(), True),
                StructField("last_block_offset", IntegerType(), True),
                StructField("num_blocks", IntegerType(), True),
                StructField("chi2_min", DoubleType(), True),
                StructField("chi2_max", DoubleType(), True),
                StructField("chi2_var", DoubleType(), True),
                StructField("chi2_final", DoubleType(), True),
                StructField("start_epoch", IntegerType(), True),
                StructField("end_epoch", IntegerType(), True),
            ])
            empty_regions_df = SparkSession.getActiveSession().createDataFrame([], schema=region_schema)
            empty_regions_df.write.mode("overwrite").parquet(regions_parquet_out)
            if "csv" in out_formats:   # was unconditional
                (empty_regions_df
                 .withColumn("block_ids", to_json(col("block_ids")))
                 .write.mode("overwrite").option("header", True).csv(regions_csv_out_dir))

            coarse.finish()
            s1.dump(label="Step 1 fine profile (summary)")    # Fine profiles: only those used so far
            coarse.dump()         # Print coarse profile even in the early-exit path
                
            return parquet_out, csv_out_dir, regions_parquet_out, regions_csv_out_dir

        mutated_ids_df = spark.createDataFrame([(int(i),) for i in mutated_ids], ["id"]).select(col("id").cast("long"))

        # -------- Block-debug: read audit (file-relative, block-aligned offsets) --------
        bd_state = {}
        bd_cfg = getattr(run_detection, "_bd_cfg", None)
        bd_audit_offsets_df = None
        if bd_cfg and bd_cfg.get("enabled", False):
            audit_path = bd_cfg.get("audit")
            bd_outdir = bd_cfg.get("outdir")

            if not audit_path or not os.path.exists(audit_path):
                if bd_cfg.get("assume_no_audit", False):
                    print("[block-debug] No audit provided; assuming 'no persim encryption' and continuing with empty audit.")
                    # Do not preload anything here; _bd_after_latest_diff will synthesize an empty audit file
                    bd_audit_offsets_df = None
                else:
                    print("[block-debug] Disabled: --block-debug-audit missing or not found.")
            else:
                try:
                    bd_audit_offsets_df = _bd_read_audit_file_offsets(
                        spark, audit_path=audit_path, block_size=block_size
                    ).persist(StorageLevel.MEMORY_ONLY)
                    if bd_audit_offsets_df is not None:
                        bd_state["audit_offsets_df"] = bd_audit_offsets_df  # save once for reuse
                    with job_timer(spark, "block_debug.audit_offsets.cache"):
                        _ = bd_audit_offsets_df.count()
                    _bd_write_csv(bd_audit_offsets_df, bd_outdir, "audit_file_offsets_csv")
                    print(f"[block-debug] Wrote audit_file_offsets_csv to {bd_outdir}")
                except Exception as e:
                    print(f"[block-debug] Error reading audit NDJSON: {e}")
                    bd_audit_offsets_df = None

        # ---- 2) Read all mutation parquet (executors do the I/O) ----
        mutation_schema = StructType([
            StructField("id", LongType(), False),
            StructField("block", ArrayType(LongType(), containsNull=False), False),
            # epoch may be absent; we’ll derive it from filename if needed
        ])
        s1.mark("s1.read_mutations")
        
        mutations = (spark.read
                     .schema(mutation_schema)
                     .parquet(os.path.join(snapshot_path, "mutation_*.parquet")))

        # If writer didn't store epoch, derive from file name
        if "epoch" not in mutations.columns:
            s1.mark("s1.derive_epoch")
            mutations = (
                mutations
                .withColumn("_fn", input_file_name())
                .withColumn("epoch", regexp_extract(col("_fn"), r"mutation_(\d+)\.parquet", 1).cast("int"))
                .drop("_fn")
            )
        
        # Must have non-null epoch
        assert mutations.filter(col("epoch").isNull()).limit(1).count() == 0, "Null epoch in mutations"

        # Filter to only mutated ids (map-side via broadcast)
        s1.mark("s1.filter_mutated_ids")        
        mutations = (
            mutations
            .join(mutated_ids_df.hint("broadcast"), on="id", how="inner")
        )

        # Filter to epochs we care about
        s1.mark("s1.filter_end_epoch")
        mutations = mutations.filter(col("epoch") <= lit(end_epoch))

        # Compute extent_id and pin partitions
        blocks_per_extent = extent_size // block_size

        print(f"[detect] [run_detection] extent_size={extent_size} block_size={block_size} blocks_per_extent={extent_size//block_size}")
        
        # Choose a sensible partition count based on how many extents changed
        mutated_extent_count = len({int(i) // blocks_per_extent for i in mutated_ids})
        if profile:
            small_parts = max(2, min(16, (mutated_extent_count or 1) * 2))
            spark.conf.set("spark.sql.shuffle.partitions", str(small_parts))
            print(f"[profile] shuffle.partitions -> {small_parts}")
        else:
            #parts = max(4, min(16, (mutated_extent_count or 1) * 2))
            parts = max(8, min(spark.sparkContext.defaultParallelism, (mutated_extent_count or 1) * 2, 32))
            spark.conf.set("spark.sql.shuffle.partitions", str(parts))
        
        target_parts = max(8, min(spark.sparkContext.defaultParallelism, mutated_extent_count or 1))

        # Partition by extent and order rows to enable single-pass scans per extent
        def cache_once(df, spark, name, storage=StorageLevel.MEMORY_ONLY):
            df = df.persist(storage)
            with job_timer(spark, f"{name}.cache"):
                _ = df.count()
            return df
        mutations = (
            mutations
            .withColumn("extent_id", expr(f"CAST(FLOOR(id / {blocks_per_extent}) AS BIGINT)"))
            .repartition(target_parts, "extent_id")   # single up-front shuffle to cluster by extent
            # .sortWithinPartitions("id", "epoch")  # avoid heavy in-partition sort to reduce OOM
            .persist(StorageLevel.MEMORY_AND_DISK)
        )
        mutations = cache_once(
            mutations, spark, "mutations", storage=StorageLevel.MEMORY_AND_DISK
        )

        if profile:
            explain_df(mutations, "mutations_after_prepare")
            mutations, _ = materialize(mutations, spark, "mutations.materialize",
                                       storage=StorageLevel.MEMORY_ONLY)

        region_schema = StructType([
            StructField("extent_id", LongType(), False),
            StructField("delta_block_id", IntegerType(), False),
            StructField("lba_start_block", LongType(), True),
            StructField("lba_end_block", LongType(), True),
            StructField("byte_start", LongType(), True),
            StructField("byte_end_inclusive", LongType(), True),
            StructField("block_idx_start", IntegerType(), True),
            StructField("block_idx_end", IntegerType(), True),
            StructField("block_ids", ArrayType(LongType(), containsNull=False), True),
            StructField("first_block_offset", IntegerType(), True),
            StructField("last_block_offset", IntegerType(), True),
            StructField("num_blocks", IntegerType(), True),
            StructField("chi2_min", DoubleType(), True),
            StructField("chi2_max", DoubleType(), True),
            StructField("chi2_var", DoubleType(), True),
            StructField("chi2_final", DoubleType(), True),
        ])

        # latest before start_epoch
        s1.mark("s1.latest_before")
        latest_before = (
            mutations
            .filter(col("epoch") < lit(start_epoch))
            .groupBy("extent_id", col("id").alias("block_id"))
            .agg(expr("max_by(block, epoch) as by_block"))
        )

        # latest at end_epoch (inclusive)
        s1.mark("s1.latest_at_end")
        latest_at_end = (
            mutations
            .filter(col("epoch") <= lit(end_epoch))
            .groupBy("extent_id", col("id").alias("block_id"))
            .agg(expr("max_by(block, epoch) as take_block"))
        )

        # Long-typed zero array with the right length (no SQL string)
        zero_arr = array_repeat(lit(0).cast("long"), int(block_size))

        latest = (latest_before
                  .join(latest_at_end, ["extent_id","block_id"], "full_outer")
                  .select(
                      col("extent_id"),
                      col("block_id"),
                      coalesce(col("by_block"),  zero_arr).alias("by_block"),
                      coalesce(col("take_block"), zero_arr).alias("take_block"),
                  ))
        # Keep the same partitioning strategy as before
        #latest = latest.repartition(target_parts, "extent_id").sortWithinPartitions("block_id")
        
        # Drop unchanged blocks before crossing the Python boundary
        s1.mark("s1.latest_diff")
        latest_diff = (
            latest
            .filter(col("by_block") != col("take_block"))
            .select("extent_id", "block_id", "by_block", "take_block")
        )

        # --- CALL: block-debug after latest_diff ---
        s1.mark("s1.block_debug_after_latest")
        bd_state = _bd_after_latest_diff(
            spark=spark,
            mutated_ids_df=mutated_ids_df,
            latest_at_end=latest_at_end,
            latest_diff=latest_diff.select("extent_id","block_id"),
            image_path=image_path,
            blocks_per_extent=blocks_per_extent,
            block_size=block_size,
            target_parts=target_parts,
            debug=debug,
            job_timer=job_timer,   # pass the helper function itself
            audit_offsets_df=bd_state.get("audit_offsets_df"),   # <-- reuse preloaded
        )
 
        # Close Step 1 timing; defer printing to the final summary with coarse.dump()
        s1.finish()
        
        # (optional) you can repartition, but grouping will shuffle anyway
        # latest_diff = latest_diff.repartition(target_parts, "extent_id")

        metrics_dir = None
        if profile:
            metrics_dir = os.path.join(output_path, f"_regions_prof_{start_epoch}_{end_epoch}")
            try:
                os.makedirs(metrics_dir, exist_ok=True)
            except Exception:
                metrics_dir = None

        # ==========================
        # Coarse Step 2 — SAWA/Regions
        # ==========================
        coarse.mark("coarse.step2_regions")
        s2.mark("s2.pre_checks")
        # --- NEW: groupBy(extent_id) → applyInPandas to guarantee full groups per extent ---
        def _regions_apply(pdf):
            """
            pdf contains ONLY one extent_id (enforced by groupBy.applyInPandas).
            We sort/dedupe block_ids defensively, then delegate to process_extent_group_regions.
            """
            # --- BEGIN PROBE ---
            import os, json, time, uuid
            from pyspark import TaskContext

            extent_id = int(pdf["extent_id"].iloc[0]) if not pdf.empty else -1

            # Estimate bytes of the whole group in Python
            try:
                in_bytes = int(pdf.memory_usage(index=False, deep=True).sum())
            except Exception:
                in_bytes = -1

            # Basic shape signals
            n_rows = int(len(pdf))
            try:
                by_sz = int(pdf["by_block"].map(len).mean()) if "by_block" in pdf.columns else -1
                tk_sz = int(pdf["take_block"].map(len).mean()) if "take_block" in pdf.columns else -1
            except Exception:
                by_sz = tk_sz = -1

            # Task metadata + RSS if available
            tid = -1
            try:
                tc = TaskContext.get()
                if tc: tid = int(tc.taskAttemptId())
            except Exception:
                pass

            rss = -1
            try:
                import resource
                rss = int(resource.getrusage(resource.RUSAGE_SELF).ru_maxrss)  # KB on Linux
            except Exception:
                pass

            # Write a tiny metrics record per group
            try:
                outdir = os.environ.get("REGIONS_METRICS_DIR", "")  # set this env var when you call run_detection
                if outdir:
                    os.makedirs(outdir, exist_ok=True)
                    rec = {
                        "ts": time.time(),
                        "phase": "regions_apply_in",
                        "extent_id": extent_id,
                        "task": tid,
                        "rows": n_rows,
                        "pdf_bytes": in_bytes,
                        "by_arr_mean": by_sz,
                        "take_arr_mean": tk_sz,
                        "rss_kb": rss,
                    }
                    with open(os.path.join(outdir, f"grp-{extent_id}-{tid}-{uuid.uuid4().hex}.jsonl"), "a") as fh:
                        fh.write(json.dumps(rec) + "\n")
            except Exception:
                pass
            # --- END PROBE ---

            import pandas as pd
            if pdf.empty:
                # Return an empty frame with the expected schema columns (names only)
                return pd.DataFrame(columns=[
                    "extent_id","delta_block_id","lba_start_block","lba_end_block",
                    "byte_start","byte_end_inclusive","block_idx_start","block_idx_end",
                    "block_ids","first_block_offset","last_block_offset","num_blocks",
                    "chi2_min","chi2_max","chi2_var","chi2_final",
                ])
            # keep only the needed columns and normalize ordering
            pdf = pdf[["extent_id","block_id","by_block","take_block"]]
            # best-effort de-dup in case upstream fed duplicates
            pdf = (pdf
                   .drop_duplicates(subset=["extent_id","block_id"])
                   .sort_values(by=["block_id"], kind="mergesort"))
            return process_extent_group_regions(
                pdf, extent_size, block_size, min_gap_length,
                width, stride, chi2_threshold, min_expansions, max_chi2_var,
                debug, profile, metrics_dir, sawa_expand=sawa_expand,
            )

        # Ensure we don't feed duplicate rows into groups (cheap safety)
        latest_diff = latest_diff.dropDuplicates(["extent_id","block_id"])

        # === PROBES: before grouped Pandas UDF ===
        s2.mark("s2.probes")
        print("[probe] latest_diff partitions:", latest_diff.rdd.getNumPartitions())

        # A. Show the biggest groups (top 50 extent_ids by row count)
        top_groups = (latest_diff.groupBy("extent_id").count()
                      .orderBy(desc("count")).limit(50))
        print("[probe] Top groups by count (extent_id,count):")
        for r in top_groups.collect():
            print(f"[probe] group {int(r['extent_id'])} rows={int(r['count'])}")

        # B. Show per-row array widths to understand row "fatness"
        summary = (latest_diff
                   .select(size(col("by_block")).alias("by_sz"),
                           size(col("take_block")).alias("take_sz"))
                   .summary())
        print("[probe] by/take array-size summary:")
        summary.show(truncate=False)

        # C. Plan snapshot around the hotspot (cheap)
        explain_df(latest_diff, "latest_diff.before_applyInPandas")

        # D. Fail-fast guard so you get the smoking-gun extent_id instead of OOM
        MAX_ROWS_PER_GROUP = 500_000  # tune for your heap
        too_big = (latest_diff.groupBy("extent_id").count()
                   .filter(col("count") > lit(MAX_ROWS_PER_GROUP)))
        if too_big.limit(1).count():
            print("[guard] Oversized groups detected (showing top offenders):")
            too_big.orderBy(desc("count")).show(20, truncate=False)
            raise RuntimeError("Oversized extent groups; shard or stream before applyInPandas")

        s2.mark("s2.applyInPandas")
        with job_timer(spark, "regions.applyInPandas"):  # <-- tags stage in logs
            suspicious_regions_df = (
                latest_diff
                .groupBy("extent_id")
                .applyInPandas(_regions_apply, schema=region_schema)
                .withColumn("start_epoch", lit(start_epoch))
                .withColumn("end_epoch", lit(end_epoch))
            )

        s2.mark("s2.cache_regions")
        suspicious_regions_df = cache_once(
            suspicious_regions_df, spark, "regions", storage=StorageLevel.MEMORY_AND_DISK
        )
        
        # --- FIX #1: Break lineage before heavy text outputs (CSV) ---
        # This prevents recomputation of upstream joins/aggregations during the write,
        # which otherwise can bring the UnsafeExternalRowSorter back into the job.
        s2.mark("s2.region_checkpoint")
        try:
            chk = os.path.join(output_path, "_chkpt")
            os.makedirs(chk, exist_ok=True)
            spark.sparkContext.setCheckpointDir(os.path.join(output_path, "_chkpt"))
            suspicious_regions_df = suspicious_regions_df.localCheckpoint(eager=True)
        except Exception:
            pass

        # --- CALL: block-debug vs. SAWA-kept regions ---
        s2.mark("s2.block_debug_after_regions")
        _bd_after_regions(
            spark=spark,
            suspicious_regions_df=suspicious_regions_df,
            bd_state=bd_state
        )

        # quick driver-side summary (top hot extents)
        if profile and metrics_dir:
            try:
                import glob
                totals = {}
                n_regions = {}
                for fp in glob.glob(os.path.join(metrics_dir, "*.jsonl")):
                    with open(fp, "r") as fh:
                        for line in fh:
                            m = json.loads(line)
                            eid = int(m["extent_id"])
                            totals[eid] = totals.get(eid, 0.0) + float(m.get("t_total", 0.0))
                            n_regions[eid] = n_regions.get(eid, 0) + int(m.get("n_regions", 0))
                top = sorted(totals.items(), key=lambda x: x[1], reverse=True)[:10]
                print("[regions.prof] Top extents by time:")
                for eid, tt in top:
                    print(f"  extent_id={eid:<8}  t_total={tt:6.3f}s  n_regions={n_regions.get(eid,0)}")
            except Exception as e:
                print(f"[regions.prof] summary error: {e}")

        if profile:
            explain_df(suspicious_regions_df, "regions_df")
            s2.mark("s2.materialize")
            suspicious_regions_df, _ = materialize(
                suspicious_regions_df, spark, "regions.materialize",
                storage=StorageLevel.MEMORY_AND_DISK
            )
        s2.finish()
            
        # 1) Union of suspicious blocks (kept regions)
        # ============================
        # Coarse Step 3 — Block→File map
        # ============================
        coarse.mark("coarse.step3_mapping")
        s3.mark("s3.expand_kept_blocks")
        with job_timer(spark, "regions.expand_kept_blocks"):
            kept_blocks = (suspicious_regions_df
                           .select("extent_id", explode("block_ids").alias("block_id"))
                           .withColumn("block_id", col("block_id").cast("long")))  # keep types aligned
        _ = kept_blocks.limit(1).count()  # cheap action to attach the label
        if profile:
            explain_df(kept_blocks, "kept_blocks")
            kept_blocks, n_kept = materialize(
                kept_blocks, spark, "kept_blocks.materialize",
                storage=StorageLevel.MEMORY_ONLY
            )
        
        mapping_schema = StructType([
            StructField("extent_id", LongType(), False),
            StructField("block_id", LongType(), False),
            StructField("file_id", IntegerType(), False),
            StructField("file_path", StringType(), False),
            StructField("offset_bytes", LongType(), False),
            StructField("extent_start_block", LongType(), False),
            StructField("extent_end_block", LongType(), False),
        ])

        # Make sure blocks for the same extent are processed together
        s3.mark("s3.repartition_blocks")
        kept_blocks = (
            kept_blocks
            .repartition(target_parts, "extent_id")
        )

        def _map_partition(pdf_iter):
            import pandas as pd
            cur_eid = None
            seen = None

            def flush(eid, seen_blocks):
                if not seen_blocks:
                    return None
                blocks = sorted(seen_blocks)  # keep deterministic
                pdf = pd.DataFrame({"extent_id": [eid]*len(blocks), "block_id": blocks})
                return map_extent_blocks_only(pdf=pdf, image_path=image_path, block_size=block_size, debug=debug)

            for pdf in pdf_iter:
                for r in pdf.itertuples(index=False):
                    eid = int(r.extent_id); bid = int(r.block_id)
                    if cur_eid is None:
                        cur_eid = eid; seen = set()
                    if eid != cur_eid:
                        out = flush(cur_eid, seen)
                        if out is not None: yield out
                        cur_eid = eid; seen = set()
                    seen.add(bid)

            out = flush(cur_eid, seen if seen is not None else set())
            if out is not None: yield out

        s3.mark("s3.mapInPandas")
        suspicious_mappings_df = (
            kept_blocks
            .mapInPandas(_map_partition, schema=mapping_schema)
            .withColumn("start_epoch", lit(start_epoch))
            .withColumn("end_epoch", lit(end_epoch))
        )

        if profile:
            explain_df(suspicious_mappings_df, "mappings_df")
            s3.mark("s3.materialize")
            suspicious_mappings_df, n_maps = materialize(
                suspicious_mappings_df, spark, "mappings.materialize",
                storage=StorageLevel.MEMORY_ONLY
            )

        # --- MEMORY-EFFICIENT: audit vs suspicious_mappings_df (keys only) ---
        bd_cfg = getattr(run_detection, "_bd_cfg", None)
        if bd_cfg and bd_cfg.get("enabled", False):
            s3.mark("s3.block_debug_after_mappings")
            _bd_after_mappings(
                spark=spark,
                suspicious_mappings_df=suspicious_mappings_df.select("file_path", "offset_bytes"),
                bd_state=bd_state,  # from _bd_after_latest_diff
                path_match=bd_cfg.get("path_match", "basename"),
                bd_outdir=bd_cfg["outdir"],
            )
        s3.finish()
        
        if bd_state.get("audit_device_blocks_df") is not None:
            bd_state["audit_device_blocks_df"].unpersist()
        if bd_state.get("audit_offsets_df") is not None:
            bd_state["audit_offsets_df"].unpersist()
            
        # =========================================
        # Coarse Step 4 — Trust + File-aware filter
        # =========================================
        coarse.mark("coarse.step4_trust_fileaware")
        s4.mark("s4.load_inventory")
        # ---- 6) Inventory + trusted filter (single-source) ----
        inventory_path = os.path.join(output_path, "file_inventory.json")
        inv = _load_inventory_db(inventory_path)
        
        s4.mark("s4.parse_manifest")
        comp_hashes, file_hashes = _parse_trusted_manifest(spark, trusted_manifest)

        # Seed inventory *file-level* trusted set with only file hashes
        if file_hashes:
            inv["trusted_sha256"] = sorted(
                set(inv.get("trusted_sha256", [])) | {h.lower() for h in file_hashes}
            )

        # Build a fast set for file-level membership checks
        inv_trusted_files = set(inv.get("trusted_sha256", []))

        if not end_mount_root:
            if debug:
                print("[trust] --end-mount-root not provided; cannot hash files; trusted drop disabled.")
            trust_rows = []
        else:
            s4.mark("s4.hash_suspect_files")
            fs_end = ("mount", os.path.abspath(end_mount_root))
            # Stream paths to the driver to avoid collect() blow-ups
            suspect_paths_iter = (
                row["file_path"]
                for row in suspicious_mappings_df.select("file_path").distinct().toLocalIterator()
            )
            trust_rows = []
            for fp in suspect_paths_iter:
                sha_hex, sizeb = _fs_sha256(fs_end, fp)
                sha_l = (sha_hex.lower() if isinstance(sha_hex, str) else None)
                is_trusted = bool(sha_l and (sha_l in inv_trusted_files))

                prev = inv["files"].get(fp, {})
                first_seen = prev.get("first_seen_epoch", end_epoch)
                inv["files"][fp] = {
                    "sha256": sha_l,
                    "size_bytes": int(sizeb) if sizeb is not None else None,
                    "trusted": is_trusted,
                    "first_seen_epoch": min(first_seen, end_epoch),
                    "last_seen_epoch": end_epoch,
                }

                trust_rows.append({
                    "file_path": fp,
                    "sha256": sha_l,
                    "size_bytes": int(sizeb) if sizeb is not None else None,
                    "trusted": is_trusted,
                })

                if is_trusted and sha_l:
                    inv_trusted_files.add(sha_l)

        # Persist inventory (dedup happens in _save_inventory_db)
        inv["trusted_sha256"] = sorted(inv_trusted_files)
        try:
            s4.mark("s4.persist_inventory")
            _save_inventory_db(inventory_path, inv)
        except Exception as e:
            print(f"[warn] Unable to persist {inventory_path}: {e} (continuing)")

        # If we have trusted hashes, drop trusted paths and update regions accordingly
        if inv_trusted_files and end_mount_root:
            s4.mark("s4.drop_trusted_paths")
            trusted_paths = [fp for fp, info in inv["files"].items() if info.get("trusted")]
            trusted_schema = StructType([StructField("file_path", StringType(), False)])
            if trusted_paths:
                trusted_paths_df = spark.createDataFrame([(p,) for p in trusted_paths], schema=trusted_schema)
            else:
                # Create a truly empty DF with the right schema
                trusted_paths_df = spark.createDataFrame(spark.sparkContext.emptyRDD(), schema=trusted_schema)
                if debug:
                    print("[trust] No trusted file paths found in end snapshot; skipping trusted drop.")

            all_mappings_df = suspicious_mappings_df
            suspicious_mappings_df = all_mappings_df.join(trusted_paths_df, on="file_path", how="left_anti")

            regions_with_id = suspicious_regions_df.withColumn("region_id", monotonically_increasing_id())
            reg_blocks = (regions_with_id
                          .select("region_id", explode("block_ids").alias("block_id"))
                          .withColumn("block_id", col("block_id").cast("long")))

            all_mapped_blocks = (all_mappings_df
                                 .select("block_id").distinct()
                                 .withColumn("is_mapped", lit(1)))

            trusted_mapped_blocks = (all_mappings_df
                                     .join(trusted_paths_df, on="file_path", how="inner")
                                     .select("block_id").distinct()
                                     .withColumn("is_trusted", lit(1)))

            reg_flags = (reg_blocks
                         .join(all_mapped_blocks, on="block_id", how="left")
                         .join(trusted_mapped_blocks, on="block_id", how="left")
                         .withColumn("is_mapped",  coalesce(col("is_mapped"),  lit(0)))
                         .withColumn("is_trusted", coalesce(col("is_trusted"), lit(0)))
                         .groupBy("region_id")
                         .agg(
                             spark_count(lit(1)).alias("total"),
                             spark_sum(col("is_mapped")).alias("mapped"),
                             spark_sum(col("is_trusted")).alias("trusted_mapped"),
                         )
                         .withColumn(
                             "keep_region",
                             (col("mapped") < col("total")) | (col("trusted_mapped") < col("mapped"))
                         ))

            suspicious_regions_df = (regions_with_id
                                     .join(reg_flags.filter(col("keep_region") == True).select("region_id"),
                                           on="region_id", how="inner")
                                     .drop("region_id"))
        else:
            if debug:
                print("[trust] No trusted hashes to drop or hashing disabled; keeping all suspect paths for file-aware stage.")

        # Optional: keep your per-run audit for convenience
        if end_mount_root:
            trust_schema = StructType([
                StructField("file_path",  StringType(),  False),
                StructField("sha256",     StringType(),  True),
                StructField("size_bytes", LongType(),    True),
                StructField("trusted",    BooleanType(), True),
            ])
            trust_df = spark.createDataFrame(trust_rows, schema=trust_schema)
            if end_mount_root and audit_formats and trust_rows:
                s4.mark("s4.audit_artifacts")
                trust_parquet_out = os.path.join(output_path, f"trusted_new_files_{start_epoch}_{end_epoch}.parquet")
                trust_csv_out_dir = os.path.join(output_path, f"trusted_new_files_{start_epoch}_{end_epoch}_csv")
                if "parquet" in audit_formats:
                    trust_df.write.mode("overwrite").parquet(trust_parquet_out)
                if "csv" in audit_formats:
                    trust_df.write.mode("overwrite").option("header", True).csv(trust_csv_out_dir)
        
        # === Phase 3: File-aware filter (OOXML/ZIP, JPEG) ===
        from detector.fileaware import pick_handler
        from detector.fileaware.types import FileContext, SuspiciousFileRegion
        
        def _ranges_from_offsets_no_merge(offsets: List[int], step: int) -> List[Tuple[int,int]]:
            """
            Produce one [start, end] byte range per offset, WITHOUT merging adjacent
            blocks. Each block-sized offset becomes an independent range.
            """
            offs_sorted = sorted({int(x) for x in offsets})
            return [(o, o + step - 1) for o in offs_sorted]

        def _merge_consecutive_offsets(offsets: List[int], step: int) -> List[Tuple[int,int]]:
            if not offsets: return []
            offsets = sorted(set(int(x) for x in offsets))
            ranges = []
            s = e = offsets[0]
            for v in offsets[1:]:
                if v == e + step:
                    e = v
                else:
                    ranges.append((s, e + step - 1))
                    s = e = v
            ranges.append((s, e + step - 1))
            return ranges

        def _peek_magic(fs_root: str, fp: str, n=8) -> Optional[bytes]:
            try:
                p = os.path.join(fs_root, fp.lstrip("/"))
                with open(p, "rb") as f: return f.read(n)
            except Exception:
                return None

        # 3.1 Collect per-file suspicious offsets (file-relative)
        block_step = int(block_size)
        #block_step = min_gap_length
        s4.mark("s4.fileaware_collect")
        if profile:
            t0 = time.perf_counter()
        per_file = (suspicious_mappings_df
                    .groupBy("file_path")
                    .agg(expr("collect_list(offset_bytes) as offs")))

        if profile:
            # Force the groupBy to happen and measure it, but don’t pull data to driver.
            _ = per_file.count()
            print(f"[profile] per_file.groupBy+collect_list: {time.perf_counter() - t0:.3f}s")

        # Stream to driver to reduce peak memory
        if profile:
            with wall("driver.per_file_toLocalIterator"):
                per_file_rows = (
                    (r["file_path"], r["offs"])
                    for r in per_file.toLocalIterator()
                    if r["file_path"]
                )
        else:
            per_file_rows = (
                (r["file_path"], r["offs"])
                for r in per_file.toLocalIterator()
                if r["file_path"]
            )
        
        # 3.2 Build trusted component hash set from the single-source inventory
        # We already parsed the manifest earlier in this function:
        #   comp_hashes = ALL manifest hashes (embedded + stand-alone)
        #   file_hashes = stand-alone file hashes
        # Handlers need component-level trust (raw stream/entry/file bytes)
        trusted_component_hashes = set(comp_hashes)  # already includes file-hash rows

        # 3.3 Decide per file (driver) -- WITH per-region decisions
        fs_root = os.path.abspath(end_mount_root) if end_mount_root else None
        if not fs_root and debug:
            print("[fileaware] --end-mount-root not provided; deep inspection disabled; conservative keep.")

        from detector.fileaware.types import FileAwareDecision, RegionDecision

        decisions: Dict[str, FileAwareDecision] = {}  # fp -> decision (with region_decisions)
        file_rows = []    # (file_path, keep_file, reason)
        range_rows = []   # (file_path, start, end, keep_region, reason)

        if profile:
            n_files = 0
            t0 = time.perf_counter()

        s4.mark("s4.fileaware_decide")
        for fp, offs in per_file_rows:
            # STOP MERGING contiguous blocks before file-aware filters.
            # Each block-sized offset becomes its own byte-range.
            ranges = _ranges_from_offsets_no_merge(offs, step=block_step)
            reg = SuspiciousFileRegion(byte_ranges=ranges, chi2_summary=None)

            sha_hex, sizeb = _fs_sha256(("mount", fs_root), fp) if fs_root else (None, None)
            ctx = FileContext(
                file_path=fp,
                fs_root=fs_root,
                sha256=(sha_hex.lower() if sha_hex else None),
                size_bytes=sizeb,
                trusted_hashes=trusted_component_hashes,
                params={
                    "decompress_budget_bytes": 100*1024*1024,
                    "chi2_threshold": float(chi2_threshold),
                    "chi2_uniform_thresh": 350.0,
                    "chi2_plaintext_thresh": 2000.0,
                    "sawa_width_bytes": max(64*1024, width*block_size*4),
                    "sawa_stride_bytes": max(16*1024, stride*block_size*4),
                    "mp3_min_decode_bytes": 4096,
                    "trusted_manifest_csv": (trusted_manifest or ""),
                    "debug_pdf_prelude": True,
                    "debug_pdf_textish": True,
                    "debug_pdf_streams": True,
                    "debug_pdf_gaps": True,
                    "debug_pdf_gap_kinds": True,
                    "ooxml_debug": 0,
                    "zip_debug": 0,
                    "txt_debug": 1, 
                },
            )
            magic = _peek_magic(fs_root, fp, n=8) if fs_root else None
            handler = pick_handler(fp, magic)
            try:
                dec = handler.decide(ctx, reg)
                handler_name = handler.__class__.__name__
            except Exception as e:
                dec = FileAwareDecision(keep_file=True, reason=f"fileaware exception: {e}", region_decisions=None)
                handler_name = handler.__class__.__name__

            decisions[fp] = dec
            file_rows.append((fp, bool(dec.keep_file), f"{handler_name}: {dec.reason}"))

            # Collect region-level rows (if provided)
            if dec.region_decisions:
                for rd in dec.region_decisions:
                    range_rows.append((fp, int(rd.start), int(rd.end), bool(rd.keep), str(rd.reason)))

            if profile:
                n_files += 1

        if profile:
            print(f"[profile] fileaware.decide loop: {time.perf_counter() - t0:.3f}s, files={n_files}")

        # 3.4 Apply decisions back to Spark — region-level filtering of blocks
        # File-level audit DF (always)
        decisions_schema = StructType() \
            .add("file_path", StringType(), False) \
            .add("keep_file", BooleanType(), False) \
            .add("fileaware_reason", StringType(), True)
        file_decisions_df = spark.createDataFrame(file_rows, schema=decisions_schema) if file_rows \
            else spark.createDataFrame(spark.sparkContext.emptyRDD(), schema=decisions_schema)

        # Region-level audit DF (optional)
        region_decisions_schema = StructType() \
            .add("file_path", StringType(), False) \
            .add("start", LongType(), False) \
            .add("end", LongType(), False) \
            .add("keep_region", BooleanType(), False) \
            .add("reason", StringType(), True)
        region_decisions_df = spark.createDataFrame(range_rows, schema=region_decisions_schema) if range_rows \
            else spark.createDataFrame(spark.sparkContext.emptyRDD(), schema=region_decisions_schema)

        # If we have region decisions, keep ONLY mappings whose (file_path, offset_bytes) fall
        # into at least one kept region [start..end]. We do this by expanding kept ranges to block offsets.
        if region_rows := len(range_rows):
            s4.mark("s4.apply_region_decisions")
            kept_ranges = region_decisions_df.filter(col("keep_region") == True)

            # Expand [start..end] to block indices and offsets; use Spark sequence()
            # start_idx = floor(start/B), end_idx = floor(end/B), then offset_bytes = idx*B
            B = int(block_size)
            kept_offsets_df = (
                kept_ranges
                .withColumn("start_idx", floor(col("start") / lit(B)))
                .withColumn("end_idx",   floor(col("end")   / lit(B)))
                .withColumn("block_idx", explode(sequence(col("start_idx"), col("end_idx"))))
                .withColumn("offset_bytes", col("block_idx") * lit(B))
                .select("file_path", "offset_bytes")
                .dropDuplicates()
            )

            # Filter suspicious_mappings_df to only offsets inside kept regions
            suspicious_mappings_df = (
                suspicious_mappings_df
                .join(kept_offsets_df.hint("broadcast"), ["file_path", "offset_bytes"], "inner")
            )
            
            # --- block-debug: log kept "untrusted" regions -> block mappings
            bd_cfg = getattr(run_detection, "_bd_cfg", None)
            if bd_cfg and bd_cfg.get("enabled", False):
                # Offsets from the subset of kept ranges whose reason mentions "untrusted"
                untrusted_offsets_df = (
                    kept_ranges
                    .filter(lower(col("reason")).contains("untrusted"))
                    .withColumn("start_idx", floor(col("start") / lit(B)))
                    .withColumn("end_idx",   floor(col("end")   / lit(B)))
                    .withColumn("block_idx", explode(sequence(col("start_idx"), col("end_idx"))))
                    .withColumn("offset_bytes", col("block_idx") * lit(B))
                    .select("file_path", "offset_bytes")
                    .dropDuplicates()
                )

                # Map those offsets to blocks (file_path, block_id, offset_bytes)
                untrusted_maps_df = (
                    suspicious_mappings_df
                    .join(broadcast(untrusted_offsets_df), ["file_path", "offset_bytes"], "inner")
                    .select("file_path", "block_id", "offset_bytes")
                    .dropDuplicates()
                )

                _bd_write_csv(untrusted_maps_df, bd_cfg["outdir"], "audit_untrusted_immutable_block_mappings_csv")

        else:
            s4.mark("s4.apply_file_level_decisions")
            # Fallback: file-level keep/drop (legacy behavior)
            suspicious_mappings_df = (
                suspicious_mappings_df
                .join(file_decisions_df, on="file_path", how="left")
                .fillna({"keep_file": True})
                .filter(col("keep_file") == True)
                .drop("keep_file", "fileaware_reason")
            )
            # --- block-debug: if no region decisions, log kept files whose file-level reason mentions "untrusted"
            bd_cfg = getattr(run_detection, "_bd_cfg", None)
            if bd_cfg and bd_cfg.get("enabled", False):
                untrusted_files = (
                    file_decisions_df
                    .filter((col("keep_file") == True) & lower(col("fileaware_reason")).contains("untrusted"))
                    .select("file_path")
                    .dropDuplicates()
                )
                
                untrusted_maps_df = (
                    suspicious_mappings_df
                    .join(broadcast(untrusted_files), "file_path", "inner")
                    .select("file_path", "block_id", "offset_bytes")
                    .dropDuplicates()
                )

                _bd_write_csv(untrusted_maps_df, bd_cfg["outdir"], "audit_untrusted_immutable_block_mappings_csv")

        if profile:
            explain_df(suspicious_mappings_df, "mappings_after_decision_join")
            suspicious_mappings_df, _ = materialize(
                suspicious_mappings_df, spark, "mappings.after_decision.materialize",
                storage=StorageLevel.MEMORY_ONLY
            )
        
        # Regions: keep only those that map to kept files (coarse: any block of region in a kept file)
        s4.mark("s4.regions_keep_update")
        regions_with_id = suspicious_regions_df.withColumn("region_id", monotonically_increasing_id())
        reg_blocks = (regions_with_id
                      .select("region_id", "extent_id", "delta_block_id", explode("block_ids").alias("block_id")))
        blk2file = (suspicious_mappings_df.select("block_id", "file_path").distinct())
        kept_regions = (reg_blocks.join(blk2file, "block_id", "inner")
                        .select("region_id").distinct())
        suspicious_regions_df = (regions_with_id.join(kept_regions, "region_id", "inner")
                                 .drop("region_id"))
        
        if profile:
            explain_df(suspicious_regions_df, "regions_after_keep")
            suspicious_regions_df, _ = materialize(
                suspicious_regions_df, spark, "regions.after_keep.materialize",
                storage=StorageLevel.MEMORY_ONLY
            )
        
        # --- Write file-aware audit artifacts (optional) ---
        if end_mount_root and audit_formats:
            s4.mark("s4.fileaware_audit_artifacts")
            if "parquet" in audit_formats:
                file_decisions_df.write.mode("overwrite").parquet(
                    os.path.join(output_path, f"fileaware_files_{start_epoch}_{end_epoch}.parquet")
                )
                region_decisions_df.write.mode("overwrite").parquet(
                    os.path.join(output_path, f"fileaware_regions_{start_epoch}_{end_epoch}.parquet")
                )
            if "csv" in audit_formats:
                file_decisions_df.write.mode("overwrite").option("header", True).csv(
                    os.path.join(output_path, f"fileaware_files_{start_epoch}_{end_epoch}_csv")
                )
                region_decisions_df.write.mode("overwrite").option("header", True).csv(
                    os.path.join(output_path, f"fileaware_regions_{start_epoch}_{end_epoch}_csv")
                )
        s4.finish()
        if debug:
            print("[dbg] regions partitions:", suspicious_regions_df.rdd.getNumPartitions())
            print("[dbg] mappings partitions:", suspicious_mappings_df.rdd.getNumPartitions())
            suspicious_regions_df.explain(False)   # logical+physical plan; no job
            suspicious_mappings_df.explain(False)
        
        # =====================
        # Coarse Step 5 — Output
        # =====================
        coarse.mark("coarse.step5_outputs")
        # ---- 8) Write outputs (minimize extra jobs) ----
        regions_parquet_out = os.path.join(output_path, f"suspicious_regions_{start_epoch}_{end_epoch}.parquet")
        regions_csv_out_dir = os.path.join(output_path, f"suspicious_regions_{start_epoch}_{end_epoch}_csv")
        parquet_out        = os.path.join(output_path, f"suspicious_block_mappings_{start_epoch}_{end_epoch}.parquet")
        csv_out_dir        = os.path.join(output_path, f"suspicious_block_mappings_{start_epoch}_{end_epoch}_csv")

        # Keep write tasks small to avoid OOM in UnsafeExternalRowSorter/FileFormatWriter
        # --- FIX #3: Increase partition count for writes so each shuffle partition is smaller.
        # (Applies to both Parquet and CSV; harmless for Parquet, protective for CSV.)
        # Previously: max(256, target_parts * 2)
        write_parts = max(512, target_parts * 8)
        
        #if need_regions_both:
        #    suspicious_regions_df = suspicious_regions_df.persist(StorageLevel.MEMORY_AND_DISK)

        # regions → Parquet
        if "parquet" in out_formats:
            s5.mark("s5.write_regions_parquet")
            with job_timer(spark, "write_regions_parquet"):
                suspicious_regions_df.repartition(write_parts).write.mode("overwrite").parquet(regions_parquet_out)
            print(f"[Stage 3] Wrote suspicious region summaries (Parquet): {regions_parquet_out}")

        # regions → CSV (create JSON view only when needed)
        if "csv" in out_formats:
            s5.mark("s5.write_regions_csv")
            with job_timer(spark, "write_regions_csv"):
                # --- FIX #2: Partition by a stable key to reduce skew vs. round-robin.
                # Repartitioning by "extent_id" spreads large rows more predictably.
                (suspicious_regions_df
                 .repartition(write_parts, "extent_id")
                 .select(
                     "extent_id","delta_block_id","lba_start_block","lba_end_block",
                     "byte_start","byte_end_inclusive","block_idx_start","block_idx_end",
                     to_json(col("block_ids")).alias("block_ids"),
                     "first_block_offset","last_block_offset","num_blocks",
                     "chi2_min","chi2_max","chi2_var","chi2_final",
                     "start_epoch","end_epoch"
                 )
                 .write.mode("overwrite").option("header", True).csv(regions_csv_out_dir)
                 )
            print(f"[Stage 3] Wrote suspicious region summaries (CSV dir): {regions_csv_out_dir}")

        if debug:
            print(f"[dbg] regions_emitted (acc): {regions_acc.value}")  # ← print here

        suspicious_regions_df.unpersist()
        mutations.unpersist()

        #if need_maps_both:
        #    suspicious_mappings_df = suspicious_mappings_df.persist(StorageLevel.MEMORY_AND_DISK)

        # mappings → Parquet
        if "parquet" in out_formats:
            s5.mark("s5.write_mappings_parquet")
            with job_timer(spark, "write_mappings_parquet"):
                suspicious_mappings_df.repartition(write_parts).write.mode("overwrite").parquet(parquet_out)
            print(f"[Stage 3] Wrote suspicious block→file mappings (Parquet): {parquet_out}")

        # mappings → CSV
        if "csv" in out_formats:
            s5.mark("s5.write_mappings_csv")
            with job_timer(spark, "write_mappings_csv"):
                (suspicious_mappings_df.repartition(write_parts)
                 .write.mode("overwrite").option("header", True).csv(csv_out_dir)
                 )
            print(f"[Stage 3] Wrote suspicious block→file mappings (CSV dir): {csv_out_dir}")
        s5.finish()
            
        #if need_maps_both:
        #    suspicious_mappings_df.unpersist()

        # Print coarse summary before returning
        coarse.finish()
        # Include fine-grained timings for all steps used
        s1.dump(label="Step 1 fine profile (summary)")
        s2.dump(label="Step 2 fine profile (summary)")
        s3.dump(label="Step 3 fine profile (summary)")
        s4.dump(label="Step 4 fine profile (summary)")
        s5.dump(label="Step 5 fine profile (summary)")
        coarse.dump()

        return parquet_out, csv_out_dir, regions_parquet_out, regions_csv_out_dir

    finally:
        spark.stop()
        
def parse_args():
    p = argparse.ArgumentParser(description="Rhea Detection Pipeline")
    p.add_argument("--start-epoch", type=int, required=True, help="Start epoch for analysis window")
    p.add_argument("--end-epoch", type=int, required=True, help="End epoch for analysis window")
    p.add_argument("--snapshot-path", type=str, default="./data/snapshot", help="Path to mutation snapshots")
    p.add_argument("--output-path", type=str, default="./data/suspicious", help="Path for suspicious mappings")
    p.add_argument("--extent-size", type=int, default=4096, help="Extent size in bytes (default: 4096)")
    p.add_argument("--block-size", type=int, default=512, help="Block size in bytes (default: 512)")
    p.add_argument("--min-gap-length", type=int, default=16, help="Minimum gap length for delta extraction")
    p.add_argument("--width", type=int, default=16, help="Initial SAWA window width")
    p.add_argument("--stride", type=int, default=4, help="SAWA window stride")
    p.add_argument("--chi2-threshold", type=int, default=350, help="Chi-squared threshold for SAWA")
    p.add_argument("--min-expansions", type=int, default=2, help="Minimum successful doublings before a region is considered")
    p.add_argument("--max-chi2-var", type=float, default=75.0, help="Maximum allowed variance of chi2 across expansion+final")
    p.add_argument("--trusted-manifest", type=str, default=None, help="CSV/JSON containing a 'sha256' column (lower/upper OK).")
    p.add_argument("--end-mount-root", type=str, default=None,
                   help="Path where device_<end>.img is already mounted (read-only). "
                   "Required when --trusted-manifest is provided.")
    p.add_argument("--out-formats", type=str, default="parquet", help="Comma-separated output formats for main artifacts: 'parquet', 'csv', or 'parquet,csv'.")
    p.add_argument("--audit-formats", type=str, default="parquet", help="Comma-separated formats for audit artifacts: 'parquet', 'csv', 'parquet,csv', or 'none'.")
    p.add_argument("--debug", action="store_true", help="Enable debug output")
    p.add_argument("--profile", action="store_true", help="Enable profiling")
    p.add_argument("--block-debug", action="store_true",
                   help="Enable block-level debug comparing detector vs. persim audit.")
    p.add_argument("--block-debug-audit", type=str, default=None,
                   help="Path to persim audit NDJSON (audit_*.ndjson).")
    p.add_argument("--block-debug-outdir", type=str, default=None,
                   help="Directory to write block-debug CSVs. Defaults to <output-path>/block_debug_<start>_<end>.")
    p.add_argument("--block-debug-path-match", type=str, default="basename",
                   choices=["basename", "full"],
                   help="How to match file paths between detector and audit (default: basename).")
    p.add_argument("--no-sawa-expand", dest="sawa_expand", action="store_false", default=True, help="Disable SAWA adaptive window expansion (default: expansion enabled).",
)
    return p.parse_args()

def main():
    args = parse_args()

    def _fmtset(s: Optional[str]) -> Set[str]:
        s = (s or "").lower().strip()
        if not s or s == "none":
            return set()
        return {x.strip() for x in s.split(",") if x.strip()}

    args.out_formats = _fmtset(args.out_formats)
    args.audit_formats = _fmtset(args.audit_formats)

    os.makedirs(args.output_path, exist_ok=True)
     
    # Validate inputs early (fail fast with actionable messages)
    end_img = os.path.join(args.snapshot_path, f"device_{args.end_epoch}.img")
    if not os.path.exists(end_img):
        print(f"[error] Missing device image for end epoch: {end_img}")
        print("        Ensure the preprocessor produced 'device_<end_epoch>.img' in --snapshot-path.")
        raise SystemExit(2)
    end_parquet = os.path.join(args.snapshot_path, f"mutation_{args.end_epoch}.parquet")
    if not os.path.exists(end_parquet):
        print(f"[error] Missing parquet snapshot for end epoch: {end_parquet}")
        raise SystemExit(2)
    start_parquet = os.path.join(args.snapshot_path, f"mutation_{args.start_epoch}.parquet")
    if not os.path.exists(start_parquet):
        print(f"[error] Missing parquet snapshot for start epoch: {start_parquet}")
        raise SystemExit(2)
    if args.trusted_manifest:
        if not args.end_mount_root or not os.path.isdir(args.end_mount_root):
            print("[error] --trusted-manifest was provided, but --end-mount-root is missing or not a directory.")
            raise SystemExit(2)

    # --- Block-debug config: enable even without audit path (assume empty audit) ---
    no_audit_fallback = bool(args.block_debug and not args.block_debug_audit)
    run_detection._bd_cfg = {
        # Enable when --block-debug is present, even if no audit file was provided
        "enabled": bool(args.block_debug),
        "audit": args.block_debug_audit,  # may be None
        "outdir": args.block_debug_outdir or os.path.join(
            args.output_path, f"block_debug_{args.start_epoch}_{args.end_epoch}"
        ),
        "path_match": args.block_debug_path_match,  # default is "basename"
        "assume_no_audit": no_audit_fallback,
    }
        
    parquet_out, csv_out_dir, regions_parquet_out, regions_csv_out_dir = run_detection(
        start_epoch=args.start_epoch,
        end_epoch=args.end_epoch,
        snapshot_path=args.snapshot_path,
        output_path=args.output_path,
        extent_size=args.extent_size,
        block_size=args.block_size,
        min_gap_length=args.min_gap_length,
        width=args.width,
        stride=args.stride,
        chi2_threshold=args.chi2_threshold,
        min_expansions=args.min_expansions,
        max_chi2_var=args.max_chi2_var,
        trusted_manifest=args.trusted_manifest,
        end_mount_root=args.end_mount_root,
        out_formats=args.out_formats,
        audit_formats=args.audit_formats,
        debug=args.debug,
        profile=args.profile,
        sawa_expand=args.sawa_expand,
    )

    print("[detect] Done.")
    if "parquet" in args.out_formats:
        print(f"         Block→File Parquet: {parquet_out}")
    if "csv" in args.out_formats:    
        print(f"         Block→File CSV dir: {csv_out_dir}")
    if "parquet" in args.out_formats:
        print(f"         Regions Parquet   : {regions_parquet_out}")
    if "csv" in args.out_formats:    
        print(f"         Regions CSV dir   : {regions_csv_out_dir}")


#############################
#       ENTRY POINT         #
#############################

if __name__ == "__main__":
    main()
