#!/usr/bin/env python3
"""
pdf_fav.py (v1 skeleton)

Specification-based validator for PDF files (self-contained).

Design goals
- Match zip_fav.py runner structure:
  - analyze_file() returns a unified CSV-row dict
  - run directory: out/run_YYYYMMDD-HHMMSS_mode-pdf_fav/
  - config.json + results.csv
- Re-implement the core approach used in pdf.py:
  - stream boundary scanning
  - basic dictionary parsing around streams
  - filter decoding (bounded, DoS-resistant)
- IMPORTANT DIFFERENCE vs pdf.py typical pipeline usage:
  - pdf_fav.py treats the entire file as suspicious and examines the whole file.

v1 invariants (pragmatic, conservative)
- Header contains "%PDF-x.y" near the beginning.
- Tail contains "startxref" and "%%EOF" near the end.
- For each detected stream:
  - stream/endstream pairing is consistent.
  - stream payload is in-bounds.
  - Filter chain (if any) is supported and decodable under budgets.
  - If FlateDecode uses PNG predictor, apply minimal predictor decoding.
- Optional (contractual) payload invariants via publisher whitelist:
  - Scan for embedded image and font streams and compute sha256 over the raw
    stream payload bytes (exact bytes between 'stream' EOL and 'endstream').
  - If --whitelist-dir is set, any image/font stream payload hash not present
    in the whitelist is treated as suspicious (contract violation => attack).

Unified output schema matches txt_fav.py / content_detector.py:
    file_path, window_size, stride, tail_mode, file_size, num_windows,
    num_suspicious_windows, min_score, max_score, score_threshold, mode,
    verdict, note, error

For pdf_fav:
- window_size/stride/tail_mode are retained for schema compatibility but unused.
- We map:
    num_windows            := num_components (prelude/tail + per-stream components)
    num_suspicious_windows := suspicious_components
    min_score/max_score    := 0/1
    score_threshold        := 0

Patch highlights (v1.1 diagnostics + robustness)
- Prefer /Length-based stream slicing when available:
  * /Length <int> direct
  * /Length <obj> <gen> R indirect (xref-less regex resolve, bounded)
- Keep note compact; write rich decode diagnostics to stderr when enabled.
"""

# ------------------------------------------------------------
# How to run pdf_fav.py (examples)
# ------------------------------------------------------------
#
# 1) Analyze a single PDF file:
#   python3 pdf_fav.py \
#     --input-path /path/to/sample.pdf \
#     --output-path /path/to/out/
#
# 2) Analyze all files in a *flat* directory (no recursion):
#   python3 pdf_fav.py \
#     --input-path /path/to/pdf_dir/ \
#     --output-path /path/to/out/
#
# 3) Analyze PDFs with publisher-provided stream whitelist (recommended for PDF):
#   python3 pdf_fav.py \
#     --input-path /path/to/pdf_dir/ \
#     --output-path /path/to/out/ \
#     --whitelist-dir /path/to/whitelist_run_dir/ \
#     --whitelist-file pdf_stream_whitelist.json
#
# Output:
#   A new run directory will be created under --output-path, e.g.
#     out/run_20251228-235959_mode-pdf_fav/
#   It will contain:
#     - config.json    (the exact run configuration)
#     - results.csv    (one row per analyzed file)
#
# ------------------------------------------------------------
# Validation model (pdf_fav v1)
# ------------------------------------------------------------
#
# pdf_fav applies specification-based and contract-based validation to PDFs.
# It treats the entire file as potentially suspicious and inspects all streams.
#
# File-wide invariants:
#   - A "%PDF-x.y" header appears near the beginning of the file.
#   - "startxref" appears near the end of the file.
#   - "%%EOF" appears at the end of the file tail.
#
# Stream-level invariants:
#   - Each "stream" has a matching "endstream".
#   - Stream payload boundaries are in-bounds.
#   - If /Filter is present, the filter chain must be supported.
#   - Supported filters are decoded under strict DoS budgets.
#   - PNG predictors (Predictor 10..15) are minimally handled for FlateDecode.
#
# ------------------------------------------------------------
# Whitelist-based validation for opaque streams
# ------------------------------------------------------------
#
# Motivation:
#   PDF image and font streams often contain opaque binary payloads
#   (e.g., JPEG images, embedded fonts) whose internal structure is
#   weakly constrained by the PDF specification.
#
#   Under a "clean PDF" contract, these payloads are expected to be
#   immutable after publication.
#
# Contract assumptions (caller responsibility):
#   - PDFs are cleanly rewritten (no incremental update history retained).
#   - Editors do not recompress, optimize, or rewrite image/font streams.
#   - Any violation of these assumptions is treated as an attack.
#
# Whitelist behavior:
#   - pdf_fav scans the PDF and identifies:
#       * Image streams: stream dict contains "/Subtype /Image"
#       * Font streams: objects referenced by /FontFile, /FontFile2, /FontFile3
#   - For each such stream, pdf_fav computes:
#       sha256(raw_stream_payload_bytes)
#     where "raw_stream_payload_bytes" are the exact bytes between
#     "stream" and "endstream" (excluding the delimiter EOL).
#
#   - The whitelist JSON file is generated offline from trusted PDFs.
#   - During validation:
#       * If the PDF is not present in the whitelist (keyed by pdf_sha256),
#         the file is suspicious.
#       * If any image/font stream hash is missing from the whitelist,
#         the file is suspicious.
#
# Verdict mapping:
#   - Any whitelist violation => suspicious component => verdict=encrypted
#   - No violations => verdict=benign
#
# ------------------------------------------------------------
# Intent and defaults
# ------------------------------------------------------------
#
# - pdf_fav only evaluates files with ".pdf" extension by default.
#   Non-PDF files => verdict=not_evaluated, note=not_pdf_intent
#
# - window_size / stride / tail_mode fields are retained only for
#   output schema compatibility and are not used by pdf_fav.
#
# ------------------------------------------------------------
# DoS resistance knobs
# ------------------------------------------------------------
#
#   --max-decoded-total-bytes
#       Total decoded bytes allowed across all streams (default: 32 MiB).
#
#   --max-dict-backscan-bytes
#       Maximum bytes to scan backward from "stream" to locate the
#       preceding "<<...>>" dictionary (default: 64 KiB).
#
#   --max-streams
#       Maximum number of streams to scan before aborting (default: 200,000).
#
# ------------------------------------------------------------


from __future__ import annotations

import argparse
import base64
import binascii
import csv
import hashlib
import json
import mmap
import os
import re
import sys
import zlib
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Dict, Iterable, List, Optional, Tuple, Set

# ----------------------------
# Unified schema defaults (compat)
# ----------------------------

DEFAULT_SCORE_THRESHOLD = 0
DEFAULT_WINDOW_SIZE = 4096   # unused (schema compatibility)
DEFAULT_STRIDE = 4096        # unused (schema compatibility)
DEFAULT_TAIL_MODE = "ignore" # unused (schema compatibility)


# ----------------------------
# Regex / constants
# ----------------------------

PDF_HEADER_RE = re.compile(rb"%PDF-\d\.\d")
STARTXREF_RE  = re.compile(rb"\bstartxref\b")
EOF_RE        = re.compile(rb"%%EOF\s*$", re.DOTALL)

DICT_RE       = re.compile(rb"<<.*?>>", re.DOTALL)
FILTER_RE     = re.compile(rb"/Filter\s+(?P<val>(\[.*?\]|/\S+))", re.DOTALL)
DECODEPARMS_RE = re.compile(rb"/DecodeParms\s+(?P<val>(\[.*?\]|<<.*?>>))", re.DOTALL)
NAME_RE       = re.compile(rb"/([A-Za-z0-9\-\+\.]+)")

# Whitelist-related patterns (contractual payload invariants)
OBJ_HDR_BACKSCAN_RE = re.compile(rb"(?m)^[ \t]*([0-9]+)[ \t]+([0-9]+)[ \t]+obj\b")
FONTFILE_REF_RE = re.compile(rb"/FontFile(?:2|3)?[ \t\r\n]+([0-9]+)[ \t]+([0-9]+)[ \t]+R\b")
SUBTYPE_IMAGE_RE = re.compile(rb"/Subtype[ \t\r\n]+/Image\b")

LENGTH_DIRECT_RE = re.compile(rb"/Length\s+(\d+)\b")
LENGTH_INDIRECT_RE = re.compile(rb"/Length\s+(\d+)\s+(\d+)\s+R\b")

SUPPORTED_FILTERS = {
    b"FlateDecode",
    b"ASCII85Decode",
    b"ASCIIHexDecode",
    b"RunLengthDecode",
    b"DCTDecode",   # JPEG (do not decode in v1)
    b"JPXDecode",   # JPEG2000 (do not decode in v1, optional but recommended)
}

MAX_SCAN_HEAD = 64 * 1024       # scan window for header
MAX_SCAN_TAIL = 256 * 1024      # scan window for startxref/%%EOF
DEFAULT_PER_STREAM_DECODE_CAP = 8 * 1024 * 1024  # 8 MiB per stream (soft cap)

DEFAULT_OBJ_RESOLVE_SCAN_CAP = 512 * 1024  # bytes to scan when resolving indirect /Length (bounded)

def _debug_stderr(msg: str) -> None:
    print(msg.rstrip() + "\n", file=sys.stderr)


def _truncate(s: str, n: int = 120) -> str:
    s = s.replace("\n", " ").replace("\r", " ")
    return s if len(s) <= n else (s[:n] + "...")


def _detect_indirect_ref(dict_bytes: bytes, key: bytes) -> bool:
    # e.g., "/Length 12 0 R" or "/Filter 12 0 R"
    # Keep it simple: key + whitespace + digits digits R
    pat = re.compile(re.escape(key) + rb"\s+\d+\s+\d+\s+R\b")
    return bool(pat.search(dict_bytes))

def _has_indirect_ref(dict_bytes: bytes, key: bytes) -> bool:
    # Backward-compatible alias (some blocks used _has_indirect_ref)
    return _detect_indirect_ref(dict_bytes, key)

def _parse_length_hint(dict_bytes: bytes) -> Optional[int]:
    """
    NOTE: This is only a *direct* length parse. It must NOT be used as a real
    length if /Length is an indirect reference (/Length N 0 R).
    """
    m = re.search(rb"/Length\s+(\d+)\b", dict_bytes)
    if not m:
        return None
    try:
        return int(m.group(1))
    except Exception:
        return None

def _parse_length_direct_or_ref(dict_bytes: bytes) -> Tuple[Optional[int], Optional[Tuple[int, int]]]:
    """
    Parse /Length in two forms:
      - direct:   /Length 1234
      - indirect: /Length 12 0 R
    Return (direct_length, (obj,gen) ref) where exactly one is typically non-None.
    """
    m = LENGTH_INDIRECT_RE.search(dict_bytes)
    if m:
        try:
            return None, (int(m.group(1)), int(m.group(2)))
        except Exception:
            return None, None
    m = LENGTH_DIRECT_RE.search(dict_bytes)
    if m:
        try:
            return int(m.group(1)), None
        except Exception:
            return None, None
    return None, None
 
def _resolve_indirect_length_from_mmap(
    mm: mmap.mmap,
    ref: Tuple[int, int],
    *,
    max_body_bytes: int = 256 * 1024,
) -> Tuple[Optional[int], str]:
    """
    Best-effort resolver for indirect /Length (<obj> <gen> R) WITHOUT xref.

    IMPORTANT FIX:
      - Do NOT scan only a prefix of the file.
      - Use mmap.find over the whole file for "<obj> <gen> obj".

    Parses a simple numeric object:
        N 0 obj
          2897
        endobj

    Returns (length, why_token). why_token is "" on success.
    """
    obj, gen = ref
    needle = f"{obj} {gen} obj".encode("ascii")

    # Search the entire file (mmap.find is in C and fast).
    pos = mm.find(needle, 0, len(mm))
    if pos < 0:
        return None, "len_indirect_obj_not_found"

    # Bound parsing to avoid DoS:
    start = pos + len(needle)
    end_limit = min(len(mm), start + max_body_bytes)
    endobj = mm.find(b"endobj", start, end_limit)
    if endobj < 0:
        return None, "len_indirect_endobj_not_found"

    body = bytes(mm[start:endobj])
    body = re.sub(rb"(?m)%.*?$", b"", body)  # strip comments
    mi = re.search(rb"[-+]?\d+", body)
    if not mi:
        return None, "len_indirect_no_int"

    try:
        v = int(mi.group(0))
    except Exception:
        return None, "len_indirect_int_parse_fail"

    if v < 0:
        return None, "len_indirect_negative"
 
    return v, "" 
 
def _sniff_endstream_near(mm: mmap.mmap, pos: int, limit: int = 64) -> bool:
    """
    Light sanity: does 'endstream' appear very near a predicted payload end?
    """
    if pos < 0:
        return False
    lo = max(0, pos - 4)
    hi = min(len(mm), pos + limit)
    return (mm.find(b"endstream", lo, hi) >= 0)
    
def _count_endstream_candidates(buf: bytes, payload_start: int, obj_end: int) -> int:
    """
    Count how many 'endstream' tokens appear between payload_start and obj_end.
    If >1, early-match ambiguity is plausible (payload contains 'endstream' bytes).
    """
    if payload_start < 0:
        return 0
    if obj_end <= payload_start:
        return 0
    try:
        return buf.count(b"endstream", payload_start, obj_end)
    except Exception:
        # Fallback for python versions without count(start,end) on bytes (rare)
        n = 0
        i = payload_start
        while True:
            j = buf.find(b"endstream", i, obj_end)
            if j < 0:
                break
            n += 1
            i = j + len(b"endstream")
        return n

def _debug_decode_hints(
    dict_bytes: bytes,
    filters: List[bytes],
    raw: bytes,
    exc: Exception
) -> str:
    """
    Return compact hint tokens to help root-cause decode failures.
    This does NOT change validation behavior; it is only for 'note' diagnostics.
    """
    parts: List[str] = []
    ex_name = type(exc).__name__
    msg = _truncate(str(exc))
    parts.append(f"ex={ex_name}")
    if msg:
        parts.append(f"msg={msg}")

    # Indirect refs are common and currently unsupported in v1.
    if _detect_indirect_ref(dict_bytes, b"/Filter"):
        parts.append("filter_indirect_ref=yes")
    if _detect_indirect_ref(dict_bytes, b"/Length"):
        parts.append("len_indirect_ref=yes")

    len_hint = _parse_length_hint(dict_bytes)
    if len_hint is not None:
        parts.append(f"len_hint={len_hint}")
    parts.append(f"raw_len={len(raw)}")

    # Filter-specific heuristics
    if filters:
        # show first filter (most useful) and chain length
        parts.append(f"f0={filters[0].decode('latin1', 'ignore')}")
        if len(filters) > 1:
            parts.append(f"fN={len(filters)}")

    # Special checks for FlateDecode
    if b"FlateDecode" in filters:
        # Try a safe probe with decompressobj to see if there is unused_data.
        try:
            dobj = zlib.decompressobj()
            _ = dobj.decompress(raw, max(1024 * 1024, len(raw)))  # bounded probe
            _ = dobj.flush()
            if dobj.unused_data:
                parts.append(f"zlib_unused={len(dobj.unused_data)}")
        except Exception:
            pass

        # Probe raw-deflate likelihood (do not change behavior, just hint)
        try:
            _ = zlib.decompress(raw, -zlib.MAX_WBITS)
            parts.append("raw_deflate_seems=yes")
        except Exception:
            parts.append("raw_deflate_seems=no")

    # ASCII85 / ASCIIHex marker presence hints
    if b"ASCII85Decode" in filters:
        parts.append(f"has_a85_eod={'yes' if b'~>' in raw else 'no'}")
    if b"ASCIIHexDecode" in filters:
        parts.append(f"has_hex_eod={'yes' if b'>' in raw else 'no'}")
    if b"RunLengthDecode" in filters:
        parts.append(f"has_rle_eod={'yes' if (128 in raw) else 'no'}")

    return " ".join(parts)

# ----------------------------
# Data structures
# ----------------------------

@dataclass(frozen=True)
class ComponentResult:
    component: str
    score: int  # 0 or 1
    reason: str


@dataclass(frozen=True)
class PdfFavConfig:
    # DoS resistance budgets
    max_decoded_total_bytes: int = 32 * 1024 * 1024   # total decoded across streams
    max_dict_backscan_bytes: int = 64 * 1024          # how far to scan backward for "<<"
    max_streams: int = 200_000                        # stop scanning if too many
 
    # Optional whitelist enforcement (contractual payload invariants)
    whitelist_dir: str = ""
    whitelist_file: str = "pdf_stream_whitelist.json"
 
    # Loaded at startup (main) for efficiency:
    # map[pdf_sha256] -> set of allowed stream payload sha256 values
    whitelist_index: Optional[Dict[str, Set[str]]] = None
    debug_notes: bool = False
    debug_stderr: bool = False
    debug_stderr_limit_per_file: int = 20  # avoid flooding stderr on huge PDFs
    
    # Indirect length resolver controls (xref-less)
    max_obj_resolve_scan_bytes: int = DEFAULT_OBJ_RESOLVE_SCAN_CAP

    
@dataclass
class StreamInfo:
    dict_span: Tuple[int, int]        # [start,end)
    stream_kw_span: Tuple[int, int]   # [start,end) for "stream" + EOL
    data_span: Tuple[int, int]        # [start,end) stream payload
    endstream_span: Tuple[int, int]   # [start,end) for "endstream"

    dict_bytes: bytes
    filters: List[bytes]
    decodeparms: List[Dict[bytes, Any]]

    # Best-effort object identity (used for font stream detection)
    obj_num: Optional[int] = None
    obj_gen: Optional[int] = None
    # Best-effort object span [obj_start, obj_end) for ambiguity checks
    obj_span: Optional[Tuple[int, int]] = None
    
    # /Length parsing (direct or indirect)
    length_direct: Optional[int] = None
    length_ref: Optional[Tuple[int, int]] = None
    
# ----------------------------
# Run directory + config dump
# ----------------------------

def create_run_directory(output_root: str) -> str:
    os.makedirs(output_root, exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    base = f"run_{timestamp}_mode-pdf_fav"
    run_dir = os.path.join(output_root, base)

    suffix = 1
    unique = run_dir
    while os.path.exists(unique):
        unique = f"{run_dir}_{suffix}"
        suffix += 1
    os.makedirs(unique, exist_ok=False)
    return unique


def write_config_json(run_dir: str, args: argparse.Namespace, cfg: PdfFavConfig) -> None:
    path = os.path.join(run_dir, "config.json")
    obj = {
        "input_path": os.path.abspath(args.input_path),
        "mode": "pdf_fav",
        "timestamp": datetime.now().isoformat(),
        "score_threshold": DEFAULT_SCORE_THRESHOLD,
        "pdf_fav_config": {
            "max_decoded_total_bytes": cfg.max_decoded_total_bytes,
            "max_dict_backscan_bytes": cfg.max_dict_backscan_bytes,
            "max_streams": cfg.max_streams,
            "whitelist_dir": os.path.abspath(cfg.whitelist_dir) if cfg.whitelist_dir else "",
            "whitelist_file": cfg.whitelist_file,
        },
    }
    with open(path, "w", encoding="utf-8") as f:
        json.dump(obj, f, indent=2)


# ----------------------------
# File discovery (flat dir)
# ----------------------------

def discover_files(input_path: str) -> List[str]:
    if os.path.isfile(input_path):
        return [os.path.abspath(input_path)]
    if os.path.isdir(input_path):
        out: List[str] = []
        for e in os.scandir(input_path):
            if e.is_file():
                out.append(os.path.abspath(e.path))
        return out
    raise ValueError(f"input-path is neither a file nor a directory: {input_path}")


# ----------------------------
# Small helpers
# ----------------------------

def _read_at(fp, off: int, n: int) -> bytes:
    fp.seek(off, os.SEEK_SET)
    return fp.read(max(0, n))


def _parse_name_or_array(val: bytes) -> List[bytes]:
    """
    Parse /Filter that can be a single name "/FlateDecode"
    or an array "[/FlateDecode /ASCII85Decode]".
    """
    val = val.strip()
    if val.startswith(b"["):
        return [m.group(1) for m in NAME_RE.finditer(val)]
    m = NAME_RE.search(val)
    return [m.group(1)] if m else []


def _parse_decodeparms(val: bytes) -> List[Dict[bytes, Any]]:
    """
    Minimal DecodeParms parsing, focused on PNG predictors.
    Extract numeric values for:
      /Predictor /Colors /BitsPerComponent /Columns
    """
    val = val.strip()
    dict_blobs: List[bytes] = []

    if val.startswith(b"["):
        dict_blobs = [m.group(0) for m in DICT_RE.finditer(val)]
    elif val.startswith(b"<<"):
        dict_blobs = [val]
    else:
        dict_blobs = []

    out: List[Dict[bytes, Any]] = []
    for db in dict_blobs:
        d: Dict[bytes, Any] = {}
        for key in (b"/Predictor", b"/Colors", b"/BitsPerComponent", b"/Columns"):
            m = re.search(re.escape(key) + rb"\s+(\d+)", db)
            if m:
                d[key] = int(m.group(1))
        out.append(d)
    return out

 

# ----------------------------
# Whitelist helpers (contractual payload invariants)
# ----------------------------
 
def _sha256_file_hex(path: str, chunk_size: int = 1024 * 1024) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while True:
            b = f.read(chunk_size)
            if not b:
                break
            h.update(b)
    return h.hexdigest()
 
 
def _sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()

def _trim_eol_before_endstream(payload: bytes) -> bytes:
    """
    Match pdf_stream_whitelist.py hashing rule:
    exclude exactly one clean EOL immediately preceding 'endstream' if present.
    """
    if len(payload) >= 2 and payload[-2:] == b"\r\n":
        return payload[:-2]
    if len(payload) >= 1 and payload[-1:] in (b"\n", b"\r"):
        return payload[:-1]
    return payload
 
def load_pdf_stream_whitelist_index(whitelist_dir: str, whitelist_file: str) -> Tuple[Optional[Dict[str, Set[str]]], str]:
    """
    Load publisher whitelist JSON and build:
      index[pdf_sha256] -> set(payload_sha256)

    Expected format (v1):
      {
        "entries": [
           { "pdf_sha256": "...",
             "streams": [ {"sha256": "..."}, ... ]
           }, ...
        ]
      }
    """
    if not whitelist_dir:
        return None, ""

    path = os.path.join(whitelist_dir, whitelist_file)
    if not os.path.isfile(path):
        return None, f"whitelist_missing:{path}"

    try:
        with open(path, "r", encoding="utf-8") as f:
            obj = json.load(f)
    except Exception as e:
        return None, f"whitelist_parse_error:{type(e).__name__}:{e}"

    index: Dict[str, Set[str]] = {}
    for ent in obj.get("entries", []):
        pdf_sha = ent.get("pdf_sha256", "")
        if not isinstance(pdf_sha, str) or not pdf_sha:
            continue
        allowed: Set[str] = set()
        for s in ent.get("streams", []):
            h = s.get("sha256", "")
            if isinstance(h, str) and h:
                allowed.add(h)
        index[pdf_sha] = allowed

    return index, ""

def _apply_png_predictor(data: bytes, parms: Dict[bytes, Any]) -> bytes:
    """
    Minimal PNG predictor implementation for FlateDecode when Predictor is 10..15.
    Only supports BitsPerComponent=8. If unsupported, returns data unchanged.
    """
    pred = int(parms.get(b"/Predictor", 1) or 1)
    if pred <= 1:
        return data
    if pred < 10:
        return data

    colors = int(parms.get(b"/Colors", 1) or 1)
    bpc = int(parms.get(b"/BitsPerComponent", 8) or 8)
    cols = int(parms.get(b"/Columns", 1) or 1)
    if bpc != 8:
        return data

    bpp = max(1, colors * (bpc // 8))
    row_size = cols * bpp

    out = bytearray()
    i = 0
    prev = bytearray(row_size)
    L = len(data)

    def paeth(a: int, b: int, c: int) -> int:
        p = a + b - c
        pa = abs(p - a)
        pb = abs(p - b)
        pc = abs(p - c)
        if pa <= pb and pa <= pc:
            return a
        if pb <= pc:
            return b
        return c

    while i < L:
        if i + 1 > L:
            break
        filt = data[i]
        i += 1
        row = bytearray(data[i:i + row_size])
        if len(row) < row_size:
            break
        i += row_size

        if filt == 0:
            pass
        elif filt == 1:  # Sub
            for x in range(row_size):
                left = row[x - bpp] if x >= bpp else 0
                row[x] = (row[x] + left) & 0xFF
        elif filt == 2:  # Up
            for x in range(row_size):
                row[x] = (row[x] + prev[x]) & 0xFF
        elif filt == 3:  # Average
            for x in range(row_size):
                left = row[x - bpp] if x >= bpp else 0
                up = prev[x]
                row[x] = (row[x] + ((left + up) // 2)) & 0xFF
        elif filt == 4:  # Paeth
            for x in range(row_size):
                a = row[x - bpp] if x >= bpp else 0
                b = prev[x]
                c = prev[x - bpp] if x >= bpp else 0
                row[x] = (row[x] + paeth(a, b, c)) & 0xFF
        else:
            # Unknown PNG row filter => do not transform (keep raw stream)
            return data

        out.extend(row)
        prev = row

    return bytes(out)


def _ascii85_decode(data: bytes) -> bytes:
    # Adobe-style ASCII85 is common in PDFs.
    return base64.a85decode(data, adobe=True, ignorechars=b" \t\r\n")


def _asciihex_decode(data: bytes) -> bytes:
    s = re.sub(rb"\s+", b"", data)
    if b">" in s:
        s = s.split(b">", 1)[0]
    if len(s) % 2 == 1:
        s += b"0"
    return binascii.unhexlify(s)


def _runlength_decode(data: bytes, cap: int) -> bytes:
    out = bytearray()
    i = 0
    L = len(data)
    while i < L and len(out) < cap:
        b = data[i]
        i += 1
        if b == 128:
            break
        if b <= 127:
            n = b + 1
            out.extend(data[i:i + n])
            i += n
        else:
            n = 257 - b
            if i >= L:
                break
            out.extend(data[i:i + 1] * n)
            i += 1
    return bytes(out)


def _decode_supported_filters(
    raw: bytes,
    filters: List[bytes],
    decodeparms: List[Dict[bytes, Any]],
    cap: int
) -> Tuple[Optional[bytes], str]:
    """
    Decode a supported filter chain under a decode cap.
    Returns (decoded_bytes, "") on success, (None, reason) on failure.
    """
    if not filters:
        return (raw[:cap] if len(raw) > cap else raw), ""

    # Normalize decodeparms alignment:
    # - allow none
    # - allow single dict applied to all
    # - allow per-filter list
    parms_list = decodeparms or []
    if len(parms_list) not in (0, 1, len(filters)):
        parms_list = []

    data = raw
    for idx, f in enumerate(filters):
        if f not in SUPPORTED_FILTERS:
            return None, f"unsupported_filter:{f!r}"

        # Opaque but valid filters: accept without decoding
        if f in (b"DCTDecode", b"JPXDecode"):
            # Return a small prefix only (for diagnostics), but treat as success.
            if len(data) > cap:
                data = data[:cap]
            return data, "opaque_filter_ok"
        
        parms = {}
        if parms_list:
            parms = parms_list[idx] if len(parms_list) == len(filters) else parms_list[0]

        try:
            if f == b"ASCII85Decode":
                data = _ascii85_decode(data)
            elif f == b"ASCIIHexDecode":
                data = _asciihex_decode(data)
            elif f == b"RunLengthDecode":
                data = _runlength_decode(data, cap)
            elif f == b"FlateDecode":
                data = zlib.decompress(data)
                if parms:
                    data = _apply_png_predictor(data, parms)
            else:
                return None, "internal_filter_dispatch_error"
        except Exception as e:
            return None, f"filter_decode_exception:{f!r}:{type(e).__name__}:{_truncate(str(e), 80)}"

        if len(data) > cap:
            data = data[:cap]

    return data, ""


# ----------------------------
# Prelude checks (file-wide invariants)
# ----------------------------

def check_prelude(ap: str) -> List[ComponentResult]:
    out: List[ComponentResult] = []

    # Header check
    try:
        with open(ap, "rb") as f:
            head = f.read(MAX_SCAN_HEAD)
        if not PDF_HEADER_RE.search(head):
            out.append(ComponentResult("prelude:header", 1, "missing_pdf_header"))
        else:
            out.append(ComponentResult("prelude:header", 0, "ok"))
    except Exception as e:
        out.append(ComponentResult("prelude:header", 1, f"read_error:{type(e).__name__}:{e}"))
        return out

    # Tail checks
    try:
        fs = os.path.getsize(ap)
        take = min(fs, MAX_SCAN_TAIL)
        with open(ap, "rb") as f:
            f.seek(fs - take, os.SEEK_SET)
            tail = f.read(take)

        if not STARTXREF_RE.search(tail):
            out.append(ComponentResult("prelude:startxref", 1, "missing_startxref_in_tail"))
        else:
            out.append(ComponentResult("prelude:startxref", 0, "ok"))

        if not EOF_RE.search(tail):
            out.append(ComponentResult("prelude:eof", 1, "missing_%%EOF_in_tail"))
        else:
            out.append(ComponentResult("prelude:eof", 0, "ok"))
    except Exception as e:
        out.append(ComponentResult("prelude:tail", 1, f"tail_read_error:{type(e).__name__}:{e}"))

    return out


# ----------------------------
# Stream scanning (mmap)
# ----------------------------

def scan_streams(ap: str, cfg: PdfFavConfig) -> Tuple[List[StreamInfo], Optional[str]]:
    """
    Find stream boundaries and extract nearby dictionaries.
    Conservative: if a stream is malformed (missing endstream), return error.
    """
    streams: List[StreamInfo] = []
    try:
        with open(ap, "rb") as f:
            mm = mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ)
            try:
                idx = 0
                L = len(mm)
                while idx < L:
                    if len(streams) >= cfg.max_streams:
                        return streams, "too_many_streams"

                    s = mm.find(b"stream", idx)
                    if s < 0:
                        break

                    after = s + 6
                    if after >= L:
                        break

                    # Require EOL after "stream"
                    if mm[after:after + 2] == b"\r\n":
                        data_start = after + 2
                        stream_kw_end = after + 2
                    elif mm[after:after + 1] == b"\n":
                        data_start = after + 1
                        stream_kw_end = after + 1
                    else:
                        idx = after
                        continue

                    # Back-scan for dictionary start "<<"
                    back_lo = max(0, s - cfg.max_dict_backscan_bytes)
                    back = mm[back_lo:s]
                    dd_pos = back.rfind(b"<<")
                    if dd_pos < 0:
                        idx = stream_kw_end
                        continue

                    dict_start = back_lo + dd_pos
                    dict_end = mm.rfind(b">>", dict_start, s)
                    if dict_end < 0:
                        idx = stream_kw_end
                        continue
                    dict_end += 2

                    dict_bytes = bytes(mm[dict_start:dict_end])
                    
                    # Parse /Length (direct or indirect ref) for later accurate slicing.
                    length_direct, length_ref = _parse_length_direct_or_ref(dict_bytes)

                    # Find matching "endstream"
                    es = mm.find(b"endstream", data_start)
                    if es < 0:
                        return streams, "missing_endstream"

                    data_end = es
                    # Align with whitelist hashing rule: trim one EOL before 'endstream'
                    if data_end >= 2 and mm[data_end-2:data_end] == b"\r\n":
                        data_end -= 2
                    elif data_end >= 1 and mm[data_end-1:data_end] in (b"\n", b"\r"):
                        data_end -= 1
                    endstream_end = es + len(b"endstream")

                    filters: List[bytes] = []
                    decodeparms: List[Dict[bytes, Any]] = []

                    m = FILTER_RE.search(dict_bytes)
                    if m:
                        filters = _parse_name_or_array(m.group("val"))

                    m = DECODEPARMS_RE.search(dict_bytes)
                    if m:
                        decodeparms = _parse_decodeparms(m.group("val"))

                    # Best-effort object header backscan for "<obj> <gen> obj"
                    # This is used to map font stream references (/FontFile2 N 0 R)
                    # to actual stream objects.
                    obj_num: Optional[int] = None
                    obj_gen: Optional[int] = None
                    obj_span: Optional[Tuple[int, int]] = None
                    try:
                        obj_back_lo = max(0, dict_start - cfg.max_dict_backscan_bytes)
                        obj_back = bytes(mm[obj_back_lo:dict_start])
                        # find the last object header in the back window
                        last = None
                        for mmh in OBJ_HDR_BACKSCAN_RE.finditer(obj_back):
                            last = mmh
                        if last is not None:
                            obj_num = int(last.group(1))
                            obj_gen = int(last.group(2))
                            # approximate object start: the header match in file coords
                            obj_start = obj_back_lo + last.start()
                            # approximate object end: next "endobj" after dict_start (bounded search)
                            endobj = mm.find(b"endobj", dict_start, min(L, dict_start + 2 * cfg.max_dict_backscan_bytes))
                            if endobj < 0:
                                # fallback: end at endstream_end (still useful for candidate count)
                                obj_end = endstream_end
                            else:
                                obj_end = endobj + len(b"endobj")
                            obj_span = (obj_start, obj_end)
                    except Exception:
                        obj_num = None
                        obj_gen = None
                        obj_span = None
                        
                    streams.append(StreamInfo(
                        dict_span=(dict_start, dict_end),
                        stream_kw_span=(s, stream_kw_end),
                        data_span=(data_start, data_end),
                        endstream_span=(es, endstream_end),
                        dict_bytes=dict_bytes,
                        filters=filters,
                        decodeparms=decodeparms,
                        obj_num=obj_num,
                        obj_gen=obj_gen,
                        obj_span=obj_span,
                        length_direct=length_direct,
                        length_ref=length_ref,
                    ))

                    idx = endstream_end
            finally:
                mm.close()
    except Exception as e:
        return [], f"stream_scan_error:{type(e).__name__}:{e}"

    return streams, None
 

def collect_fontfile_object_numbers(ap: str) -> Set[int]:
    """
    Scan the entire file for /FontFile, /FontFile2, /FontFile3 references and
    return the referenced object numbers.
    """
    try:
        with open(ap, "rb") as f:
            buf = f.read()
    except Exception:
        return set()

    out: Set[int] = set()
    for m in FONTFILE_REF_RE.finditer(buf):
        try:
            out.add(int(m.group(1)))
        except Exception:
            continue
    return out

def _find_stream_bounds_in_object(buf: bytes, start_search: int, end_limit: int) -> Optional[Tuple[int, int, int]]:
    """
    Find 'stream' ... 'endstream' within [start_search, end_limit).
    Returns (stream_kw_off, payload_start, payload_end_excl) or None.

    payload_end_excl excludes exactly one clean EOL immediately before 'endstream'
    (CRLF or LF or CR) to match pdf_stream_whitelist.py.
    """
    stream_kw = buf.find(b"stream", start_search, end_limit)
    if stream_kw < 0:
        return None

    i = stream_kw + len(b"stream")
    while i < end_limit and buf[i] in b" \t":
        i += 1
    if i >= end_limit:
        return None

    if buf[i:i+2] == b"\r\n":
        payload_start = i + 2
    elif buf[i:i+1] == b"\n":
        payload_start = i + 1
    elif buf[i:i+1] == b"\r":
        payload_start = i + 1
    else:
        return None

    endstream_kw = buf.find(b"endstream", payload_start, end_limit)
    if endstream_kw < 0:
        return None

    payload_end = endstream_kw
    if payload_end >= 2 and buf[payload_end-2:payload_end] == b"\r\n":
        payload_end -= 2
    elif payload_end >= 1 and buf[payload_end-1:payload_end] in (b"\n", b"\r"):
        payload_end -= 1

    if payload_end < payload_start:
        return None
    return (stream_kw, payload_start, payload_end)


def _extract_nearby_dict_for_object(buf: bytes, obj_start: int, stream_kw_off: int, max_back_window: int = 64 * 1024) -> bytes:
    """
    Best-effort extraction of the stream dictionary preceding 'stream' within an object.
    Mirrors pdf_stream_whitelist.py behavior.
    """
    lo = max(obj_start, stream_kw_off - max_back_window)
    chunk = buf[lo:stream_kw_off]
    dd = chunk.rfind(b"<<")
    if dd < 0:
        return b""
    dd_abs = lo + dd
    ee = buf.find(b">>", dd_abs, stream_kw_off)
    if ee < 0:
        return b""
    return buf[dd_abs:ee+2]


def scan_image_font_stream_hashes_obj_based(ap: str) -> Tuple[List[Tuple[str, int, int, str]], Optional[str]]:
    """
    Returns list of (kind, obj, gen, payload_sha256) for image/font streams,
    using the same object-based scanning approach as pdf_stream_whitelist.py.
    """
    try:
        with open(ap, "rb") as f:
            buf = f.read()
    except Exception as e:
        return [], f"read_error:{type(e).__name__}:{e}"

    font_obj_nums = set()
    for m in FONTFILE_REF_RE.finditer(buf):
        try:
            font_obj_nums.add(int(m.group(1)))
        except Exception:
            pass

    hits: List[Tuple[str, int, int, str]] = []
    objs = list(OBJ_HDR_BACKSCAN_RE.finditer(buf))
    for idx, m in enumerate(objs):
        obj = int(m.group(1))
        gen = int(m.group(2))
        obj_start = m.start()
        obj_end = objs[idx + 1].start() if idx + 1 < len(objs) else len(buf)

        sb = _find_stream_bounds_in_object(buf, start_search=m.end(), end_limit=obj_end)
        if sb is None:
            continue
        stream_kw_off, payload_start, payload_end = sb
        dct = _extract_nearby_dict_for_object(buf, obj_start=obj_start, stream_kw_off=stream_kw_off)

        is_image = bool(SUBTYPE_IMAGE_RE.search(dct))
        is_font = (obj in font_obj_nums)
        if not is_image and not is_font:
            continue

        payload = buf[payload_start:payload_end]
        h = _sha256_hex(payload)
        hits.append(("image" if is_image else "font", obj, gen, h))

    return hits, None

# ----------------------------
# Finalization (zip_fav-style)
# ----------------------------

def finalize_result(
    result: Dict[str, Optional[str]],
    comps: List[ComponentResult],
    verdict_if_any: str = "encrypted",
    note: str = "",
) -> Dict[str, Optional[str]]:
    if not comps:
        comps = [ComponentResult("noop", 0, "no_components")]

    scores = [int(c.score) for c in comps]
    suspicious = sum(1 for s in scores if s > DEFAULT_SCORE_THRESHOLD)

    result["num_windows"] = str(len(comps))
    result["num_suspicious_windows"] = str(suspicious)
    result["min_score"] = str(min(scores))
    result["max_score"] = str(max(scores))

    if suspicious > 0:
        result["verdict"] = verdict_if_any
        first_bad = next((c for c in comps if c.score > 0), None)
        result["note"] = note or (first_bad.reason if first_bad else "has_suspicious_components")
    else:
        result["verdict"] = "benign"
        result["note"] = note or "all_components_ok"

    return result


# ----------------------------
# Core analysis (analyze_file)
# ----------------------------

def analyze_file(file_path: str, cfg: PdfFavConfig) -> Dict[str, Optional[str]]:
    """
    Analyze a single PDF file and return a unified CSV-row dict.

    Policy: treat the entire file as suspicious and inspect all discovered streams
    (plus prelude/tail invariants).
 
    Optional contractual payload invariants:
    - If cfg.whitelist_dir is set and cfg.whitelist_index is loaded, scan for
      embedded image and font streams and verify their raw payload sha256 hashes
      against the whitelist entry for this PDF (keyed by pdf_sha256).
    """
    result: Dict[str, Optional[str]] = {
        "file_path": file_path,
        "window_size": str(DEFAULT_WINDOW_SIZE),
        "stride": str(DEFAULT_STRIDE),
        "tail_mode": DEFAULT_TAIL_MODE,
        "file_size": "",
        "num_windows": "0",
        "num_suspicious_windows": "0",
        "min_score": "",
        "max_score": "",
        "score_threshold": str(DEFAULT_SCORE_THRESHOLD),
        "mode": "pdf_fav",
        "verdict": "error",
        "note": "",
        "error": "",
    }

    # Stat
    try:
        st = os.stat(file_path)
        file_size = int(st.st_size)
        result["file_size"] = str(file_size)
    except Exception as e:
        result["error"] = str(e)
        return result

    if file_size <= 0:
        result["verdict"] = "not_evaluated"
        result["note"] = "empty_file"
        return result

    # Intent: only handle .pdf by default (same spirit as zip_fav)
    ext = os.path.splitext(file_path)[1].lstrip(".").lower()
    if ext != "pdf":
        result["verdict"] = "not_evaluated"
        result["note"] = "not_pdf_intent"
        return result

    comps: List[ComponentResult] = []
    debug_samples: List[str] = []

    # 1) File-wide invariants
    comps.extend(check_prelude(file_path))

    # 2) Stream map
    streams, err = scan_streams(file_path, cfg)
    if err:
        comps.append(ComponentResult("metadata:stream_map", 1, err))
        return finalize_result(result, comps, verdict_if_any="encrypted")

    comps.append(ComponentResult("metadata:stream_map", 0, f"ok streams={len(streams)}"))
 
    # 2.5) Optional whitelist enforcement (image/font stream payload hashes)
    # - Identify image streams by dictionary marker: /Subtype /Image
    # - Identify font streams by object number referenced by /FontFile*, collected
    #   from the entire file.
    if cfg.whitelist_dir and cfg.whitelist_index is not None:
        pdf_sha = _sha256_file_hex(file_path)
        allowed = cfg.whitelist_index.get(pdf_sha)
        if allowed is None:
            comps.append(ComponentResult("whitelist", 1, "pdf_not_in_whitelist"))
        else:
            hits, herr = scan_image_font_stream_hashes_obj_based(file_path)
            if herr:
                comps.append(ComponentResult("whitelist", 1, f"whitelist_scan_error:{herr}"))
            else:
                bad = 0
                for (kind, obj, gen, h) in hits:
                    if h not in allowed:
                        bad += 1
                        comps.append(ComponentResult(
                            component=f"whitelist:{kind}:obj{obj}:{gen}",
                            score=1,
                            reason="stream_hash_not_whitelisted",
                        ))
                if bad == 0:
                    comps.append(ComponentResult("whitelist", 0, "all_image_font_stream_hashes_whitelisted"))
    elif cfg.whitelist_dir and cfg.whitelist_index is None:
        comps.append(ComponentResult("whitelist", 1, "whitelist_enabled_but_not_loaded"))
    else:
        comps.append(ComponentResult("whitelist", 0, "whitelist_disabled"))
    
    # 3) Decode each stream conservatively
    # Total decode budget is shared across streams.
    decoded_total_used = 0
    stderr_debug_count = 0

    try:
        with open(file_path, "rb") as fp:
            # mmap once per file for cheap sanity checks & indirect length resolve (bounded)
            mm: Optional[mmap.mmap] = None
            try:
                mm = mmap.mmap(fp.fileno(), 0, access=mmap.ACCESS_READ)
            except Exception:
                mm = None
            for i, st in enumerate(streams):
                comp_id = f"stream:{i}[{st.data_span[0]},{st.data_span[1]}]"

                # Bounds check
                if st.data_span[0] < 0 or st.data_span[1] < st.data_span[0] or st.data_span[1] > file_size:
                    comps.append(ComponentResult(comp_id, 1, "stream_data_span_oob"))
                    continue

                raw_len = st.data_span[1] - st.data_span[0]
                raw = _read_at(fp, st.data_span[0], raw_len)

                # --- Prefer /Length-based slicing when possible ---
                # Many PDFs store /Length as an indirect ref. Without resolving it,
                # 'endstream' scanning can early-match inside compressed bytes,
                # producing truncated FlateDecode streams (common in your logs).
                slice_mode = "endstream"
                len_tok = "len=none"
                resolved_len: Optional[int] = None
                resolved_why: str = ""
 
                if st.length_direct is not None:
                    resolved_len = st.length_direct
                    len_tok = "len=direct"
                elif st.length_ref is not None and mm is not None:
                    # FIX: resolve indirect /Length using mmap.find over the whole file,
                    # not only a prefix slice (which caused len_indirect_obj_not_found).
                    resolved_len, resolved_why = _resolve_indirect_length_from_mmap(
                        mm,
                        st.length_ref,
                        max_body_bytes=256 * 1024,
                    )
                    if resolved_len is not None:
                        len_tok = "len=indirect_resolved"
                    else:
                        len_tok = f"len=indirect_unresolved:{resolved_why}"
 
                # If we resolved a plausible length, slice by it (with sanity).
                if resolved_len is not None:
                    # Bounds check for length-based end
                    pred_end = st.data_span[0] + int(resolved_len)
                    if pred_end <= st.data_span[0]:
                        # zero or negative -> fallback to endstream
                        resolved_len = None
                    elif pred_end > file_size:
                        # out of file -> fallback
                        resolved_len = None
                    else:
                        # Light sanity: endstream should appear near predicted end.
                        # If not, we still may proceed (some PDFs have odd whitespace),
                        # but mark as mismatch in stderr.
                        slice_mode = "length"
                        fp.seek(st.data_span[0], os.SEEK_SET)
                        raw = fp.read(int(resolved_len))
                        raw_len = len(raw)
 
                        # If the predicted end doesn't look like it lines up with endstream,
                        # keep going (we already have the bytes), but give a hint.
                        if mm is not None and not _sniff_endstream_near(mm, pred_end, limit=96):
                            # only a hint token; do not blow up note
                            len_tok += ":sanity_miss"
 
                if resolved_len is None:
                    # Fallback: endstream-based slicing (existing behavior)
                    raw_len = st.data_span[1] - st.data_span[0]
                    raw = _read_at(fp, st.data_span[0], raw_len)
 
                # Enforce total decode budget
                remaining_total = max(0, cfg.max_decoded_total_bytes - decoded_total_used)
                if remaining_total <= 0:
                    comps.append(ComponentResult(comp_id, 1, "decoded_total_budget_exhausted"))
                    continue

                per_cap = min(remaining_total, DEFAULT_PER_STREAM_DECODE_CAP)

                # If filters exist, require they are supported
                if any(f not in SUPPORTED_FILTERS for f in (st.filters or [])):
                    comps.append(ComponentResult(comp_id, 1, f"unsupported_filter_chain:{st.filters!r}"))
                    continue

                dec, why = _decode_supported_filters(raw, st.filters or [], st.decodeparms or [], per_cap)
                if dec is None:
                    if cfg.debug_notes and len(debug_samples) < 3:
                        # Provide root-cause hints for decode failures without changing behavior.
                        if str(why).startswith("filter_decode_exception"):
                            # Build a hint string using dict/filter/raw context.
                            # We do not have the original exception object here,
                            # so we rely on 'why' + additional heuristics.
                            # For richer hints, see alternative below (probe with try/except around decoders).
                            len_hint = _parse_length_hint(st.dict_bytes)
                            indirect_filter = _detect_indirect_ref(st.dict_bytes, b"/Filter")
                            indirect_len = _detect_indirect_ref(st.dict_bytes, b"/Length")
                            hint = (
                                f"stream{i} "
                                f"filters={[f.decode('latin1','ignore') for f in (st.filters or [])]} "
                                f"raw_len={len(raw)} "
                                f"len_hint={len_hint if len_hint is not None else 'none'} "
                                f"filter_indirect_ref={'yes' if indirect_filter else 'no'} "
                                f"len_indirect_ref={'yes' if indirect_len else 'no'} "
                                f"why={why}"
                            )
                            debug_samples.append(_truncate(hint, 220))

                    reason = "filter_decode_exception"
                    if st.filters:
                        reason += f":{st.filters[0]!r}"

                    comps.append(ComponentResult(comp_id, 1, reason))

                    if cfg.debug_stderr and stderr_debug_count < cfg.debug_stderr_limit_per_file:
                        # IMPORTANT: len_hint from _parse_length_hint is NOT real length when /Length is indirect.
                        len_hint = _parse_length_hint(st.dict_bytes)
                        len_ind = _has_indirect_ref(st.dict_bytes, b"/Length")
                        filter_ind = _has_indirect_ref(st.dict_bytes, b"/Filter")

                        amb = "unknown"
                        cand = -1
                        if st.obj_span is not None:
                            try:
                                # Avoid mmap per-stream if possible: read small slice
                                obj_s, obj_e = st.obj_span
                                obj_s = max(0, obj_s)
                                obj_e = min(file_size, obj_e)
                                fp.seek(obj_s, os.SEEK_SET)
                                obj_buf = fp.read(obj_e - obj_s)
                                # candidate count in object-local buffer: shift payload_start
                                payload_off = max(0, st.data_span[0] - obj_s)
                                cand = _count_endstream_candidates(obj_buf, payload_off, len(obj_buf))
                                amb = "yes" if cand > 1 else "no"
                            except Exception:
                                pass

                        _debug_stderr(
                            "[pdf_fav][decode_fail] "
                            f"file={os.path.basename(file_path)} "
                            f"stream={i} "
                            f"obj={st.obj_num if st.obj_num is not None else '?'} "
                            f"filters={[f.decode('latin1','ignore') for f in (st.filters or [])]} "
                            f"slice={slice_mode} "
                            f"raw_len={len(raw)} "
                            f"len_tok={len_tok} "
                            f"len_hint_rawtoken={len_hint if len_hint is not None else 'none'} "
                            f"len_direct={st.length_direct if st.length_direct is not None else 'none'} "
                            f"len_ref={(f'{st.length_ref[0]} {st.length_ref[1]} R' if st.length_ref else 'none')} "
                            f"len_indirect={'yes' if len_ind else 'no'} "
                            f"filter_indirect={'yes' if filter_ind else 'no'} "
                            f"endstream_ambiguous={amb} "
                            f"endstream_candidates={cand} "
                            f"error={why}"
                        )
                        stderr_debug_count += 1
                        
                    continue

                decoded_total_used += len(dec)
                comps.append(ComponentResult(comp_id, 0, "ok"))
            if mm is not None:
                try:
                    mm.close()
                except Exception:
                    pass
                
    except Exception as e:
        comps.append(ComponentResult("io", 1, f"io_error:{type(e).__name__}:{e}"))

    if cfg.debug_notes and debug_samples:
        # Put a compact summary in note; finalize_result may overwrite note with first_bad.reason,
        # so we pass it explicitly as 'note' to preserve the debug summary.
        dbg = "decode_fail_samples=" + " | ".join(debug_samples)
        return finalize_result(result, comps, verdict_if_any="encrypted", note=dbg)
    return finalize_result(result, comps, verdict_if_any="encrypted")


# ----------------------------
# CLI
# ----------------------------

def parse_args(argv: Optional[List[str]] = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Specification-based PDF format-aware validator (v1 skeleton)."
    )
    p.add_argument("--input-path", required=True, help="A PDF file or a flat directory (no recursion).")
    p.add_argument("--output-path", required=True, help="Root output directory.")

    # Budgets / caps
    p.add_argument("--max-decoded-total-bytes", type=int, default=32 * 1024 * 1024,
                   help="Total decoded bytes budget across all streams (default 32 MiB).")
    p.add_argument("--max-dict-backscan-bytes", type=int, default=64 * 1024,
                   help="Maximum bytes to scan backwards for '<<' before a stream (default 64 KiB).")
    p.add_argument("--max-streams", type=int, default=200_000,
                   help="Maximum number of streams to scan before aborting (default 200k).")
 
    # Optional whitelist enforcement (contractual payload invariants)
    p.add_argument("--whitelist-dir", default="",
                   help="Directory containing a publisher whitelist JSON (default: disabled).")
    p.add_argument("--whitelist-file", default="pdf_stream_whitelist.json",
                   help="Whitelist JSON filename inside --whitelist-dir (default: pdf_stream_whitelist.json).")
    p.add_argument("--debug-notes", action="store_true", default=False,
                   help="Include richer per-file debug hints in the CSV 'note' field (may be verbose).")
    p.add_argument("--debug-stderr", action="store_true", default=False,
                   help="Emit per-stream decode failure diagnostics to stderr (recommended).")
    p.add_argument("--debug-stderr-limit-per-file", type=int, default=20,
                   help="Max number of per-stream stderr debug lines per file (default: 20).")
    p.add_argument("--max-obj-resolve-scan-bytes", type=int, default=DEFAULT_OBJ_RESOLVE_SCAN_CAP,
                   help="Max bytes scanned (from file start) to resolve indirect /Length without xref (default: 512 KiB).")
    
    return p.parse_args(argv)


def main(argv: Optional[List[str]] = None) -> None:
    args = parse_args(argv)

    try:
        files = discover_files(args.input_path)
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)

    if not files:
        print("No files found to analyze.", file=sys.stderr)
        sys.exit(1)

    wl_index: Optional[Dict[str, Set[str]]] = None
    if args.whitelist_dir:
        wl_index, wl_err = load_pdf_stream_whitelist_index(args.whitelist_dir, args.whitelist_file)
        if wl_err:
            # Keep running, but whitelist enforcement will flag an error component per file.
            wl_index = None
 
    cfg = PdfFavConfig(
        max_decoded_total_bytes=int(args.max_decoded_total_bytes),
        max_dict_backscan_bytes=int(args.max_dict_backscan_bytes),
        max_streams=int(args.max_streams),
        whitelist_dir=str(args.whitelist_dir or ""),
        whitelist_file=str(args.whitelist_file or "pdf_stream_whitelist.json"),
        whitelist_index=wl_index,
        debug_notes=bool(args.debug_notes),
        debug_stderr=bool(args.debug_stderr),
        debug_stderr_limit_per_file=int(args.debug_stderr_limit_per_file),
        max_obj_resolve_scan_bytes=int(args.max_obj_resolve_scan_bytes),
    )

    run_dir = create_run_directory(args.output_path)
    write_config_json(run_dir, args, cfg)

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

    with open(csv_path, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=fieldnames)
        w.writeheader()
        for pth in files:
            row = analyze_file(pth, cfg)
            w.writerow(row)

    print(f"Analysis complete. Results written to: {csv_path}")


if __name__ == "__main__":
    main()
