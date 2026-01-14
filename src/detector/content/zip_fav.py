#!/usr/bin/env python3
"""
zip_fav.py (v1 skeleton)

Specification-based validator for classic ZIP (non-ZIP64) archives.

v1 policies (as discussed)
- Support only STORE(0) and DEFLATE(8). Other methods => suspicious.
- ZIP64 => not_evaluated with note="zip64_unsupported"
- Data Descriptor (GPBF bit 3 / 0x0008) supported.
- CRC-32 validation default ON (after bounded decompression).
- Gaps outside the "active ZIP spans" => suspicious (clean-archive assumption).
- Nested container flattening OFF (stubbed, toggleable later).

Output schema matches txt_fav.py (unified with content_detector.py):
    file_path, window_size, stride, tail_mode, file_size, num_windows,
    num_suspicious_windows, min_score, max_score, score_threshold, mode,
    verdict, note, error

For zip_fav:
- "window_size/stride/tail_mode" are retained for schema compatibility but not used.
  We map:
    num_windows            := num_components (typically entries + metadata + gap checks)
    num_suspicious_windows := suspicious_components
    min_score/max_score    := 0/1
    score_threshold        := 0
"""

# ------------------------------------------------------------
# How to run zip_fav.py (examples)
# ------------------------------------------------------------
#
# 1) Analyze a single ZIP file:
#   python3 zip_fav.py \
#     --input-path /path/to/sample.zip \
#     --output-path /path/to/out/
#
# 2) Analyze all files in a *flat* directory (no recursion):
#   python3 zip_fav.py \
#     --input-path /path/to/zip_dir/ \
#     --output-path /path/to/out/
#
# Output:
#   A new run directory will be created under --output-path, e.g.
#     out/run_20251226-235959_mode-zip_fav/
#   It will contain:
#     - config.json    (the exact run configuration)
#     - results.csv    (one row per analyzed file)
#
# v1 policy defaults (recommended):
#   - CRC-32 validation: ON
#   - Data-descriptor validation: ON (GPBF 0x0008)
#   - Gaps: suspicious (clean-archive assumption)
#   - ZIP64: unsupported => verdict=not_evaluated, note=zip64_unsupported
#   - Nested flattening: OFF
#
# Common knobs:
#   Disable CRC check (not recommended):
#     python3 zip_fav.py --input-path ... --output-path ... --no-crc-check
#
#   Ignore gaps (prototype convenience, weakens security model):
#     python3 zip_fav.py --input-path ... --output-path ... --ignore-gaps
#
#   Tighten/relax DoS budgets:
#     python3 zip_fav.py --input-path ... --output-path ... \
#       --max-uncompressed-per-entry $((8*1024*1024)) \
#       --max-total-uncompressed     $((64*1024*1024))
# ------------------------------------------------------------


from __future__ import annotations

import argparse
import csv
import os
import struct
import sys
import json
import zlib
from dataclasses import dataclass
from datetime import datetime
from typing import Dict, List, Optional, Tuple, Iterable, Set


# ----------------------------
# Constants (ZIP signatures)
# ----------------------------

SIG_LOC  = 0x04034B50  # "PK\x03\x04" Local file header
SIG_CEN  = 0x02014B50  # "PK\x01\x02" Central directory file header
SIG_EOCD = 0x06054B50  # "PK\x05\x06" End of central directory
SIG_DD   = 0x08074B50  # "PK\x07\x08" Data descriptor optional signature

# ZIP64 markers (v1 unsupported)
SIG_ZIP64_EOCD = 0x06064B50  # "PK\x06\x06"
SIG_ZIP64_LOC  = 0x07064B50  # "PK\x06\x07"

# Methods
METHOD_STORE   = 0
METHOD_DEFLATE = 8
METHOD_AES     = 99  # wrapper; often implies encryption

# General purpose bit flag masks
GPBF_ENCRYPTED = 0x0001
GPBF_DD        = 0x0008  # "data descriptor present"
GPBF_UTF8      = 0x0800

# Limits / defaults
DEFAULT_SCORE_THRESHOLD = 0
DEFAULT_WINDOW_SIZE = 4096   # unused (schema compatibility)
DEFAULT_STRIDE = 4096        # unused (schema compatibility)
DEFAULT_TAIL_MODE = "ignore" # unused (schema compatibility)

MAX_EOCD_SEARCH = 66_000 + 22  # per ZIP spec: comment up to 65535, plus EOCD


# ----------------------------
# Data structures
# ----------------------------

@dataclass(frozen=True)
class ZipEocdInfo:
    file_size: int
    eocd_off: int
    eocd_size: int
    cd_off: int
    cd_size: int
    n_total: int
    comment_len: int
    zip64_marker: bool = False

    @property
    def eocd_span(self) -> Tuple[int, int]:
        return (self.eocd_off, self.eocd_off + self.eocd_size)  # [start, end_excl)

    @property
    def cd_span(self) -> Tuple[int, int]:
        return (self.cd_off, self.cd_off + self.cd_size)        # [start, end_excl)


@dataclass(frozen=True)
class ZipCdEntry:
    # raw fields from central directory
    name_bytes: bytes
    flags: int
    method: int
    crc32: int
    comp_size: int
    uncomp_size: int
    lfh_off: int
    extra: bytes  # keep for AES extra detection if desired


@dataclass
class ZipEntryResolved:
    # resolved from CD + LFH
    name_bytes: bytes
    name: str
    flags: int
    method: int
    cd_crc32: int
    cd_comp_size: int
    cd_uncomp_size: int
    lfh_off: int

    lfh_name_len: int
    lfh_extra_len: int

    data_start: int
    data_end_excl: int  # exclusive

    # data descriptor (if flags&GPBF_DD)
    dd_start: int
    dd_end_excl: Optional[int] = None  # filled if validated / parsed
    is_encrypted: bool = False

    def lfh_span(self) -> Tuple[int, int]:
        # local header fixed=30 + variable fields
        lfh_len = 30 + self.lfh_name_len + self.lfh_extra_len
        return (self.lfh_off, self.lfh_off + lfh_len)

    def data_span(self) -> Tuple[int, int]:
        return (self.data_start, self.data_end_excl)

    def dd_span(self) -> Optional[Tuple[int, int]]:
        if self.dd_end_excl is None:
            return None
        return (self.dd_start, self.dd_end_excl)


@dataclass(frozen=True)
class ComponentResult:
    component: str  # e.g., "metadata", "entry:<name>", "gap"
    score: int      # 0 or 1
    reason: str


@dataclass(frozen=True)
class ZipFavConfig:
    # v1 toggles/policies
    crc_check: bool = True
    allow_zip64: bool = False  # v1: false -> zip64 => not_evaluated
    supported_methods: Tuple[int, ...] = (METHOD_STORE, METHOD_DEFLATE)

    # DoS resistance budgets
    max_uncompressed_per_entry: int = 32 * 1024 * 1024   # 32 MiB per entry inflate cap
    max_total_uncompressed: int = 256 * 1024 * 1024      # 256 MiB total inflate cap
    max_entries: int = 100_000                           # guard against pathological CD
    dd_validate: bool = True                             # validate DD if present
    gaps_suspicious: bool = True                         # v1: gaps are suspicious
    nested_flattening: bool = False                      # v1: OFF


# ----------------------------
# Low-level I/O helpers
# ----------------------------

def _read_at(fp, off: int, n: int) -> bytes:
    fp.seek(off, os.SEEK_SET)
    return fp.read(max(0, n))

def _u16le(b: bytes, off: int = 0) -> int:
    return struct.unpack_from("<H", b, off)[0]

def _u32le(b: bytes, off: int = 0) -> int:
    return struct.unpack_from("<I", b, off)[0]


# ----------------------------
# Basic ZIP detection
# ----------------------------

def looks_like_zip_head(head4: bytes) -> bool:
    if len(head4) < 4:
        return False
    sig = _u32le(head4, 0)
    return sig in (SIG_LOC, SIG_CEN, SIG_EOCD)

def find_eocd(fp, file_size: int) -> Tuple[Optional[ZipEocdInfo], str]:
    """
    Find the LAST EOCD in the tail region and parse it.
    Return (ZipEocdInfo, "") on success, (None, reason) on failure.

    v1:
    - If ZIP64 markers are detected in tail => return ZipEocdInfo(zip64_marker=True)
      so caller can map to not_evaluated note="zip64_unsupported".
    """
    take = min(file_size, MAX_EOCD_SEARCH)
    tail_off = file_size - take
    tail = _read_at(fp, tail_off, take)

    # ZIP64 marker presence (best-effort)
    if tail.rfind(b"PK\x06\x06") >= 0 or tail.rfind(b"PK\x06\x07") >= 0:
        # We still try to find classic EOCD, but mark zip64.
        zip64_marker = True
    else:
        zip64_marker = False

    idx = tail.rfind(b"PK\x05\x06")
    if idx < 0 or len(tail) - idx < 22:
        return None, "missing_eocd"

    # Parse EOCD (22 bytes fixed)
    # sig, disk, cd_disk, n_this, n_total, cd_size, cd_off, com_len
    try:
        sig, disk, cd_disk, n_this, n_total, cd_size, cd_off, com_len = struct.unpack_from(
            "<IHHHHIIH", tail, idx
        )
        if sig != SIG_EOCD:
            return None, "bad_eocd_sig"
    except Exception:
        return None, "eocd_parse_error"

    eocd_off = tail_off + idx
    eocd_size = 22 + int(com_len)

    info = ZipEocdInfo(
        file_size=file_size,
        eocd_off=eocd_off,
        eocd_size=eocd_size,
        cd_off=int(cd_off),
        cd_size=int(cd_size),
        n_total=int(n_total),
        comment_len=int(com_len),
        zip64_marker=zip64_marker,
    )
    return info, ""


# ----------------------------
# Parsing (metadata syntax)
# ----------------------------

def parse_central_directory(fp, eocd: ZipEocdInfo, cfg: ZipFavConfig) -> Tuple[Optional[List[ZipCdEntry]], str]:
    """
    Parse central directory entries.

    Returns (entries, "") on success, (None, reason) on failure.
    """
    # basic bounds
    if eocd.cd_off < 0 or eocd.cd_size < 0:
        return None, "cd_negative"
    if eocd.cd_off + eocd.cd_size > eocd.file_size:
        return None, "cd_oob"
    if eocd.n_total < 0 or eocd.n_total > cfg.max_entries:
        return None, "cd_entry_count_unreasonable"

    entries: List[ZipCdEntry] = []
    pos = eocd.cd_off
    cd_end = eocd.cd_off + eocd.cd_size

    while pos < cd_end:
        if pos + 46 > cd_end:
            return None, "cd_truncated"
        hdr = _read_at(fp, pos, 46)
        if len(hdr) != 46:
            return None, "cd_read_fail"
        sig = _u32le(hdr, 0)
        if sig != SIG_CEN:
            return None, "cd_bad_sig"

        # Central directory file header layout:
        # 0:4 sig
        # 4:2 ver_made, 6:2 ver_need, 8:2 flags, 10:2 method, 12:2 time, 14:2 date
        # 16:4 crc32, 20:4 csz, 24:4 usz
        # 28:2 nlen, 30:2 xlen, 32:2 clen
        # 34:2 disk_no, 36:2 int_attr, 38:4 ext_attr, 42:4 lho
        flags = _u16le(hdr, 8)
        method = _u16le(hdr, 10)
        crc32v = _u32le(hdr, 16)
        csz = _u32le(hdr, 20)
        usz = _u32le(hdr, 24)
        nlen = _u16le(hdr, 28)
        xlen = _u16le(hdr, 30)
        clen = _u16le(hdr, 32)
        lho = _u32le(hdr, 42)

        # ZIP64 markers in classic fields => unsupported in v1
        if csz == 0xFFFFFFFF or usz == 0xFFFFFFFF or lho == 0xFFFFFFFF:
            return None, "zip64_marker_in_cd"

        var_total = 46 + nlen + xlen + clen
        if pos + var_total > cd_end:
            return None, "cd_var_oob"

        name = _read_at(fp, pos + 46, nlen)
        extra = _read_at(fp, pos + 46 + nlen, xlen)
        # comment = _read_at(fp, pos + 46 + nlen + xlen, clen)  # unused

        entries.append(
            ZipCdEntry(
                name_bytes=name,
                flags=int(flags),
                method=int(method),
                crc32=int(crc32v),
                comp_size=int(csz),
                uncomp_size=int(usz),
                lfh_off=int(lho),
                extra=extra,
            )
        )
        pos += var_total

        # optional early stop if we already collected n_total
        if len(entries) >= eocd.n_total and eocd.n_total != 0:
            # Some zips may have padding; we still can break if we trust n_total.
            break

    return entries, ""


def has_winzip_aes_extra(extra: bytes) -> bool:
    """Detect WinZip AES extra field header 0x9901 (best-effort)."""
    i = 0
    L = len(extra)
    while i + 4 <= L:
        hid = _u16le(extra, i)
        sz = _u16le(extra, i + 2)
        i += 4
        if i + sz > L:
            break
        if hid == 0x9901:
            return True
        i += sz
    return False


def resolve_entries(fp, file_size: int, cd_entries: List[ZipCdEntry], cfg: ZipFavConfig) -> Tuple[Optional[List[ZipEntryResolved]], str]:
    """
    For each central directory entry, read local header and compute data spans.
    """
    resolved: List[ZipEntryResolved] = []

    for cd in cd_entries:
        lho = cd.lfh_off
        if lho < 0 or lho + 30 > file_size:
            return None, "lfh_oob"

        lfh = _read_at(fp, lho, 30)
        if len(lfh) != 30:
            return None, "lfh_read_fail"
        sig = _u32le(lfh, 0)
        if sig != SIG_LOC:
            return None, "lfh_bad_sig"

        # Local file header: after sig(4)
        # 4:2 ver, 6:2 flags, 8:2 method, 10:2 time, 12:2 date,
        # 14:4 crc, 18:4 csz, 22:4 usz, 26:2 nlen, 28:2 xlen
        l_flags = _u16le(lfh, 6)
        l_method = _u16le(lfh, 8)
        nlen = _u16le(lfh, 26)
        xlen = _u16le(lfh, 28)

        data_start = lho + 30 + nlen + xlen
        data_end_excl = data_start + cd.comp_size  # CD comp_size is source of truth

        if data_start < 0 or data_end_excl < data_start or data_end_excl > file_size:
            return None, "data_span_oob"

        # Name decoding rule (minimal): if UTF-8 flag set, enforce strict UTF-8 later in semantics check
        try:
            name_str = cd.name_bytes.decode("utf-8", errors="replace")
        except Exception:
            name_str = repr(cd.name_bytes)

        is_encrypted = bool(cd.flags & GPBF_ENCRYPTED) or (cd.method == METHOD_AES) or has_winzip_aes_extra(cd.extra)

        ent = ZipEntryResolved(
            name_bytes=cd.name_bytes,
            name=name_str,
            flags=cd.flags,
            method=cd.method,
            cd_crc32=cd.crc32,
            cd_comp_size=cd.comp_size,
            cd_uncomp_size=cd.uncomp_size,
            lfh_off=cd.lfh_off,
            lfh_name_len=int(nlen),
            lfh_extra_len=int(xlen),
            data_start=int(data_start),
            data_end_excl=int(data_end_excl),
            dd_start=int(data_end_excl),
            dd_end_excl=None,
            is_encrypted=is_encrypted,
        )

        # Optional: ensure CD/LFH method/flags are consistent (semantic check can do stricter)
        # ent.flags / ent.method are from CD by design.

        resolved.append(ent)

    return resolved, ""


# ----------------------------
# Validation (metadata semantics)
# ----------------------------

def validate_metadata_semantics(eocd: ZipEocdInfo, entries: List[ZipEntryResolved]) -> List[ComponentResult]:
    out: List[ComponentResult] = []

    # EOCD/CD bounds already checked during parsing, but keep semantic component explicit.
    # Also: zip64 marker observed in tail is handled at top-level.
    # UTF-8 flag (bit 11): filename bytes must be valid UTF-8
    for ent in entries:
        if ent.flags & GPBF_UTF8:
            try:
                ent.name_bytes.decode("utf-8", errors="strict")
            except UnicodeDecodeError:
                out.append(ComponentResult(
                    component=f"entry_name_utf8:{ent.name}",
                    score=1,
                    reason="utf8_flag_set_but_name_invalid_utf8",
                ))

    # Basic count sanity (optional): mismatch isn't always fatal due to quirks,
    # but you can decide whether it is suspicious in v1.
    # Here: if EOCD n_total != 0 and mismatch -> suspicious.
    if eocd.n_total != 0 and eocd.n_total != len(entries):
        out.append(ComponentResult(
            component="metadata",
            score=1,
            reason=f"eocd_entry_count_mismatch eocd={eocd.n_total} parsed={len(entries)}",
        ))

    if not out:
        out.append(ComponentResult(component="metadata", score=0, reason="ok"))

    return out


# ----------------------------
# Validation (data descriptor semantics)
# ----------------------------

def validate_data_descriptor(fp, file_size: int, ent: ZipEntryResolved) -> Tuple[int, str, Optional[int]]:
    """
    Validate DD at ent.dd_start. Returns (score, reason, dd_end_excl).
    v1 approach: best-effort parse; if present/parsable ensure values match CD.

    DD formats:
      - optional 4-byte signature (0x08074b50)
      - then CRC32 (4)
      - comp_size (4)  [ZIP64 uses 8, but v1 excludes ZIP64]
      - uncomp_size (4)
    Total: 12 or 16 bytes.
    """
    dd_off = ent.dd_start
    if dd_off < 0 or dd_off >= file_size:
        return 1, "dd_oob", None

    # Read up to 16 bytes
    buf = _read_at(fp, dd_off, 16)
    if len(buf) < 12:
        return 1, "dd_truncated", None

    sig = _u32le(buf, 0)
    if sig == SIG_DD:
        # signature present: crc at +4
        if len(buf) < 16:
            return 1, "dd_truncated_with_sig", None
        crc = _u32le(buf, 4)
        csz = _u32le(buf, 8)
        usz = _u32le(buf, 12)
        dd_end = dd_off + 16
    else:
        # signature absent: crc at +0
        crc = _u32le(buf, 0)
        csz = _u32le(buf, 4)
        usz = _u32le(buf, 8)
        dd_end = dd_off + 12

    # Compare to CD truth
    if crc != ent.cd_crc32 or csz != ent.cd_comp_size or usz != ent.cd_uncomp_size:
        return 1, "dd_values_mismatch_with_cd", dd_end

    return 0, "dd_ok", dd_end


# ----------------------------
# Validation (member-level semantics)
# ----------------------------

class _InflateBudget:
    __slots__ = ("per_entry_cap", "total_cap", "total_used")

    def __init__(self, per_entry_cap: int, total_cap: int):
        self.per_entry_cap = per_entry_cap
        self.total_cap = total_cap
        self.total_used = 0

def inflate_deflate_bounded(comp: bytes, cap: int) -> Tuple[Optional[bytes], str]:
    """
    Raw DEFLATE stream inflate (-15). Returns (bytes, "") on success, (None, reason) on failure.
    """
    try:
        d = zlib.decompressobj(-15)
        out = d.decompress(comp, cap)
        # If there's still output possible beyond cap, treat as over-cap (zip bomb signal for v1)
        if len(out) >= cap:
            # Not perfect, but good v1 conservative behavior.
            return None, "inflate_over_cap"
        # Also consider unconsumed_tail: compressed stream not finished.
        # In v1 we don't require full stream consumption as long as it produced data within cap,
        # but you can tighten later.
        return out, ""
    except Exception:
        return None, "inflate_error"

def compute_crc32(data: bytes) -> int:
    return zlib.crc32(data) & 0xFFFFFFFF

def flatten_nested_containers_stub(payload: bytes, enable: bool = False) -> List[Tuple[str, bytes]]:
    """
    v1: OFF by default, returns payload as single leaf.
    v2+: expand zip/gzip/ooxml/pdf etc and delegate to other FAVs.
    """
    return [("_.leaf", payload)]


def validate_member(fp, file_size: int, ent: ZipEntryResolved, cfg: ZipFavConfig, bud: _InflateBudget) -> List[ComponentResult]:
    """
    Validate one entry according to v1 policies.
    Returns a list of component results (0/1) with reasons.
    """
    out: List[ComponentResult] = []
    comp_id = f"entry:{ent.name}"

    # Encryption indicators
    if ent.is_encrypted:
        out.append(ComponentResult(component=comp_id, score=1, reason="entry_encrypted_flag_or_aes"))
        return out

    # Compression method policy
    if ent.method not in cfg.supported_methods:
        out.append(ComponentResult(component=comp_id, score=1, reason=f"unsupported_method:{ent.method}"))
        return out

    # Read compressed data
    comp_len = ent.cd_comp_size
    if comp_len < 0 or ent.data_start + comp_len > file_size:
        out.append(ComponentResult(component=comp_id, score=1, reason="compressed_span_oob"))
        return out

    comp = _read_at(fp, ent.data_start, comp_len)

    # Decompress or store
    if ent.method == METHOD_STORE:
        payload = comp
        # For STORE, a basic semantic expectation is comp_size == uncomp_size (often true).
        # But keep it as soft: if mismatch, suspicious (v1 conservative).
        if ent.cd_uncomp_size != ent.cd_comp_size:
            out.append(ComponentResult(component=comp_id, score=1, reason="store_size_mismatch_cd"))
            return out
    else:
        # DEFLATE
        # zip bomb control: cap per entry + total
        cap = min(cfg.max_uncompressed_per_entry, max(0, cfg.max_total_uncompressed - bud.total_used))
        if cap <= 0:
            out.append(ComponentResult(component=comp_id, score=1, reason="inflate_budget_exhausted"))
            return out

        payload, why = inflate_deflate_bounded(comp, cap=cap)
        if payload is None:
            out.append(ComponentResult(component=comp_id, score=1, reason=why))
            return out

        bud.total_used += len(payload)

        # Semantic expectation: decompressed length equals CD uncomp_size.
        # v1 conservative: mismatch => suspicious.
        if ent.cd_uncomp_size != len(payload):
            out.append(ComponentResult(component=comp_id, score=1, reason="uncomp_size_mismatch_cd"))
            return out

    # CRC validation (default ON)
    if cfg.crc_check:
        crc = compute_crc32(payload)
        if crc != ent.cd_crc32:
            out.append(ComponentResult(component=comp_id, score=1, reason="crc32_mismatch_cd"))
            return out

    # Nested flattening (v1 off)
    if cfg.nested_flattening:
        _ = flatten_nested_containers_stub(payload, enable=True)

    out.append(ComponentResult(component=comp_id, score=0, reason="ok"))
    return out


# ----------------------------
# Gap computation (v1: suspicious if exists)
# ----------------------------

def merge_spans(spans: Iterable[Tuple[int, int]]) -> List[Tuple[int, int]]:
    """Merge half-open spans [s,e) where s<e."""
    xs = [(int(s), int(e)) for (s, e) in spans if int(s) < int(e)]
    if not xs:
        return []
    xs.sort()
    out = [xs[0]]
    for s, e in xs[1:]:
        ps, pe = out[-1]
        if s <= pe:
            out[-1] = (ps, max(pe, e))
        else:
            out.append((s, e))
    return out

def compute_active_spans(eocd: ZipEocdInfo, entries: List[ZipEntryResolved]) -> List[Tuple[int, int]]:
    spans: List[Tuple[int, int]] = []
    spans.append(eocd.cd_span)
    spans.append(eocd.eocd_span)
    for ent in entries:
        spans.append(ent.lfh_span())
        spans.append(ent.data_span())
        if ent.dd_span() is not None:
            spans.append(ent.dd_span())  # type: ignore[arg-type]
    return merge_spans(spans)

def compute_gap_spans(file_size: int, active: List[Tuple[int, int]]) -> List[Tuple[int, int]]:
    """Return complement spans of active in [0,file_size)."""
    gaps: List[Tuple[int, int]] = []
    cur = 0
    for s, e in active:
        if cur < s:
            gaps.append((cur, s))
        cur = max(cur, e)
    if cur < file_size:
        gaps.append((cur, file_size))
    # Filter empty
    return [(s, e) for (s, e) in gaps if s < e]


# ----------------------------
# Core analysis (analyze_file)
# ----------------------------

def analyze_file(file_path: str, cfg: ZipFavConfig, *, force_zip_intent: bool = False) -> Dict[str, Optional[str]]:
    """
    Returns a dict suitable for CSV row matching unified schema.
    """
    result: Dict[str, Optional[str]] = {
        "file_path": file_path,
        "window_size": DEFAULT_WINDOW_SIZE,   # unused
        "stride": DEFAULT_STRIDE,             # unused
        "tail_mode": DEFAULT_TAIL_MODE,       # unused
        "file_size": None,
        "num_windows": 0,  # num_components
        "num_suspicious_windows": 0,
        "min_score": "",
        "max_score": "",
        "score_threshold": DEFAULT_SCORE_THRESHOLD,
        "mode": "zip_fav",
        "verdict": "error",
        "note": "",
        "error": "",
    }

    # I/O
    try:
        st = os.stat(file_path)
        file_size = int(st.st_size)
        result["file_size"] = file_size
    except Exception as e:
        result["error"] = str(e)
        result["verdict"] = "error"
        return result

    if file_size == 0:
        result["verdict"] = "not_evaluated"
        result["note"] = "empty_file"
        return result

    # v1: zip_fav is intended for zip-like files (zip/jar/apk).
    # Use extension as the primary "intent" signal.
    ext = os.path.splitext(file_path)[1].lstrip(".").lower()
    is_zip_intended = force_zip_intent or (ext in ("zip", "jar", "apk"))
    
    try:
        with open(file_path, "rb") as fp:
            # Read head only for diagnostics; DO NOT gate evaluation on it.
            head4 = _read_at(fp, 0, 4)
            head_ok = looks_like_zip_head(head4)

            # Primary ZIP detection: EOCD from tail.
            eocd, why = find_eocd(fp, file_size)

            if eocd is None:
                # If caller intended ZIP (by extension), missing EOCD means structure is
                # missing/corrupted -> suspicious (encrypted) for v1.
                if is_zip_intended:
                    comps = [ComponentResult("metadata", 1, f"eocd_missing:{why}")]
                    note = "zip_structure_missing_or_corrupted"
                    # If head isn't PK either, keep a more specific note (optional).
                    if not head_ok:
                        note = "zip_magic_invalid_and_eocd_missing"
                    return finalize_result(result, comps, verdict_if_any="encrypted", note=note)

                # If not intended as ZIP, treat as not evaluated.
                result["verdict"] = "not_evaluated"
                result["note"] = "not_zip_magic_or_missing_eocd"
                return result

            # ZIP64 policy
            if (not cfg.allow_zip64) and (eocd.zip64_marker is True):
                result["verdict"] = "not_evaluated"
                result["note"] = "zip64_unsupported"
                return result

            cd_entries, why = parse_central_directory(fp, eocd, cfg)
            if cd_entries is None:
                comps = [ComponentResult("metadata", 1, f"cd_parse_fail:{why}")]
                return finalize_result(
                    result, comps, verdict_if_any="encrypted", note=f"cd_parse_fail:{why}"
                )

            entries, why = resolve_entries(fp, file_size, cd_entries, cfg)
            if entries is None:
                comps = [ComponentResult("metadata", 1, f"lfh_resolve_fail:{why}")]
                return finalize_result(
                    result, comps, verdict_if_any="encrypted", note=f"lfh_resolve_fail:{why}"
                )

            comps: List[ComponentResult] = []

            # Metadata semantics
            comps.extend(validate_metadata_semantics(eocd, entries))

            # Data descriptor semantics (optional) + fill dd_end_excl so gap calc is correct
            if cfg.dd_validate:
                for ent in entries:
                    if ent.flags & GPBF_DD:
                        sc, r, dd_end = validate_data_descriptor(fp, file_size, ent)
                        if dd_end is not None:
                            ent.dd_end_excl = dd_end
                        comps.append(ComponentResult(component=f"dd:{ent.name}", score=sc, reason=r))

            # Member semantics (inflate + CRC)
            bud = _InflateBudget(cfg.max_uncompressed_per_entry, cfg.max_total_uncompressed)
            for ent in entries:
                comps.extend(validate_member(fp, file_size, ent, cfg, bud))

            # Gaps
            if cfg.gaps_suspicious:
                active = compute_active_spans(eocd, entries)
                gaps = compute_gap_spans(file_size, active)
                # count only non-empty gaps
                real_gaps = [(s, e) for (s, e) in gaps if e > s]
                if real_gaps:
                    comps.append(ComponentResult(component="gap", score=1, reason=f"gap_present count={len(real_gaps)}"))
                else:
                    comps.append(ComponentResult(component="gap", score=0, reason="no_gap"))

            return finalize_result(result, comps, verdict_if_any="encrypted", note="")

    except Exception as e:
        result["error"] = str(e)
        result["verdict"] = "error"
        return result

def finalize_result(
    result: Dict[str, Optional[str]],
    comps: List[ComponentResult],
    verdict_if_any: str = "encrypted",
    note: str = "",
) -> Dict[str, Optional[str]]:
    """
    Map component results to unified CSV row fields.
    """
    # Ensure at least one component
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
        # pick a concise strong reason
        first_bad = next((c for c in comps if c.score > 0), None)
        result["note"] = note or (first_bad.reason if first_bad else "has_suspicious_components")
    else:
        result["verdict"] = "benign"
        result["note"] = note or "all_components_ok"

    return result


# ----------------------------
# Run directory + config dump
# ----------------------------

def create_run_directory(output_root: str) -> str:
    os.makedirs(output_root, exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    base = f"run_{timestamp}_mode-zip_fav"
    run_dir = os.path.join(output_root, base)

    suff = 1
    unique = run_dir
    while os.path.exists(unique):
        unique = f"{run_dir}_{suff}"
        suff += 1
    os.makedirs(unique, exist_ok=False)
    return unique

def write_config_json(run_dir: str, args: argparse.Namespace, cfg: ZipFavConfig) -> None:
    path = os.path.join(run_dir, "config.json")
    obj = {
        "input_path": os.path.abspath(args.input_path),
        "mode": "zip_fav",
        "timestamp": datetime.now().isoformat(),
        "score_threshold": DEFAULT_SCORE_THRESHOLD,
        "zip_fav_config": {
            "crc_check": cfg.crc_check,
            "allow_zip64": cfg.allow_zip64,
            "supported_methods": list(cfg.supported_methods),
            "max_uncompressed_per_entry": cfg.max_uncompressed_per_entry,
            "max_total_uncompressed": cfg.max_total_uncompressed,
            "max_entries": cfg.max_entries,
            "dd_validate": cfg.dd_validate,
            "gaps_suspicious": cfg.gaps_suspicious,
            "nested_flattening": cfg.nested_flattening,
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
    raise ValueError(f"input-path is neither file nor directory: {input_path}")


# ----------------------------
# CLI
# ----------------------------

def parse_args(argv: Optional[List[str]] = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Specification-based ZIP format-aware validator (v1 skeleton)."
    )
    p.add_argument("--input-path", required=True, help="File or flat directory.")
    p.add_argument("--output-path", required=True, help="Root output directory.")

    # v1 config knobs
    p.add_argument("--crc-check", action="store_true", default=True, help="Enable CRC-32 validation (default on).")
    p.add_argument("--no-crc-check", dest="crc_check", action="store_false", help="Disable CRC-32 validation.")
    p.add_argument("--dd-validate", action="store_true", default=True, help="Validate data descriptors (default on).")
    p.add_argument("--no-dd-validate", dest="dd_validate", action="store_false", help="Disable DD validation.")
    p.add_argument("--gaps-suspicious", action="store_true", default=True, help="Treat gaps as suspicious (default on).")
    p.add_argument("--ignore-gaps", dest="gaps_suspicious", action="store_false", help="Ignore gaps (not recommended).")

    p.add_argument("--max-uncompressed-per-entry", type=int, default=32 * 1024 * 1024)
    p.add_argument("--max-total-uncompressed", type=int, default=256 * 1024 * 1024)
    p.add_argument("--max-entries", type=int, default=100_000)

    # ZIP64 remains unsupported in v1; keep the flag but default false.
    p.add_argument("--allow-zip64", action="store_true", default=False, help="Treat ZIP64 as supported (NOT v1 default).")

    # nested flattening remains off by default
    p.add_argument("--nested-flattening", action="store_true", default=False)

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

    cfg = ZipFavConfig(
        crc_check=bool(args.crc_check),
        allow_zip64=bool(args.allow_zip64),
        max_uncompressed_per_entry=int(args.max_uncompressed_per_entry),
        max_total_uncompressed=int(args.max_total_uncompressed),
        max_entries=int(args.max_entries),
        dd_validate=bool(args.dd_validate),
        gaps_suspicious=bool(args.gaps_suspicious),
        nested_flattening=bool(args.nested_flattening),
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
