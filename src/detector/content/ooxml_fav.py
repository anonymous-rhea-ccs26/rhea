#!/usr/bin/env python3
"""
ooxml_fav.py (v1)

Specification-based validator for OOXML packages (.docx/.xlsx/.pptx).

OOXML = OPC package (parts + relationships + content types) stored in a ZIP container.
This FAV is content-only and spec-driven: it detects violations of packaging invariants.

v1 design (as finalized)
------------------------
Container precondition:
- Reuse zip_fav as the container layer.
- If zip_fav verdict is suspicious/encrypted -> ooxml_fav suspicious.
- If zip_fav verdict is not_evaluated due to ZIP64 -> propagate not_evaluated (zip64_unsupported).

OOXML semantic checks (v1):
- Type identification:
  - Use extension hint (.docx/.xlsx/.pptx) and confirm:
    - [Content_Types].xml exists
    - _rels/.rels exists
    - root rels has exactly one officeDocument relationship
    - its internal target matches the expected main part path for that extension
    - main part ContentType exact match for that format
 - Path policy (mixed strict + safe normalization):
   - ZIP entry names: strict/no-normalization. Any suspicious path form is rejected:
       ../, ./, //, backslash, leading '/', control chars, or other non-standard forms.
   - Relationship Targets:
       * Internal Targets are resolved with safe normalization (POSIX join + normpath)
         relative to the source part's directory (or package root for _rels/.rels).
       * Leading '/' is treated as package-root-relative.
       * Targets are rejected if they contain control chars, backslashes, double slashes,
         percent-encoded slashes, normalize to empty/absolute, or escape the package via '..'.
       * After normalization, the resolved target must exist as a ZIP entry.
- Content types:
  - Override first, then Default.
  - XML-ness detection allows +xml suffix.
  - Content type undetermined for any referenced part => suspicious.
- Relationships:
  - External targets allowed iff URI is syntactically valid (minimal RFC3986-ish checks).
  - Internal targets must exist as ZIP entries.
- Reachability + orphan:
  - Traverse relationships starting from root .rels and following part-level .rels up to depth<=16.
  - Orphan policy is 0-tolerant:
      ORPHAN_SET = ENTRY_SET - (REFERENCED_SET ∪ ALLOWED_RESERVED_SET)
    where ALLOWED_RESERVED_SET includes [Content_Types].xml and all .rels parts.
- XML parsing:
  - Use lxml with safe options (no DTD/entities/network, no recover, huge_tree disabled).
  - Pre-limit reads (byte caps). Any budget exceed => suspicious.

Output schema matches zip_fav.py / txt_fav.py (unified):
    file_path, window_size, stride, tail_mode, file_size, num_windows,
    num_suspicious_windows, min_score, max_score, score_threshold, mode,
    verdict, note, error

For ooxml_fav:
- window_size/stride/tail_mode are retained for schema compatibility but not used.
- num_windows := number of components evaluated (metadata + checks)
- score_threshold := 0
"""

# ------------------------------------------------------------
# How to run ooxml_fav.py (examples)
# ------------------------------------------------------------
#
# Prereqs:
#   - Put ooxml_fav.py in the same directory as zip_fav.py
#     (ooxml_fav imports zip_fav as the ZIP container precondition).
#   - Install lxml:
#       pip install lxml
#
# 1) Analyze a single OOXML file (.docx/.xlsx/.pptx):
#   python3 ooxml_fav.py \
#     --input-path /path/to/sample.docx \
#     --output-path /path/to/out/
#
# 2) Analyze all files in a *flat* directory (no recursion):
#   python3 ooxml_fav.py \
#     --input-path /path/to/ooxml_dir/ \
#     --output-path /path/to/out/
#
# Output:
#   A new run directory will be created under --output-path, e.g.
#     out/run_20251227-081530_mode-ooxml_fav/
#   It will contain:
#     - config.json    (the exact run configuration)
#     - results.csv    (one row per analyzed file)
#
# v1 policy defaults (recommended):
#   - ZIP container precondition: MUST pass zip_fav
#   - officeDocument relationship: must be exactly 1
#   - Orphan parts: NOT allowed (0-tolerant)
#   - Path policy: no normalization; any suspicious path form => suspicious
#   - XML parsing: lxml strict + safe (no DTD/entities/network, no recover, huge_tree disabled)
#   - Budgets: pre-limit reads; resource exhaustion => suspicious
#
# Common knobs (mostly for experimentation; weakens v1 if loosened):
#
#   Allow orphan parts (NOT recommended for your v1 security posture):
#     python3 ooxml_fav.py --input-path ... --output-path ... --allow-orphans
#
#   Allow multiple officeDocument relationships (NOT recommended):
#     python3 ooxml_fav.py --input-path ... --output-path ... --allow-multiple-officedocument
#
#   Tighten/relax budgets (DoS vs FP tradeoff):
#     python3 ooxml_fav.py --input-path ... --output-path ... \
#       --max-xml-part-bytes   $((8*1024*1024)) \
#       --max-total-xml-bytes  $((32*1024*1024)) \
#       --max-rels-part-bytes  $((1*1024*1024)) \
#       --max-total-rels-bytes $((16*1024*1024)) \
#       --max-zip-entries      10000 \
#       --max-reachability-depth 12
#
# Notes:
#   - For non-.docx/.xlsx/.pptx extensions, ooxml_fav will still run if the file is a valid ZIP,
#     but it will NOT enforce extension-specific main-part expectations.
#   - If the ZIP is ZIP64, v1 returns verdict=not_evaluated, note=zip64_unsupported
#     (propagated from zip_fav policy).
# ------------------------------------------------------------


from __future__ import annotations

import argparse
import csv
import json
import os
import sys
import zipfile
import posixpath
import re
from dataclasses import dataclass
from datetime import datetime
from typing import Dict, List, Optional, Tuple, Set, Iterable
from urllib.parse import urlsplit

# lxml is the chosen XML parser (v1 decision)
from lxml import etree  # type: ignore

# Reuse zip_fav as container precondition (must be importable from same directory)
import zip_fav  # type: ignore

# ----------------------------
# Unified schema constants
# ----------------------------

DEFAULT_SCORE_THRESHOLD = 0
DEFAULT_WINDOW_SIZE = 4096   # unused (schema compatibility)
DEFAULT_STRIDE = 4096        # unused (schema compatibility)
DEFAULT_TAIL_MODE = "ignore" # unused (schema compatibility)


# ----------------------------
# OOXML constants
# ----------------------------

# Required OPC parts
CT_NAME = "[Content_Types].xml"
ROOT_RELS = "_rels/.rels"

# Expected main part paths per extension
MAIN_PART_PATH = {
    "docx": "word/document.xml",
    "xlsx": "xl/workbook.xml",
    "pptx": "ppt/presentation.xml",
}

# Expected main part content types (exact match)
EXPECTED_MAIN_CT = {
    "docx": "application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml",
    "xlsx": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml",
    "pptx": "application/vnd.openxmlformats-officedocument.presentationml.presentation.main+xml",
}

# Relationship type identifier for the package root officeDocument relationship
# In practice it's a full URI; we match by suffix "/officeDocument" or ending with "officeDocument".
OFFICE_DOCUMENT_SUFFIX = "officeDocument"
OFFICE_DOCUMENT_RELTYPE = (
    "http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument"
)

# Path policy: strict/no-normalization and "standard Office-only" assumption
_CONTROL_CHAR_RE = re.compile(r"[\x00-\x1F\x7F]")  # includes NUL and DEL

# ----------------------------
# Data structures
# ----------------------------

@dataclass(frozen=True)
class ComponentResult:
    component: str
    score: int      # 0/1
    reason: str     # note code or verbose reason


@dataclass(frozen=True)
class OoxmlFavConfig:
    # Budgets
    max_total_read_bytes: int = 512 * 1024 * 1024           # 512 MiB
    max_zip_entries: int = 20_000
    max_single_entry_uncompressed_bytes: int = 64 * 1024 * 1024  # 64 MiB

    max_xml_part_bytes: int = 16 * 1024 * 1024              # 16 MiB
    max_total_xml_bytes: int = 64 * 1024 * 1024             # 64 MiB
    max_rels_part_bytes: int = 2 * 1024 * 1024              # 2 MiB
    max_total_rels_bytes: int = 32 * 1024 * 1024            # 32 MiB

    max_rels_files_followed: int = 256
    max_relationships_per_rels: int = 50_000
    max_relationships_total: int = 1_000_000
    max_reachability_depth: int = 16

    max_bin_part_bytes: int = 256 * 1024 * 1024             # 256 MiB
    bin_sniff_bytes: int = 64 * 1024                        # 64 KiB

    # Policy toggles
    orphan_zero_tolerant: bool = True
    office_document_must_be_unique: bool = True
    path_normalization: bool = False  # v1: must be False
    allow_external_all_schemes: bool = True  # v1: parseable => allow


# ----------------------------
# Helper: run dir + config dump
# ----------------------------

def create_run_directory(output_root: str) -> str:
    os.makedirs(output_root, exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    base = f"run_{timestamp}_mode-ooxml_fav"
    run_dir = os.path.join(output_root, base)

    suff = 1
    unique = run_dir
    while os.path.exists(unique):
        unique = f"{run_dir}_{suff}"
        suff += 1
    os.makedirs(unique, exist_ok=False)
    return unique


def write_config_json(run_dir: str, args: argparse.Namespace, cfg: OoxmlFavConfig) -> None:
    path = os.path.join(run_dir, "config.json")
    obj = {
        "input_path": os.path.abspath(args.input_path),
        "mode": "ooxml_fav",
        "timestamp": datetime.now().isoformat(),
        "score_threshold": DEFAULT_SCORE_THRESHOLD,
        "ooxml_fav_config": {
            "max_total_read_bytes": cfg.max_total_read_bytes,
            "max_zip_entries": cfg.max_zip_entries,
            "max_single_entry_uncompressed_bytes": cfg.max_single_entry_uncompressed_bytes,
            "max_xml_part_bytes": cfg.max_xml_part_bytes,
            "max_total_xml_bytes": cfg.max_total_xml_bytes,
            "max_rels_part_bytes": cfg.max_rels_part_bytes,
            "max_total_rels_bytes": cfg.max_total_rels_bytes,
            "max_rels_files_followed": cfg.max_rels_files_followed,
            "max_relationships_per_rels": cfg.max_relationships_per_rels,
            "max_relationships_total": cfg.max_relationships_total,
            "max_reachability_depth": cfg.max_reachability_depth,
            "max_bin_part_bytes": cfg.max_bin_part_bytes,
            "bin_sniff_bytes": cfg.bin_sniff_bytes,
            "orphan_zero_tolerant": cfg.orphan_zero_tolerant,
            "office_document_must_be_unique": cfg.office_document_must_be_unique,
            "path_normalization": cfg.path_normalization,
            "allow_external_all_schemes": cfg.allow_external_all_schemes,
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
# Safety / parsing helpers
# ----------------------------

def is_suspicious_zip_entry_name(name: str) -> bool:
    """
    Strict policy for ZIP entry names.
    No normalization. Any deviation from standard OOXML-style paths is suspicious.
    """
    if not name:
        return True
    if _CONTROL_CHAR_RE.search(name):
        return True
    if "\\" in name:
        return True
    if name.startswith("/"):
        return True
    if "//" in name:
        return True
    if name.startswith("./") or name.startswith("../"):
        return True
    if "/./" in f"/{name}/" or name.endswith("/."):
        return True
    if "/../" in f"/{name}/" or name.endswith("/.."):
        return True
    return False

def normalize_relationship_target(
    source_part: str,
    target: str
) -> Tuple[Optional[str], str]:
    """
    Safe normalization for OOXML relationship targets.

    Allows ../ and leading /, but enforces that the resolved path:
      - stays within the package
      - contains no control characters or backslashes
      - is not absolute
    """
    if not target:
        return None, "empty_target"

    if _CONTROL_CHAR_RE.search(target):
        return None, "target_contains_control_characters"

    if "\\" in target:
        return None, "target_contains_backslash"

    if "//" in target:
        return None, "target_contains_double_slash"

    low = target.lower()
    if "%2f" in low or "%5c" in low:
        return None, "target_contains_percent_encoded_slash"

    # Interpret leading "/" as package-root-relative
    t = target[1:] if target.startswith("/") else target

    base_dir = posixpath.dirname(source_part) if source_part else ""
    joined = posixpath.join(base_dir, t) if base_dir else t
    normed = posixpath.normpath(joined)

    if normed in ("", ".", "/"):
        return None, "normalized_target_empty"

    if normed.startswith("/"):
        return None, "normalized_target_absolute"

    # Must not escape the package
    if normed == ".." or normed.startswith("../") or "/../" in f"/{normed}/":
        return None, "normalized_target_escapes_package"

    return normed, ""


def _url_is_syntactically_valid(u: str) -> bool:
    """
    Minimal offline syntax gate for External URLs.
    v1 policy: allow any scheme as long as it's parseable and has no control chars/spaces.
    """
    if not u:
        return False
    if _CONTROL_CHAR_RE.search(u) is not None:
        return False
    # reject whitespace for strictness (space, tab, newline)
    if any(ch.isspace() for ch in u):
        return False
    try:
        _ = urlsplit(u)
        return True
    except Exception:
        return False


def _make_xml_parser() -> etree.XMLParser:
    """
    lxml safe + strict parser (v1 fixed).
    """
    return etree.XMLParser(
        resolve_entities=False,
        load_dtd=False,
        dtd_validation=False,
        no_network=True,
        recover=False,
        huge_tree=False,
    )


def _read_zip_entry_limited(zf: zipfile.ZipFile, name: str, limit: int) -> Tuple[Optional[bytes], str]:
    """
    Read a ZIP entry with a hard byte limit. If uncompressed size > limit -> budget exceeded.
    """
    try:
        info = zf.getinfo(name)
    except KeyError:
        return None, "missing_entry"
    # zipfile reports uncompressed size in info.file_size
    if info.file_size < 0:
        return None, "negative_size"
    if info.file_size > limit:
        return None, "entry_over_limit"
    try:
        with zf.open(info, "r") as fp:
            data = fp.read(limit + 1)
            if len(data) > limit:
                return None, "entry_over_limit"
            return data, ""
    except Exception:
        return None, "entry_read_fail"


# ----------------------------
# Content Types parsing
# ----------------------------

@dataclass
class ContentTypes:
    default: Dict[str, str]
    override: Dict[str, str]


def parse_content_types(xml_bytes: bytes) -> Tuple[Optional[ContentTypes], str]:
    """
    Parse [Content_Types].xml and build Default/Override maps.
    """
    try:
        parser = _make_xml_parser()
        root = etree.fromstring(xml_bytes, parser=parser)
    except Exception:
        return None, "ooxml_ct_xml_parse_fail"

    ns = root.nsmap.get(None, "")
    # We keep the parsing tolerant to namespace variations but still spec-driven.
    def _tag(local: str) -> str:
        if ns:
            return f"{{{ns}}}{local}"
        return local

    d: Dict[str, str] = {}
    o: Dict[str, str] = {}

    for elem in root:
        try:
            if elem.tag == _tag("Default"):
                ext = (elem.get("Extension") or "").strip()
                ct = (elem.get("ContentType") or "").strip()
                if ext and ct:
                    d[ext.lower()] = ct
            elif elem.tag == _tag("Override"):
                pn = (elem.get("PartName") or "").strip()
                ct = (elem.get("ContentType") or "").strip()
                if pn and ct:
                    # PartName in [Content_Types].xml begins with leading "/"
                    if pn.startswith("/"):
                        pn = pn[1:]
                    o[pn] = ct
        except Exception:
            # ignore malformed items; well-formedness is already checked above
            continue

    return ContentTypes(default=d, override=o), ""


def content_type_for_part(ct: ContentTypes, part: str) -> Optional[str]:
    """
    Resolve content type: Override first, then Default mapping by extension.
    part is normalized to no leading '/'.
    """
    if part.startswith("/"):
        part = part[1:]
    if part in ct.override:
        return ct.override[part]
    ext = part.rsplit(".", 1)[-1].lower() if "." in part else ""
    if not ext:
        return None
    return ct.default.get(ext)


def is_xml_content_type(ct: str) -> bool:
    lo = ct.strip().lower()
    return lo.endswith("+xml") or lo in ("application/xml", "text/xml") or lo.endswith("/xml")


# ----------------------------
# Relationships parsing
# ----------------------------


@dataclass(frozen=True)
class Relationship:
    r_id: str
    r_type: str
    target: str
    target_mode: str  # "Internal" (default) or "External"


def parse_rels(xml_bytes: bytes, cfg: OoxmlFavConfig) -> Tuple[Optional[List[Relationship]], str]:
    """
    Parse a .rels file into relationships.
    """
    try:
        parser = _make_xml_parser()
        root = etree.fromstring(xml_bytes, parser=parser)
    except Exception:
        return None, "ooxml_rels_xml_parse_fail"

    rels: List[Relationship] = []
    count = 0

    for elem in root.iter():
        # Relationship elements are typically named Relationship in the package relationships namespace
        if elem.tag.endswith("Relationship"):
            rid = (elem.get("Id") or "").strip()
            rtype = (elem.get("Type") or "").strip()
            target = (elem.get("Target") or "").strip()
            tmode = (elem.get("TargetMode") or "Internal").strip()
            if rid and rtype and target:
                rels.append(Relationship(r_id=rid, r_type=rtype, target=target, target_mode=tmode))
                count += 1
                if count > cfg.max_relationships_per_rels:
                    return None, "ooxml_rels_too_many_relationships"

    return rels, ""


def rels_path_for_part(part: str) -> str:
    """
    Given a part path like 'word/document.xml', return its relationship part:
      'word/_rels/document.xml.rels'
    """
    d = posixpath.dirname(part)
    b = posixpath.basename(part)
    if d:
        return posixpath.join(d, "_rels", b + ".rels")
    return posixpath.join("_rels", b + ".rels")


# ----------------------------
# Aggregation / result mapping
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
        result["note"] = note or (first_bad.reason if first_bad else "ooxml_has_suspicious_components")
    else:
        result["verdict"] = "benign"
        result["note"] = note or "all_components_ok"

    return result


# ----------------------------
# Core OOXML analysis
# ----------------------------

def analyze_file(file_path: str, cfg: OoxmlFavConfig) -> Dict[str, Optional[str]]:
    """
    Returns a dict suitable for CSV row matching unified schema.
    """
    result: Dict[str, Optional[str]] = {
        "file_path": file_path,
        "window_size": DEFAULT_WINDOW_SIZE,
        "stride": DEFAULT_STRIDE,
        "tail_mode": DEFAULT_TAIL_MODE,
        "file_size": None,
        "num_windows": "0",
        "num_suspicious_windows": "0",
        "min_score": "",
        "max_score": "",
        "score_threshold": DEFAULT_SCORE_THRESHOLD,
        "mode": "ooxml_fav",
        "verdict": "error",
        "note": "",
        "error": "",
    }

    # file_size
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

    # Extension hint
    ext = os.path.splitext(file_path)[1].lstrip(".").lower()
    is_ooxml_intended = ext in ("docx", "xlsx", "pptx")

    # --- Container precondition: zip_fav ---
    zcfg = zip_fav.ZipFavConfig(
        crc_check=True,
        allow_zip64=False,
        # keep defaults consistent with zip_fav v1
        max_uncompressed_per_entry=32 * 1024 * 1024,
        max_total_uncompressed=256 * 1024 * 1024,
        max_entries=100_000,
        dd_validate=True,
        gaps_suspicious=True,
        nested_flattening=False,
    )

    zrow = zip_fav.analyze_file(file_path, zcfg, force_zip_intent=True)

    zv = (zrow.get("verdict") or "").strip()
    zn = (zrow.get("note") or "").strip()
    ze = (zrow.get("error") or "").strip()

    if zv == "error":
        result["verdict"] = "error"
        result["error"] = f"zip_precondition_error:{ze or zn}"
        return result

    if zv == "not_evaluated":
        # propagate ZIP64 unsupported as-is; otherwise treat as not evaluated.
        result["verdict"] = "not_evaluated"
        result["note"] = zn or "zip_precondition_not_evaluated"
        return result

    if zv != "benign":
        # For intended OOXML, any non-benign at container layer is suspicious.
        if is_ooxml_intended:
            comps = [ComponentResult("zip_container", 1, f"ooxml_precondition_failed:zip_{zn or zv}")]
            return finalize_result(result, comps, verdict_if_any="encrypted", note=f"ooxml_precondition_failed:zip_{zn or zv}")
        # If not intended OOXML, treat as not evaluated.
        result["verdict"] = "not_evaluated"
        result["note"] = "not_ooxml_or_zip_precondition_failed"
        return result

    # --- OOXML layer ---
    comps: List[ComponentResult] = []
    total_read_budget_used = 0
    total_xml_budget_used = 0
    total_rels_budget_used = 0

    try:
        with zipfile.ZipFile(file_path, "r") as zf:
            infos = zf.infolist()

            # Entry count budget
            if len(infos) > cfg.max_zip_entries:
                comps.append(ComponentResult("ooxml_budget", 1, f"ooxml_budget_exceeded:max_zip_entries={len(infos)}"))
                return finalize_result(result, comps, verdict_if_any="encrypted")

            # Build entry set and detect duplicates
            entry_names: List[str] = [zi.filename for zi in infos]
            entry_set: Set[str] = set(entry_names)
            if len(entry_set) != len(entry_names):
                comps.append(ComponentResult("ooxml_required_parts", 1, "ooxml_duplicate_entry_names"))
                return finalize_result(result, comps, verdict_if_any="encrypted")

            # Strict ZIP entry name policy (no normalization)
            for name in entry_set:
                if is_suspicious_zip_entry_name(name):
                    comps.append(ComponentResult(
                        component="ooxml_path_policy",
                        score=1,
                        reason=f"ooxml_path_suspicious:where=zip_entry,value={name}",
                    ))
                    return finalize_result(result, comps, verdict_if_any="encrypted")


            # Required parts
            if CT_NAME not in entry_set:
                comps.append(ComponentResult("ooxml_required_parts", 1, "ooxml_missing_content_types"))
                return finalize_result(result, comps, verdict_if_any="encrypted")
            if ROOT_RELS not in entry_set:
                comps.append(ComponentResult("ooxml_required_parts", 1, "ooxml_missing_root_rels"))
                return finalize_result(result, comps, verdict_if_any="encrypted")

            # Parse [Content_Types].xml (pre-limit)
            ct_bytes, why = _read_zip_entry_limited(zf, CT_NAME, cfg.max_xml_part_bytes)
            if ct_bytes is None:
                comps.append(ComponentResult("ooxml_content_types", 1, f"ooxml_ct_read_fail:{why}"))
                return finalize_result(result, comps, verdict_if_any="encrypted")
            total_read_budget_used += len(ct_bytes)
            if total_read_budget_used > cfg.max_total_read_bytes:
                comps.append(ComponentResult(
                    "ooxml_budget", 1,
                    f"ooxml_budget_exceeded:max_total_read_bytes={total_read_budget_used}"
                ))
                return finalize_result(result, comps, verdict_if_any="encrypted")
            total_xml_budget_used += len(ct_bytes)
            if total_xml_budget_used > cfg.max_total_xml_bytes:
                comps.append(ComponentResult("ooxml_budget", 1, f"ooxml_budget_exceeded:max_total_xml_bytes={total_xml_budget_used}"))
                return finalize_result(result, comps, verdict_if_any="encrypted")

            ct, why = parse_content_types(ct_bytes)
            if ct is None:
                comps.append(ComponentResult("ooxml_content_types", 1, why))
                return finalize_result(result, comps, verdict_if_any="encrypted")

            # Parse root rels
            rels_bytes, why = _read_zip_entry_limited(zf, ROOT_RELS, cfg.max_rels_part_bytes)
            if rels_bytes is None:
                comps.append(ComponentResult("ooxml_rels_root", 1, f"ooxml_rels_root_read_fail:{why}"))
                return finalize_result(result, comps, verdict_if_any="encrypted")
            total_read_budget_used += len(rels_bytes)
            if total_read_budget_used > cfg.max_total_read_bytes:
                comps.append(ComponentResult(
                    "ooxml_budget", 1,
                    f"ooxml_budget_exceeded:max_total_read_bytes={total_read_budget_used}"
                ))
                return finalize_result(result, comps, verdict_if_any="encrypted")
            total_rels_budget_used += len(rels_bytes)
            if total_rels_budget_used > cfg.max_total_rels_bytes:
                comps.append(ComponentResult("ooxml_budget", 1, f"ooxml_budget_exceeded:max_total_rels_bytes={total_rels_budget_used}"))
                return finalize_result(result, comps, verdict_if_any="encrypted")

            root_rels, why = parse_rels(rels_bytes, cfg)
            if root_rels is None:
                comps.append(ComponentResult("ooxml_rels_root", 1, why))
                return finalize_result(result, comps, verdict_if_any="encrypted")

            # officeDocument relationship must be unique
            office_rels = [r for r in root_rels if r.r_type == OFFICE_DOCUMENT_RELTYPE]
            if not office_rels:
                # Optional tolerance: allow suffix match only if exact match not found.
                # This keeps v1 strict but avoids trivial vendor variation.
                office_rels = [r for r in root_rels if r.r_type.endswith("/officeDocument")]
            if cfg.office_document_must_be_unique and len(office_rels) != 1:
                comps.append(ComponentResult("ooxml_rels_root", 1, f"ooxml_rels_officeDocument_count:k={len(office_rels)}"))
                return finalize_result(result, comps, verdict_if_any="encrypted")

            if not office_rels:
                comps.append(ComponentResult("ooxml_rels_root", 1, "ooxml_rels_missing_officeDocument"))
                return finalize_result(result, comps, verdict_if_any="encrypted")

            office_rel = office_rels[0]

            # Handle officeDocument target (external forbidden by policy intent)
            if office_rel.target_mode.lower() == "external":
                comps.append(ComponentResult("ooxml_rels_root", 1, "ooxml_officeDocument_external_target_forbidden"))
                return finalize_result(result, comps, verdict_if_any="encrypted")

            main_part, why = normalize_relationship_target("", office_rel.target)
            if main_part is None:
                comps.append(ComponentResult(
                    component="ooxml_path_policy",
                    score=1,
                    reason=f"ooxml_path_suspicious:where=rels_target,value={office_rel.target},why={why}",
                ))
                return finalize_result(result, comps, verdict_if_any="encrypted")

            if main_part not in entry_set:
                comps.append(ComponentResult("ooxml_required_parts", 1, f"ooxml_missing_main_part:target=/{main_part}"))
                return finalize_result(result, comps, verdict_if_any="encrypted")

            # Extension-based type confirmation (strict)
            if is_ooxml_intended:
                expected_main = MAIN_PART_PATH[ext]
                if main_part != expected_main:
                    comps.append(ComponentResult("ooxml_required_parts", 1, f"ooxml_type_mismatch:ext={ext},target=/{main_part}"))
                    return finalize_result(result, comps, verdict_if_any="encrypted")
            else:
                # If extension isn't docx/xlsx/pptx, we still can evaluate, but we won't enforce main-part expectations.
                pass

            # Main part content type exactness (only if extension is recognized)
            if is_ooxml_intended:
                main_ct = content_type_for_part(ct, main_part)
                if main_ct is None:
                    comps.append(ComponentResult("ooxml_content_types", 1, f"ooxml_ct_undetermined:part=/{main_part}"))
                    return finalize_result(result, comps, verdict_if_any="encrypted")
                if main_ct.strip() != EXPECTED_MAIN_CT[ext]:
                    comps.append(ComponentResult("ooxml_content_types", 1, f"ooxml_main_ct_mismatch:part=/{main_part},ct={main_ct}"))
                    return finalize_result(result, comps, verdict_if_any="encrypted")

            # Check: overrides must refer to existing parts (strict)
            for part, _ct in ct.override.items():
                if part not in entry_set:
                    comps.append(ComponentResult("ooxml_content_types", 1, f"ooxml_ct_override_missing_part:part=/{part}"))
                    return finalize_result(result, comps, verdict_if_any="encrypted")

            # --- Reachability traversal (depth-limited) ---
            referenced_set: Set[str] = set()
            visited_rels: Set[str] = set()
            relationships_seen = 0

            # queue holds (source_part, rels_part, depth)
            # for root .rels, source_part is "" and rels_part is ROOT_RELS
            queue: List[Tuple[str, str, int]] = [("", ROOT_RELS, 0)]

            while queue:
                source_part, rels_part, depth = queue.pop(0)

                if depth > cfg.max_reachability_depth:
                    comps.append(ComponentResult("ooxml_budget", 1, f"ooxml_budget_exceeded:max_reachability_depth={depth}"))
                    return finalize_result(result, comps, verdict_if_any="encrypted")

                if rels_part in visited_rels:
                    continue
                visited_rels.add(rels_part)

                if len(visited_rels) > cfg.max_rels_files_followed:
                    comps.append(ComponentResult("ooxml_budget", 1, f"ooxml_budget_exceeded:max_rels_files_followed={len(visited_rels)}"))
                    return finalize_result(result, comps, verdict_if_any="encrypted")

                # .rels must exist to parse; if missing for a part, we simply don't expand further (not suspicious)
                if rels_part not in entry_set:
                    continue

                rb, why = _read_zip_entry_limited(zf, rels_part, cfg.max_rels_part_bytes)
                if rb is None:
                    comps.append(ComponentResult("ooxml_reachability", 1, f"ooxml_rels_read_fail:part=/{rels_part},why={why}"))
                    return finalize_result(result, comps, verdict_if_any="encrypted")

                total_read_budget_used += len(rb)
                if total_read_budget_used > cfg.max_total_read_bytes:
                    comps.append(ComponentResult(
                        "ooxml_budget", 1,
                        f"ooxml_budget_exceeded:max_total_read_bytes={total_read_budget_used}"
                    ))
                    return finalize_result(result, comps, verdict_if_any="encrypted")
                total_rels_budget_used += len(rb)
                if total_rels_budget_used > cfg.max_total_rels_bytes:
                    comps.append(ComponentResult("ooxml_budget", 1, f"ooxml_budget_exceeded:max_total_rels_bytes={total_rels_budget_used}"))
                    return finalize_result(result, comps, verdict_if_any="encrypted")

                rels, why = parse_rels(rb, cfg)
                if rels is None:
                    # strict: malformed rels -> suspicious
                    comps.append(ComponentResult("ooxml_reachability", 1, f"ooxml_rels_parse_fail:part=/{rels_part},why={why}"))
                    return finalize_result(result, comps, verdict_if_any="encrypted")

                for r in rels:
                    relationships_seen += 1
                    if relationships_seen > cfg.max_relationships_total:
                        comps.append(ComponentResult("ooxml_budget", 1, f"ooxml_budget_exceeded:max_relationships_total={relationships_seen}"))
                        return finalize_result(result, comps, verdict_if_any="encrypted")

                    if r.target_mode.lower() == "external":
                        # External is allowed if syntactically valid
                        if not _url_is_syntactically_valid(r.target):
                            comps.append(ComponentResult("ooxml_reachability", 1, f"ooxml_url_invalid:value={r.target}"))
                            return finalize_result(result, comps, verdict_if_any="encrypted")
                        continue

                    tgt, why = normalize_relationship_target(source_part, r.target)
                    if tgt is None:
                        comps.append(ComponentResult(
                            component="ooxml_path_policy",
                            score=1,
                            reason=f"ooxml_path_suspicious:where=rels_target,value={r.target},why={why}",
                        ))
                        return finalize_result(result, comps, verdict_if_any="encrypted")

                    # Target must exist
                    if tgt not in entry_set:
                        comps.append(ComponentResult("ooxml_reachability", 1, f"ooxml_dangling_relationship:target=/{tgt}"))
                        return finalize_result(result, comps, verdict_if_any="encrypted")

                    referenced_set.add(tgt)

                    # Referenced parts must have determinable content type
                    tgt_ct = content_type_for_part(ct, tgt)
                    if tgt_ct is None:
                        comps.append(ComponentResult("ooxml_content_types", 1, f"ooxml_ct_undetermined:part=/{tgt}"))
                        return finalize_result(result, comps, verdict_if_any="encrypted")

                    # XML parts: strict parse (pre-limit)
                    if is_xml_content_type(tgt_ct):
                        xb, why = _read_zip_entry_limited(zf, tgt, cfg.max_xml_part_bytes)
                        if xb is None:
                            comps.append(ComponentResult("ooxml_xml_parse", 1, f"ooxml_xml_read_fail:part=/{tgt},why={why}"))
                            return finalize_result(result, comps, verdict_if_any="encrypted")
                        total_read_budget_used += len(xb)
                        if total_read_budget_used > cfg.max_total_read_bytes:
                            comps.append(ComponentResult(
                                "ooxml_budget", 1,
                                f"ooxml_budget_exceeded:max_total_read_bytes={total_read_budget_used}"
                            ))
                            return finalize_result(result, comps, verdict_if_any="encrypted")
                        total_xml_budget_used += len(xb)
                        if total_xml_budget_used > cfg.max_total_xml_bytes:
                            comps.append(ComponentResult("ooxml_budget", 1, f"ooxml_budget_exceeded:max_total_xml_bytes={total_xml_budget_used}"))
                            return finalize_result(result, comps, verdict_if_any="encrypted")

                        try:
                            parser = _make_xml_parser()
                            _ = etree.fromstring(xb, parser=parser)
                        except Exception:
                            comps.append(ComponentResult("ooxml_xml_parse", 1, f"ooxml_xml_parse_fail:part=/{tgt}"))
                            return finalize_result(result, comps, verdict_if_any="encrypted")
                    else:
                        # Non-XML: bounded sniff only (v1)
                        info = zf.getinfo(tgt)
                        if info.file_size > cfg.max_bin_part_bytes:
                            comps.append(ComponentResult("ooxml_budget", 1, f"ooxml_budget_exceeded:max_bin_part_bytes:part=/{tgt},size={info.file_size}"))
                            return finalize_result(result, comps, verdict_if_any="encrypted")
                        # optional sniff read; failures treated as suspicious (content corruption)
                        try:
                            with zf.open(info, "r") as fp:
                                _ = fp.read(min(cfg.bin_sniff_bytes, max(0, info.file_size)))
                        except Exception:
                            comps.append(ComponentResult("ooxml_budget", 1, f"ooxml_bin_read_fail:part=/{tgt}"))
                            return finalize_result(result, comps, verdict_if_any="encrypted")

                    # Follow child .rels of this target part (if exists)
                    child_rels = rels_path_for_part(tgt)
                    # We enqueue regardless; if it doesn't exist it will be skipped.
                    if depth + 1 <= cfg.max_reachability_depth:
                        queue.append((tgt, child_rels, depth + 1))

            # --- Orphan check (0-tolerant) ---
            # Reserved parts are meta and are excluded from orphan count:
            allowed_reserved: Set[str] = {CT_NAME}
            allowed_reserved |= {n for n in entry_set if n.endswith(".rels")}

            orphan_set = entry_set - (referenced_set | allowed_reserved)
            if cfg.orphan_zero_tolerant and orphan_set:
                comps.append(ComponentResult("ooxml_reachability", 1, f"ooxml_orphan_parts:n={len(orphan_set)}"))
                return finalize_result(result, comps, verdict_if_any="encrypted")

            # If we reached here, all checks passed.
            comps.append(ComponentResult("ooxml_required_parts", 0, "ok"))
            comps.append(ComponentResult("ooxml_content_types", 0, "ok"))
            comps.append(ComponentResult("ooxml_rels_root", 0, "ok"))
            comps.append(ComponentResult("ooxml_reachability", 0, "ok"))
            comps.append(ComponentResult("ooxml_xml_parse", 0, "ok"))
            comps.append(ComponentResult("ooxml_path_policy", 0, "ok"))
            comps.append(ComponentResult("ooxml_budget", 0, "ok"))

            return finalize_result(result, comps, verdict_if_any="encrypted")

    except zipfile.BadZipFile:
        # Should have been caught by zip_fav precondition, but keep a clear error
        if is_ooxml_intended:
            comps = [ComponentResult("zip_container", 1, "ooxml_precondition_failed:zip_badzipfile")]
            return finalize_result(result, comps, verdict_if_any="encrypted")
        result["verdict"] = "not_evaluated"
        result["note"] = "bad_zipfile"
        return result
    except Exception as e:
        result["verdict"] = "error"
        result["error"] = str(e)
        return result


# ----------------------------
# CLI
# ----------------------------

def parse_args(argv: Optional[List[str]] = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Specification-based OOXML format-aware validator (v1)."
    )
    p.add_argument("--input-path", required=True, help="File or flat directory.")
    p.add_argument("--output-path", required=True, help="Root output directory.")

    # Budgets (optional overrides)
    p.add_argument("--max-zip-entries", type=int, default=20_000)
    p.add_argument("--max-total-read-bytes", type=int, default=512 * 1024 * 1024)
    p.add_argument("--max-xml-part-bytes", type=int, default=16 * 1024 * 1024)
    p.add_argument("--max-total-xml-bytes", type=int, default=64 * 1024 * 1024)
    p.add_argument("--max-rels-part-bytes", type=int, default=2 * 1024 * 1024)
    p.add_argument("--max-total-rels-bytes", type=int, default=32 * 1024 * 1024)
    p.add_argument("--max-rels-files-followed", type=int, default=256)
    p.add_argument("--max-reachability-depth", type=int, default=16)
    p.add_argument("--max-relationships-per-rels", type=int, default=50_000)
    p.add_argument("--max-relationships-total", type=int, default=1_000_000)

    # Policy toggles (v1 defaults are strict)
    p.add_argument("--allow-orphans", action="store_true", default=False,
                   help="Allow orphan parts (NOT v1 default; weakens model).")
    p.add_argument("--allow-multiple-officedocument", action="store_true", default=False,
                   help="Allow multiple officeDocument relationships (NOT v1 default).")

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

    cfg = OoxmlFavConfig(
        max_total_read_bytes=int(args.max_total_read_bytes),
        max_zip_entries=int(args.max_zip_entries),
        max_xml_part_bytes=int(args.max_xml_part_bytes),
        max_total_xml_bytes=int(args.max_total_xml_bytes),
        max_rels_part_bytes=int(args.max_rels_part_bytes),
        max_total_rels_bytes=int(args.max_total_rels_bytes),
        max_rels_files_followed=int(args.max_rels_files_followed),
        max_reachability_depth=int(args.max_reachability_depth),
        max_relationships_per_rels=int(args.max_relationships_per_rels),
        max_relationships_total=int(args.max_relationships_total),
        orphan_zero_tolerant=(not bool(args.allow_orphans)),
        office_document_must_be_unique=(not bool(args.allow_multiple_officedocument)),
        path_normalization=False,
        allow_external_all_schemes=True,
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
