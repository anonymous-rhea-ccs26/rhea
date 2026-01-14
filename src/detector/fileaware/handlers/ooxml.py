# detector/fileaware/handlers/ooxml.py
import os
import io
import re
import bisect
import struct
import zipfile
import csv
import zlib
from typing import List, Optional, Tuple
import xml.etree.ElementTree as ET

from zlib import error as _ZlibError
from ..types import (
    FileContext,
    SuspiciousFileRegion,
    FileAwareDecision,
    RegionDecision,
)

OOXML_EXTS = {"docx", "xlsx", "pptx"}

# OOXML buckets (non-text content we want to examine structurally)
FONT_PREFIXES       = ("word/fonts/", "ppt/fonts/", "xl/fonts/")
EMBED_PREFIXES      = ("word/embeddings/", "ppt/embeddings/", "xl/embeddings/")
ACTIVEX_PREFIXES    = ("word/activeX/", "ppt/activeX/", "xl/activeX/")
VBA_NAMES           = ("vbaProject.bin",)  # CFB container
THUMB_PREFIX        = "docprops/thumbnail."  # jpeg/png etc.

# Media paths we DO evaluate via trust set
MEDIA_PREFIXES      = ("word/media/", "ppt/media/", "xl/media/")

# ZIP method constants (for completeness; not strictly needed here)
METHOD_STORE   = 0
METHOD_DEFLATE = 8

# Path-based index (kept for diagnostics/back-compat)
_TRUST_OOXML = {}             # (container_abs, entry_norm) -> sha256_lower
# Per-container SHA index (tolerates entry renames within the same container path)
_TRUST_OOXML_SHA = {}         # (container_abs, sha256_lower) -> entry_norm (first seen)
# Global SHA index (ignores container path entirely; hash-only trust)
#   sha256_lower -> list of (container_abs, entry_norm)
_TRUST_OOXML_SHA_GLOBAL = {}  # sha256_lower -> [(cont, entry), ...]

# Heuristic: anything before this offset is “early metadata surface” (LFHs, small XML parts)
_EARLY_METADATA_WINDOW = 64 * 1024

def _norm_zip_name(name: str) -> str:
    return (name or "").replace("\\", "/")

def _absnorm(p: str) -> str:
    return os.path.abspath(os.path.expanduser(p))

def _load_trusted_manifest_csv(path: str) -> None:
    global _TRUST_OOXML, _TRUST_OOXML_SHA, _TRUST_OOXML_SHA_GLOBAL
    # If already loaded or no path provided, skip.
    if (_TRUST_OOXML or _TRUST_OOXML_SHA or _TRUST_OOXML_SHA_GLOBAL) or not path:
        return
    try:
        with open(path, "r", newline="", encoding="utf-8") as f:
            r = csv.DictReader(f)
            for row in r:
                src = (row.get("source") or "").strip().lower()
                if src != "ooxml":
                    continue
                sha = (row.get("sha256") or "").strip().lower()
                cont = _absnorm(row.get("container") or "")
                entry = _norm_zip_name(row.get("entry") or "")
                if sha and cont and entry:
                    _TRUST_OOXML[(cont, entry)] = sha
                    # Populate SHA index: allow match by bytes even if entry path differs.
                    # Keep one representative entry for reason strings.
                    key = (cont, sha)
                    if key not in _TRUST_OOXML_SHA:
                        _TRUST_OOXML_SHA[key] = entry
                    # Populate GLOBAL sha index (hash-only trust, any container)
                    try:
                        _TRUST_OOXML_SHA_GLOBAL.setdefault(sha, []).append((cont, entry))
                    except Exception:
                        pass
    except Exception:
        _TRUST_OOXML = {}
        _TRUST_OOXML_SHA = {}
        _TRUST_OOXML_SHA_GLOBAL = {}
        
def _ext(path: str) -> str:
    e = os.path.splitext(path)[1]
    return e[1:].lower() if e.startswith(".") else e.lower()

def _looks_like_ooxml(path: str) -> bool:
    try:
        with zipfile.ZipFile(path, "r") as zf:
            return "[Content_Types].xml" in zf.namelist()
    except Exception:
        return False

def _read_local_header_data_span(fp, header_offset: int, comp_size: int) -> Optional[Tuple[int, int, int, int]]:
    """
    Using local file header at 'header_offset', return:
        (data_start, data_end_incl, name_len, extra_len)
    """
    try:
        fp.seek(header_offset)
        raw = fp.read(4)
        if len(raw) != 4:
            return None
        sig = struct.unpack("<I", raw)[0]
        if sig != 0x04034B50:  # 'PK\x03\x04'
            return None
        # version(2), flags(2), method(2), time(2), date(2), crc(4), csize(4), usize(4), nlen(2), xlen(2)
        fixed = fp.read(26)
        if len(fixed) != 26:
            return None
        _ver, _flg, _meth, _t, _d, _crc, _cs, _us, nlen, xlen = struct.unpack("<HHHHHIIIHH", fixed)
        data_start = header_offset + 30 + int(nlen) + int(xlen)
        data_end   = data_start + int(comp_size) - 1 if comp_size > 0 else data_start - 1
        return data_start, data_end, int(nlen), int(xlen)
    except Exception:
        return None

def _scan_lfhs_best_effort(path: str, max_bytes: int = 64 * 1024) -> List[Tuple[int, int, int, str]]:
    """
    Best-effort LFH scanner from the start of the file (early metadata surface).
    Returns a list of tuples: (lfh_off, data_start, data_end_incl, name)
    Notes:
      - Uses *local* header fields only. If data descriptor is used (flag bit 3),
        the local csize is unreliable; such entries are skipped.
      - Bounds all reads to 'max_bytes' to avoid heavy I/O.
    """
    out: List[Tuple[int, int, int, str]] = []
    try:
        with open(path, "rb") as f:
            buf = f.read(max_bytes)
    except Exception:
        return out
    i = 0
    L = len(buf)
    PK = b"PK\x03\x04"
    while i + 30 <= L:
        j = buf.find(PK, i)
        if j < 0:
            break
        # Local header fixed part starts at j
        if j + 30 > L:
            break
        try:
            # version(2), flags(2), method(2), time(2), date(2),
            # crc(4), csize(4), usize(4), nlen(2), xlen(2)
            _ver, flags, method, _t, _d, _crc, csz, _usz, nlen, xlen = struct.unpack_from("<HHHHHIIIHH", buf, j + 4)
        except Exception:
            break
        # If data descriptor is used (flag bit 3), csize in LFH is unreliable.
        # We STILL keep this entry because we only need (lfh_off, name_len, extra_len)
        # to form the LFH metadata span [lfh_off .. data_start-1].
        has_dd = (flags & 0x0008) != 0
        name_start = j + 30
        name_end = name_start + nlen
        extra_end = name_end + xlen
        if extra_end > L:
            # Out of early buffer – stop, we are out of our max_bytes window
            break
        name = buf[name_start:name_end]
        try:
            name_s = name.decode("utf-8", "replace")
        except Exception:
            name_s = str(name)
        data_start = extra_end
        data_end = data_start + (csz if (not has_dd) else 0) - 1
        # Record even when DD is used; meta span uses (j .. data_start-1)
        if 0 <= data_start < L:
            out.append((j, data_start, data_end, _norm_zip_name(name_s)))
        i = j + 4
    return out
    
class _Entry:
    __slots__ = ("name", "method", "flag_bits", "data_start", "data_end")
    def __init__(self, name: str, method: int, flag_bits: int, ds: int, de: int):
        self.name = name
        self.method = method
        self.flag_bits = flag_bits
        self.data_start = ds
        self.data_end = de

def _list_entries_with_data_spans(container_path: str) -> Tuple[List[_Entry], bool]:
    """
    Enumerate members and compute their compressed data spans using LFH parsing.
    Returns (entries, had_parse_error) where had_parse_error is True if at least
    one LFH could not be parsed (common when top-of-file was encrypted/corrupted).
    """
    out: List[_Entry] = []
    file_len = 0
    had_parse_error = False
    with zipfile.ZipFile(container_path, "r") as zf, open(container_path, "rb") as fh:
        for info in zf.infolist():
            if info.is_dir():
                continue
            name = _norm_zip_name(info.filename)
            try:
                # Some Python builds expose ZipInfo.flag_bits; fall back gracefully
                flag_bits = int(getattr(info, "flag_bits", 0))
            except Exception:
                flag_bits = 0
            try:
                file_len = os.fstat(fh.fileno()).st_size
            except Exception:
                file_len = 0
            lho = int(getattr(info, "header_offset", 0) or 0)
            # Guard obviously bad offsets as parse errors
            if lho < 0 or (file_len and lho >= file_len):
                had_parse_error = True
                continue
            span = _read_local_header_data_span(fh, lho, info.compress_size)
            if not span:
                # If LFH is unreadable, mark a parse error but continue with other entries
                had_parse_error = True
                continue
            ds, de, _n, _x = span
            out.append(_Entry(name=name,
                              method=int(info.compress_type),
                              flag_bits=flag_bits,
                              ds=ds, de=de))
    return out, had_parse_error

def _overlaps(a0: int, a1: int, b0: int, b1: int) -> bool:
    return not (a1 < b0 or b1 < a0)

# ---- lightweight entropy helpers (mirrors zip handler) ----
def _chi2_uniform(data: bytes) -> float:
    if not data:
        return float("inf")
    freq = [0] * 256
    for b in data:
        freq[b] += 1
    n = len(data)
    if n == 0:
        return float("inf")
    exp = n / 256.0
    s = 0.0
    for c in freq:
        d = c - exp
        s += (d * d) / (exp if exp > 0 else 1.0)
    return s

def _ascii_ratio(buf: bytes) -> float:
    if not buf:
        return 0.0
    printable = sum(1 for b in buf if 9 <= b <= 13 or 32 <= b <= 126)
    return printable / len(buf)

def _token_ratio(buf: bytes) -> float:
    if not buf:
        return 0.0
    toks = sum(1 for b in buf if b in b"{}[]()<>=/,:;\"' \t\r\n")
    return toks / len(buf)

def _read_span(path: str, start: int, end_incl: int, cap: int) -> bytes:
    if end_incl < start:
        return b""
    length = min(max(0, end_incl - start + 1), max(0, cap))
    try:
        with open(path, "rb") as f:
            f.seek(start)
            return f.read(length)
    except Exception:
        return b""

def _compress_ratio(b: bytes) -> float:
    if not b:
        return 0.0
    try:
        c = zlib.compress(b, 1)
        if not c:
            return 0.0
        return len(c) / max(1, len(b))
    except Exception:
        return 0.0

def _gap_metrics_str(buf: bytes, chi2_thresh: float, ascii_min: float, token_min: float) -> str:
    """
    Produce a concise diagnostics string explaining why the ciphertext check
    did or did not trigger on a non-entry slice.
    """
    if not buf:
        return "len=0"
    chi2 = _chi2_uniform(buf)
    ar   = _ascii_ratio(buf)
    tr   = _token_ratio(buf)
    # distribution features
    freq = [0]*256
    for b in buf:
        freq[b] += 1
    n = len(buf)
    uniq = sum(1 for f in freq if f > 0)
    mx   = max(freq) if n > 0 else 0
    max_share = (mx / n) if n > 0 else 0.0
    rcomp = _compress_ratio(buf)
    base_cipher = (chi2 <= chi2_thresh and ar < ascii_min and tr < token_min)
    stable = (uniq >= 128 and max_share <= 0.06 and rcomp >= 0.95)
    # Compact, fixed-order; keep a few decimals for readability
    return (f"len={n}, chi2={chi2:.1f} (≤{chi2_thresh}), ascii={ar:.3f} (<{ascii_min}), "
            f"token={tr:.3f} (<{token_min}), uniq={uniq}, max_share={max_share:.3f}, "
            f"rcomp={rcomp:.3f}, base_cipher={base_cipher}, stable={stable}")

def _ciphertext_like(
    buf: bytes,
    chi2_thresh: float,
    ascii_min: float,
    token_min: float,
    mode: str = "strict",
) -> bool:
    """
    Return True if buf looks ciphertext-like.

    Modes:
      - "strict": legacy predicate used for metadata (LFH/DD). Looks for very low ASCII/token.
      - "uniform": tuned for full-file encryption on small windows; looks for near-uniform distributions.
    """
    if not buf:
        return False

    # Core features
    chi2 = _chi2_uniform(buf)
    ar   = _ascii_ratio(buf)
    tr   = _token_ratio(buf)

    # Distribution features
    freq = [0] * 256
    for b in buf:
        freq[b] += 1
    n = len(buf)
    uniq = sum(1 for f in freq if f > 0)
    max_share = (max(freq) / n) if n > 0 else 1.0

    # Compressibility (random/ciphertext should not compress well)
    rcomp = _compress_ratio(buf)  # >~1.0 for incompressible data with zlib(level=1)

    if mode == "uniform":
        # Near-uniform bands expected for random/ciphertext.
        # Use a relaxed branch for very small slices where variance is higher.
        if n < 256:
            chi_ok   = (120.0 <= chi2 <= 700.0)
            ascii_ok = (0.28   <= ar   <= 0.58)
            token_ok = (0.02   <= tr   <= 0.15)
            # Relax uniqueness/compressibility slightly for tiny windows
            stable   = (uniq >= 120 and max_share <= 0.08 and rcomp >= 0.99)
        else:
            chi_ok   = (150.0 <= chi2 <= 600.0)
            ascii_ok = (0.28   <= ar   <= 0.48)
            token_ok = (0.03   <= tr   <= 0.12)
            stable   = (uniq >= 180 and max_share <= 0.06 and rcomp >= 0.98)
        return chi_ok and ascii_ok and token_ok and stable

    # Default: "strict" — used for metadata spans. Very low ASCII & token density.
    base_cipher = (chi2 <= chi2_thresh and ar < ascii_min and tr < token_min)
    stable      = (uniq >= 128 and max_share <= 0.06 and rcomp >= 0.95)
    return base_cipher and stable

    
def _hash_zip_member_streaming(zf: zipfile.ZipFile, name: str) -> Optional[str]:
    import hashlib
    try:
        h = hashlib.sha256()
        with zf.open(name, "r") as fp:
            while True:
                b = fp.read(1024 * 1024)
                if not b:
                    break
                h.update(b)
        return h.hexdigest().lower()
    except Exception:
        return None

def _classify_path(p: str) -> str:
    pl = p.lower()
    if any(pl.startswith(pr) for pr in MEDIA_PREFIXES):
        return "media"
    if any(pl.startswith(pr) for pr in FONT_PREFIXES):
        return "font"
    if any(pl.startswith(pr) for pr in EMBED_PREFIXES):
        return "embed"
    if any(pl.startswith(pr) for pr in ACTIVEX_PREFIXES) or any(n in pl for n in VBA_NAMES):
        return "ole"   # ActiveX/VBA (CFB)
    if pl.startswith(THUMB_PREFIX):
        return "thumbnail"  # treat as media below
    return "other"

# --------- Text-part semantics (UTF-8 + XML fragment checks) ---------
_WORD_TEXT_XML = (
    "word/document.xml",
    "word/footnotes.xml",
    "word/endnotes.xml",
    "word/comments.xml",
    "word/numbering.xml",
    "word/styles.xml",
)

def _is_text_part(name: str) -> bool:
    """Return True for OOXML parts that should be well-formed XML with textual content."""
    n = _norm_zip_name(name).lower()
    if not n.endswith(".xml"):
        return False
    if n in _WORD_TEXT_XML:
        return True
    if n.startswith("word/header") and n.endswith(".xml"):
        return True
    if n.startswith("word/footer") and n.endswith(".xml"):
        return True
    if n.startswith("ppt/slides/slide") and n.endswith(".xml"):
        return True
    if n.startswith("ppt/notesSlides/notesSlide") and n.endswith(".xml"):
        return True
    if n == "xl/sharedstrings.xml":
        return True
    if n.startswith("xl/worksheets/sheet") and n.endswith(".xml"):
        return True
    if n.startswith("xl/comments") and n.endswith(".xml"):
        return True
    # generic: other .xml parts (rels/content types often tiny & structural; we still allow)
    return True

def _is_valid_utf8(b: bytes) -> bool:
    try:
        b.decode("utf-8")
        return True
    except Exception:
        return False

def _xml_token_sanity(buf: bytes) -> bool:
    """Quick XML-ish heuristics on a slice: angle density, printable share, token share, limited controls."""
    if not buf:
        return False
    L = len(buf)
    # density of '<' '>' between 0.5% and 20%
    angle = buf.count(b"<"[0]) + buf.count(b">"[0])
    angle_ratio = angle / max(L, 1)
    if not (0.005 <= angle_ratio <= 0.20):
        return False
    printable = _ascii_ratio(buf)
    tokens = _token_ratio(buf)
    # reasonably texty
    if printable < 0.70 or tokens < 0.02:
        return False
    # disallow too many C0/C1 controls (except \t\r\n)
    ctrl_bad = sum(1 for b in buf if (b < 32 and b not in (9,10,13)) or b == 127)
    if ctrl_bad / max(L, 1) > 0.001:
        return False
    return True

_RE_XML_TRIM = re.compile(br"[^<]*", re.DOTALL)

def _xml_fragment_ok(buf: bytes, required_tags: Optional[List[str]] = None) -> bool:
    """Try to parse a trimmed fragment; optionally require certain tags to appear."""
    if not buf:
        return False
    # trim before first '<' and after last '>' to help small slices
    try:
        start = buf.find(b"<")
        end = buf.rfind(b">")
        if start == -1 or end == -1 or end <= start:
            return False
        frag = buf[start:end+1]
        # wrap to ensure a single root
        # also remove any BOM if present
        frag = frag.lstrip(b"\xEF\xBB\xBF")
        wrapped = b"<r>" + frag + b"</r>"
        root = ET.fromstring(wrapped.decode("utf-8", errors="strict"))
    except Exception:
        return False
    if not required_tags:
        return True
    # simple presence check of required elements by tag suffix (namespace-agnostic)
    want = set(required_tags)
    found = set()
    for el in root.iter():
        tag = el.tag
        # strip namespace {ns}name or prefix ns:name
        if "}" in tag:
            tag = tag.rsplit("}", 1)[1]
        if ":" in tag:
            tag = tag.rsplit(":", 1)[1]
        if tag in want:
            found.add(tag)
            if found == want:
                return True
    return found == want

def _scan_xml_windows(buf: bytes, win: int = 64 * 1024) -> Tuple[int, int]:
    """
    Windowed XML sanity scan across the whole 'buf' without exceeding a fixed budget.
    Returns (#xml_like_windows, #non_xml_like_windows). Strides by 'win'.
    """
    L = len(buf)
    if L <= 0:
        return (0, 0)
    ok = bad = 0
    pos = 0
    while pos < L:
        end = min(L, pos + win)
        sl = buf[pos:end]
        if _is_valid_utf8(sl) and _xml_token_sanity(sl):
            ok += 1
        else:
            bad += 1
        pos = end
    return (ok, bad)

def _required_tags_for(name: str) -> Optional[List[str]]:
    n = _norm_zip_name(name).lower()
    if n.startswith("word/"):
        # expect paragraph/run/text
        return ["p", "r", "t"]
    if n.startswith("ppt/slides/"):
        # drawingML text runs
        return ["t"]
    if n == "xl/sharedstrings.xml":
        return ["sst", "si", "t"]
    if n.startswith("xl/worksheets/"):
        # sheets often have 'sheetData' but may be sparse; require at least worksheet
        return ["worksheet"]
    return None

class OOXMLHandler:
    """
    OOXML handler:
      - Map suspicious regions to member data ranges using LFHs.
      - If LFH parse fails (common when top-of-file is encrypted), treat as
        'metadata encrypted (parse error)' for overlapping early regions.
      - 'Media' entries are validated via a trusted manifest (if provided).
      - Volatile content (fonts/thumbnails/embeddings) is dropped for now.
      - XML/other parts are currently deferred (drop) until deeper logic lands.
    """
    exts = OOXML_EXTS

    @staticmethod
    def supports(ext: str, magic: Optional[bytes]) -> bool:
        e = (ext or "").lstrip(".").lower()
        if e in OOXML_EXTS:
            return True
        return False  # keep this conservative to avoid false positives

    def decide(self, ctx: FileContext, reg: SuspiciousFileRegion) -> FileAwareDecision:
        # DEBUG: small helper that prints only when enabled
        def _dbg(*a):
            if bool(ctx.params.get("ooxml_debug")):
                try:
                    print("[ooxml.debug]", *a, flush=True)
                except Exception:
                    pass
                
        if not ctx.fs_root:
            return FileAwareDecision(
                keep_file=False,
                reason="ooxml: no fs_root; defer",
                region_decisions=[
                    RegionDecision(start=s, end=e, keep=False, reason="ooxml: no fs_root; defer")
                    for (s, e) in (reg.byte_ranges or [])
                ] or None,
            )

        ap = os.path.join(ctx.fs_root, ctx.file_path.lstrip("/"))
        if _ext(ap) not in OOXML_EXTS and not _looks_like_ooxml(ap):
            return FileAwareDecision(keep_file=False, reason="ooxml: not OOXML; defer")

        # Allow caller to widen the "early metadata" surface (LFHs etc.)
        early_window = int(ctx.params.get("early_metadata_window", _EARLY_METADATA_WINDOW))
        
        entries: List[_Entry] = []
        had_parse_error = False
        try:
            entries, had_parse_error = _list_entries_with_data_spans(ap)
        except Exception:
            # If parsing the ZIP itself fails, treat early regions as metadata-encrypted
            entries = []
            had_parse_error = True

        # Best-effort augmentation: if we detected parse errors (or found no entries),
        # try to salvage early LFHs directly from the top of the file.
        # This helps when ZipInfo/header_offset is unreliable or the first LFH is partly damaged
        # but later ones are intact within the early window.
        salvaged = _scan_lfhs_best_effort(ap, max_bytes=early_window)
        salvaged = salvaged or []
        if had_parse_error or not entries:
            if salvaged:
                # Add any new spans we don't already have (match on (name, data_start))
                have = {(e.name, e.data_start) for e in entries}
                for (_lho, ds, de, nm) in salvaged:
                    key = (nm, ds)
                    if key in have:
                        continue
                    # We don't know flag_bits/method here; set conservative defaults.
                    entries.append(_Entry(
                        name=nm,
                        method=METHOD_DEFLATE,  # best guess; downstream logic re-checks content anyway
                        flag_bits=0,
                        ds=ds,
                        de=de
                    ))

        # Build LFH metadata spans (header+extra area) for early surface escalation.
        # We’ll include BOTH: salvaged early LFHs and full-file LFHs from ZipInfo.header_offset
        # Each span is (lfh_off, data_start-1, name)
        lfh_meta_spans: List[Tuple[int, int, str]] = []
        for (lho, ds, _de, nm) in (salvaged or []):
            if isinstance(lho, int) and isinstance(ds, int) and ds > lho:
                lfh_meta_spans.append((int(lho), int(ds - 1), _norm_zip_name(nm)))
        # Full-file LFH spans from entries (header_offset + name/extra → data_start)
        try:
            with open(ap, "rb") as _fp:
                for info in zipfile.ZipFile(ap, "r").infolist():
                    if getattr(info, "is_dir", lambda: False)():
                        continue
                    lho = int(getattr(info, "header_offset", 0) or 0)
                    span = _read_local_header_data_span(_fp, lho, info.compress_size)
                    if not span:
                        continue
                    ds, _de, nlen, xlen = span
                    if isinstance(ds, int) and ds > lho:
                        lfh_meta_spans.append((int(lho), int(ds - 1), _norm_zip_name(info.filename)))
        except Exception:
            pass

        # Compute earliest LFH offset so we can examine any "preamble" bytes before
        # the first LFH. persim --skip-metadata can encrypt a small prefix there,
        # which is not part of any LFH header/extra nor any member span.
        earliest_lfh_off: Optional[int] = None
        if salvaged:
            try:
                earliest_lfh_off = min(int(lho) for (lho, _ds, _de, _nm) in salvaged if isinstance(lho, int))
            except Exception:
                earliest_lfh_off = None

        # Build compact Data Descriptor spans for entries that use bit-3 (General Purpose flag).
        # We don't fully parse ZIP64/DD; we just examine a small, local trailer window.
        try:
            file_len = os.path.getsize(ap)
        except Exception:
            file_len = 0
        dd_spans: List[Tuple[int, int, str]] = []
        if entries:
            for en in entries:
                if (en.flag_bits & 0x8) == 0:
                    continue
                dd_start = int(en.data_end) + 1
                if file_len and dd_start >= file_len:
                    continue
                dd_end = min(dd_start + 32, (file_len - 1) if file_len else (dd_start + 31))
                if dd_end >= dd_start:
                    dd_spans.append((dd_start, dd_end, _norm_zip_name(en.name)))
                
        # For media trust, open the zip once for hashing (best-effort)
        try:
            zf = zipfile.ZipFile(ap, "r")
        except Exception:
            zf = None

        manifest_csv = ctx.params.get("trusted_manifest_csv")
        if isinstance(manifest_csv, str) and manifest_csv:
            _load_trusted_manifest_csv(manifest_csv)
        container_abs = _absnorm(ap)

        # Disable raw DEFLATE probing; rely on ZipFile at member start only.
        bad_deflate_entries: dict[str, str] = {}
        bad_nested_members = set()

        region_out: List[RegionDecision] = []
        any_keep = False
        kept_due_to_meta_parse = False
        # NEW: track if we escalated any region due to unreadable DEFLATE header/tables
        kept_due_to_nested_meta = False

        # Tunables (aligned with zip handler names)
        decompress_budget   = int(ctx.params.get("decompress_budget_bytes", 32 * 1024 * 1024))
        per_component_budget= int(ctx.params.get("per_component_budget", 32 * 1024 * 1024))
        scan_mode           = str(ctx.params.get("ooxml_scan_mode", "full_with_budget")).lower()  # "sample" | "full_with_budget"
        chi2_thresh         = float(ctx.params.get("chi2_uniform_thresh", 350.0))
        ascii_min           = float(ctx.params.get("ascii_min_ratio", 0.25))
        token_min           = float(ctx.params.get("token_min_ratio", 0.02))
        min_region_len      = int(ctx.params.get("min_region_len_bytes", 4096))
        # NEW: smaller floor for tiny overlaps (SAWA-sized slices)
        min_slice_len       = int(ctx.params.get("min_region_len_slice", 128))
        preamble_min_len    = int(ctx.params.get("min_region_len_preamble", 64))

        # DEBUG: dump high-level context and structures
        _dbg("file:", ap)
        _dbg("SAWA ranges:", list(reg.byte_ranges or []))
        if entries:
            _dbg("entries (name, data_start..data_end, flag_bits, method):")
            for en in entries:
                _dbg("  ", _norm_zip_name(en.name), f"[{en.data_start}..{en.data_end}]",
                     f"flags=0x{en.flag_bits:04x}", f"meth={en.method}")
        if lfh_meta_spans:
            _dbg("lfh_meta_spans (lho..data_start-1, name):")
            for (m0, m1, nm) in lfh_meta_spans:
                _dbg("  ", f"[{m0}..{m1}]", nm)
        if earliest_lfh_off is not None:
            _dbg("earliest_lfh_off:", earliest_lfh_off)
        if dd_spans:
            _dbg("dd_spans (start..end, name):")
            for (d0, d1, nm) in dd_spans:
                _dbg("  ", f"[{d0}..{d1}]", nm)
        
        # -------------------------
        # Phase 1: per-substructure verdicts (ZIP members + meta spans)
        # -------------------------
        # Each key is a string identifying the substructure; values are (suspicious_bool, reason_str)
        sub_verdicts: dict[str, Tuple[bool, str]] = {}

        # NOTE: we'll record member-level suspiciousness here and later promote
        # it for every SAWA range overlapping those members.
        # Helper: set verdict once (first suspicious reason wins; otherwise keep most specific)
        def _set_verdict(key: str, suspicious: bool, reason: str):
            prev = sub_verdicts.get(key)
            if prev is None:
                sub_verdicts[key] = (bool(suspicious), str(reason))
            else:
                # promote to suspicious if any path says suspicious; otherwise keep original reason
                if suspicious and not prev[0]:
                    sub_verdicts[key] = (True, str(reason))

        # 1) Member verdicts (evaluate from member start, not mid-stream).
        #    Only evaluate members that overlap at least one SAWA range.
        try:
            zf = zipfile.ZipFile(ap, "r")
        except Exception:
            zf = None
        manifest_csv = ctx.params.get("trusted_manifest_csv")
        if isinstance(manifest_csv, str) and manifest_csv:
            _load_trusted_manifest_csv(manifest_csv)
        container_abs = _absnorm(ap)

        # Build candidate set: members overlapping any SAWA window
        candidate_names: set[str] = set()
        for (s, e) in (reg.byte_ranges or []):
            for en in entries:
                if _overlaps(int(s), int(e), en.data_start, en.data_end):
                    candidate_names.add(_norm_zip_name(en.name))
        _dbg("candidate_names (overlap any SAWA):", sorted(candidate_names))
                    
        # ---- Phase 1: member verdicts (member-start only; candidates only)
        for en in entries:
            if _norm_zip_name(en.name) not in candidate_names:
                continue
            key = f"member:{_norm_zip_name(en.name)}"
            _dbg("Phase1→member-start check:", en.name, f"[{en.data_start}..{en.data_end}]")
            # Encrypted bit is immediate suspicion
            if (en.flag_bits & 0x1) != 0:
                _set_verdict(key, True, f"ooxml: member encrypted ({en.name})")
                continue

            # How to validate media against manifest
            media_trust_mode = str(ctx.params.get("media_trust_mode", "sha_only")).lower()

            # Media trust (treat media as an entire substructure)
            cls = _classify_path(en.name)
            if cls in ("media", "thumbnail"):
                if zf is None:
                    _set_verdict(key, True, f"ooxml: trusted manifest not loaded; cannot validate ({en.name})")
                    continue
                entry_norm = _norm_zip_name(en.name)
                # We always compute the SHA of the *decompressed* member bytes
                # so we can match by hash even when entry names differ.
                actual_sha = _hash_zip_member_streaming(zf, en.name)
                if not actual_sha:
                    _set_verdict(key, True, f"ooxml: media read error ({entry_norm})")
                    continue

                # If any trust map is loaded, we can try to validate
                if _TRUST_OOXML or _TRUST_OOXML_SHA or _TRUST_OOXML_SHA_GLOBAL:
                    sha_l = actual_sha.lower()

                    # --- SHA-first: global hash-only trust (ignores path/container) ---
                    if media_trust_mode in ("sha_only", "sha_then_path"):
                        hits = _TRUST_OOXML_SHA_GLOBAL.get(sha_l, [])
                        if hits:
                            # Accept by hash-only; mention first manifest entry for clarity
                            mcont, mentry = hits[0]
                            note = "" if (mcont == container_abs) else "; manifest container differs"
                            _set_verdict(
                                key, False,
                                f"ooxml: media trusted by sha ({entry_norm}); sha={sha_l[:12]} ↔ {mentry}{note}"
                            )
                            continue
                        if media_trust_mode == "sha_only":
                            _set_verdict(
                                key, True,
                                f"ooxml: media sha not in trusted manifest ({entry_norm}); sha={sha_l[:12]}"
                            )
                            continue

                    # --- Optional fallback: same-container by-sha, then path (diagnostics) ---
                    if media_trust_mode in ("sha_then_path", "path_only"):
                        sha_hit_entry = _TRUST_OOXML_SHA.get((container_abs, sha_l))
                        if sha_hit_entry:
                            if sha_hit_entry == entry_norm:
                                _set_verdict(key, False,
                                    f"ooxml: media matches trusted manifest by sha ({entry_norm})")
                            else:
                                _set_verdict(key, False,
                                    f"ooxml: media matches trusted manifest by sha "
                                    f"(entry differs: saw {entry_norm}, manifest {sha_hit_entry})")
                            continue

                        expected_sha_by_path = _TRUST_OOXML.get((container_abs, entry_norm))
                        if expected_sha_by_path is None:
                            _set_verdict(
                                key, True,
                                f"ooxml: media not in trusted manifest by path ({entry_norm}); sha={sha_l[:12]}"
                            )
                            continue
                        if sha_l != expected_sha_by_path:
                            _set_verdict(
                                key, True,
                                f"ooxml: media hash mismatch vs manifest ({entry_norm}); "
                                f"got={sha_l[:12]} expected={expected_sha_by_path[:12]}"
                            )
                            continue
                        _set_verdict(key, False, f"ooxml: media matches trusted manifest by path ({entry_norm})")
                        continue
                else:
                    _set_verdict(key, True, f"ooxml: trusted manifest not loaded; cannot validate ({entry_norm})")
                    continue

            # Non-media: try reading *decompressed* bytes via ZipFile first (member start).
            # This handles data-descriptor/ZIP64 nuances better than manual zlib.
            inflated = None
            usize = None
            scanned = 0
            truncated = False
            if zf is not None:
                try:
                    try:
                        zi = zf.getinfo(en.name)
                        usize = int(getattr(zi, "file_size", 0) or 0)
                    except Exception:
                        usize = None
                    with zf.open(en.name, "r") as mfp:
                        if scan_mode == "full_with_budget":
                            inflated = mfp.read(per_component_budget)
                        else:
                            inflated = mfp.read(min(per_component_budget, 1 << 20))
                    scanned = len(inflated or b"")
                    truncated = bool(usize and scanned < usize and scan_mode == "full_with_budget")
                except Exception as ex:
                    ds = int(en.data_start)
                    _set_verdict(
                        key, True,
                        f"ooxml: member decompression error via zipfile ({en.name}; start={ds})"
                    )
                    continue
            # If we got some bytes, classify:
            if inflated:
                head = inflated[:max(131072, min(len(inflated), 1 << 20))]
                if _is_text_part(en.name):
                    if scan_mode == "full_with_budget":
                        ok_wins, bad_wins = _scan_xml_windows(inflated, win=64 * 1024)
                        if bad_wins > 0 and ok_wins > 0:
                            _set_verdict(
                                key, True,
                                (f"ooxml: text/XML anomaly (mixed windows) ({en.name}); "
                                 f"scanned={scanned}B/{(usize if usize is not None else 'unknown')}"
                                 + ("; truncated" if truncated else ""))
                            )
                        elif bad_wins == 0 and ok_wins > 0:
                            _set_verdict(
                                key, False,
                                (f"ooxml: text/XML plaintext-like within budget ({en.name}); "
                                 f"scanned={scanned}B/{(usize if usize is not None else 'unknown')}"
                                 + ("; truncated" if truncated else ""))
                            )
                            _dbg("member verdict:", key, "→ benign (XML-like)")
                        else:
                            _set_verdict(
                                key, True,
                                (f"ooxml: text/XML anomaly ({en.name}); "
                                 f"scanned={scanned}B/{(usize if usize is not None else 'unknown')}"
                                 + ("; truncated" if truncated else ""))
                            )
                            _dbg("member verdict:", key, "→ suspicious (xml anomaly)")
                    else:
                        # Legacy sample behavior (head-only)
                        if _is_valid_utf8(head) and _xml_token_sanity(head):
                            _set_verdict(key, False, f"ooxml: text/XML plaintext-like ({en.name})")
                        else:
                            _set_verdict(key, True,  f"ooxml: text/XML anomaly ({en.name})")
                else:
                    # Non-text: quick ciphertext-like fallback on decompressed head
                    chi2 = _chi2_uniform(head); ar = _ascii_ratio(head); tr = _token_ratio(head)
                    if chi2 <= chi2_thresh and ar < ascii_min and tr < token_min and len(head) >= min_slice_len:
                        _set_verdict(key, True,  f"ooxml: ciphertext-like member ({en.name})")
                    else:
                        _set_verdict(key, False, f"ooxml: member benign ({en.name})")
                        _dbg("member verdict:", key, "→ benign (non-text)")
            else:
                # If we could not read at all (but no exception was raised earlier),
                # stay conservative and mark benign here; slice-level logic can still flag.
                _set_verdict(key, False, f"ooxml: member benign ({en.name})")
                _dbg("member verdict:", key, "→ benign (no inflated bytes)")

        if zf is not None:
            try: zf.close()
            except Exception: pass

        # 2) Meta substructures: LFH header/extra spans, preamble, and data descriptors
        for (m0, m1, nm) in lfh_meta_spans:
            key = f"meta:lfh:{_norm_zip_name(nm)}:{m0}-{m1}"
            raw = _read_span(ap, m0, m1, cap=min(decompress_budget, 1_048_576))
            head = raw[:max(65536, min(len(raw), 1 << 20))]
            if head:
                chi2 = _chi2_uniform(head); ar = _ascii_ratio(head); tr = _token_ratio(head)
                if chi2 <= chi2_thresh and ar < ascii_min and tr < token_min and len(head) >= min_slice_len:
                    _set_verdict(key, True, f"ooxml: suspicious LFH/extra metadata ({nm})")
                else:
                    _set_verdict(key, False, f"ooxml: LFH metadata benign ({nm})")
        if earliest_lfh_off is not None and earliest_lfh_off > 0:
            pre0, pre1 = 0, int(earliest_lfh_off) - 1
            key = f"meta:preamble:{pre0}-{pre1}"
            raw = _read_span(ap, pre0, pre1, cap=min(decompress_budget, 1_048_576))
            head = raw[:max(65536, min(len(raw), 1 << 20))]
            if head:
                chi2 = _chi2_uniform(head); ar = _ascii_ratio(head); tr = _token_ratio(head)
                if len(head) >= preamble_min_len and chi2 <= chi2_thresh and ar < ascii_min and tr < token_min:
                    _set_verdict(key, True, "ooxml: suspicious pre-LFH preamble")
                else:
                    _set_verdict(key, False, "ooxml: preamble benign")
        for (d0, d1, nm) in dd_spans:
            key = f"meta:dd:{_norm_zip_name(nm)}:{d0}-{d1}"
            raw = _read_span(ap, d0, d1, cap=min(decompress_budget, 1_048_576))
            head = raw[:max(65536, min(len(raw), 1 << 20))]
            if head:
                chi2 = _chi2_uniform(head); ar = _ascii_ratio(head); tr = _token_ratio(head)
                if chi2 <= chi2_thresh and ar < ascii_min and tr < token_min and len(head) >= min_slice_len:
                    _set_verdict(key, True, f"ooxml: suspicious data descriptor ({nm})")
                else:
                    _set_verdict(key, False, f"ooxml: data descriptor benign ({nm})")

        # -------------------------
        # Phase 2: map SAWA ranges → substructures and promote decisions
        # -------------------------
        for (s, e) in (reg.byte_ranges or []):
            _dbg(f"Phase2→SAWA window [{int(s)}..{int(e)}]")
            keep = False
            reason = "ooxml: benign"

            overlapped = [en for en in entries if _overlaps(s, e, en.data_start, en.data_end)]
            if overlapped:
                _dbg("  overlaps members:",
                     [f"{_norm_zip_name(en.name)}[{en.data_start}..{en.data_end}]" for en in overlapped])
            else:
                _dbg("  no member overlap (will try meta/preamble/DD/gap)")
            
            # --- Promote/Combine member-level verdicts for all overlapping members.
            if overlapped:
                suspicious_reasons: List[str] = []
                budget_notes: List[str] = []
                for en in overlapped:
                    v = sub_verdicts.get(f"member:{_norm_zip_name(en.name)}")
                    if not v:
                        continue
                    is_susp, r = v
                    if is_susp:
                        suspicious_reasons.append(f"{_norm_zip_name(en.name)}: {r}")
                    else:
                        lr = r.lower()
                        if ("within budget" in lr) or ("truncated" in lr):
                            budget_notes.append(f"{_norm_zip_name(en.name)}: {r}")
                _dbg("  member-derived reasons:",
                     {"suspicious": suspicious_reasons, "budget_notes": budget_notes})
                if suspicious_reasons:
                    # Combine (do not overwrite); truncate to keep concise.
                    uniq = []
                    seen = set()
                    for r in suspicious_reasons:
                        if r not in seen:
                            uniq.append(r); seen.add(r)
                    shown = "; ".join(uniq[:5]) + (" …" if len(uniq) > 5 else "")
                    reason = f"ooxml: suspicious overlapping members → {shown}"
                    region_out.append(RegionDecision(start=int(s), end=int(e), keep=True, reason=reason))
                    any_keep = True
                    continue
                # No suspicious members. If we scanned only within a budget, say so explicitly.
                if budget_notes:
                    shown = "; ".join(budget_notes[:5]) + (" …" if len(budget_notes) > 5 else "")
                    reason = f"ooxml: overlapping members benign (limited by budget) → {shown}"
                    region_out.append(RegionDecision(start=int(s), end=int(e), keep=False, reason=reason))
                    _dbg("  RESULT:", reason)
                    continue

            # If LFH parsing had errors and this region is in the early metadata surface,
            # we escalate to "metadata encrypted (parse error)" to avoid dropping true hits.
            if had_parse_error and (s < early_window):
                keep = True
                reason = "ooxml: metadata encrypted (parse error)"
                any_keep |= keep
                kept_due_to_meta_parse = True
                region_out.append(RegionDecision(start=int(s), end=int(e), keep=keep, reason=reason))
                _dbg("  RESULT:", reason)
                continue

            if not overlapped:
                # No member compressed-data overlap. Before deferring, check:
                # (1) any LFH header/extra span (full-file), (2) pre-LFH preamble,
                # (3) data-descriptor trailers, then (4) generic gap ciphertext.
                suspicious_meta = False
                meta_reasons: List[str] = []
                if lfh_meta_spans:
                    for (m0, m1, nm) in lfh_meta_spans:
                        if not _overlaps(s, e, m0, m1):
                            continue
                        # Analyze the whole LFH header/extra span (more signal, still bounded)
                        rs = m0
                        re = m1
                        raw = _read_span(ap, rs, re, cap=min(decompress_budget, 1_048_576))
                        if not raw:
                            continue
                        head = raw[:max(65536, min(len(raw), 1 << 20))]
                        min_meta_len = int(ctx.params.get("min_region_len_lfh_meta", 128))
                        if len(head) >= min_meta_len and _ciphertext_like(
                                head, chi2_thresh=chi2_thresh, ascii_min=ascii_min, token_min=token_min):
                            suspicious_meta = True
                            meta_reasons.append(f"ooxml: suspicious LFH/extra metadata ({nm})")
                            break
                if bool(ctx.params.get("ooxml_debug")):
                    _dbg("  meta-LFH check:", "HIT" if suspicious_meta else "miss", meta_reasons)

                # 2) Also check a "preamble" slice before the first LFH. Some encryptors
                # touch a small prefix that is neither LFH nor member data. If this
                # region overlaps [0 .. earliest_lfh_off-1], run the ciphertext test.
                if (not suspicious_meta) and (earliest_lfh_off is not None):
                    pre0 = 0
                    pre1 = max(0, int(earliest_lfh_off) - 1)
                    if _overlaps(s, e, pre0, pre1):
                        rs = max(int(s), pre0)
                        re = min(int(e), pre1)
                        raw = _read_span(ap, rs, re, cap=min(decompress_budget, 1_048_576))
                        if raw:
                            head = raw[:max(65536, min(len(raw), 1 << 20))]
                            if (len(head) >= preamble_min_len and _ciphertext_like(
                                    head, chi2_thresh=chi2_thresh, ascii_min=ascii_min, token_min=token_min)):
                                suspicious_meta = True
                                meta_reasons.append("ooxml: suspicious pre-LFH preamble")
                            # else: benign preamble (e.g., nulls/zeros or normal)
                if bool(ctx.params.get("ooxml_debug")):
                    _dbg("  preamble check:", "HIT" if suspicious_meta and "preamble" in " ".join(meta_reasons) else "miss")


                # 3) Also check data-descriptor trailers anywhere in the file
                if not suspicious_meta and dd_spans:
                    for (m0, m1, nm) in dd_spans:
                        if not _overlaps(s, e, m0, m1):
                            continue
                        raw = _read_span(ap, m0, m1, cap=min(decompress_budget, 1_048_576))
                        if not raw:
                            continue
                        head = raw[:max(65536, min(len(raw), 1 << 20))]
                        if len(head) >= min_slice_len and _ciphertext_like(
                                head, chi2_thresh=chi2_thresh, ascii_min=ascii_min, token_min=token_min):
                            suspicious_meta = True
                            meta_reasons.append(f"ooxml: suspicious data descriptor ({nm})")
                            break
                if bool(ctx.params.get("ooxml_debug")):
                    _dbg("  data-descriptor check:", "HIT" if suspicious_meta and "descriptor" in " ".join(meta_reasons) else "miss")

                # 4) If none of the above meta hits, perform a generic gap-ciphertext check
                #    on this non-entry slice to catch uniform-like encrypted padding/alignment.
                if not suspicious_meta:
                    raw_gap = _read_span(ap, int(s), int(e), cap=min(decompress_budget, 1_048_576))
                    head = raw_gap[:max(65536, min(len(raw_gap), 1 << 20))] if raw_gap else b""
                    # Use the stronger ciphertext predicate for gaps (robust on small windows)
                    if head and len(head) >= min_slice_len and _ciphertext_like(
                            head,
                            chi2_thresh=chi2_thresh,
                            ascii_min=ascii_min,
                            token_min=token_min,
                            mode="uniform"):
                        suspicious_meta = True
                        # Append diagnostic metrics so we can see *why* it triggered
                        meta_reasons.append("ooxml: non-entry ciphertext-like gap"
                                            f" ({_gap_metrics_str(head, chi2_thresh, ascii_min, token_min)})")

                if suspicious_meta:
                    keep = True
                    reason = "; ".join(meta_reasons) if meta_reasons else "ooxml: suspicious non-entry data"
                else:
                    # Explicitly label low-entropy/small gaps as benign, with diagnostics
                    if not head or len(head) < min_slice_len:
                        keep = False
                        reason = "ooxml: non-entry small/empty gap" + (f" (len={len(head) if head else 0})")
                    else:
                        keep = False
                        reason = "ooxml: non-entry plaintext-like gap" \
                                 f" ({_gap_metrics_str(head, chi2_thresh, ascii_min, token_min)})"
                any_keep |= keep
                region_out.append(RegionDecision(start=int(s), end=int(e), keep=keep, reason=reason))
                _dbg("  RESULT:", reason)
                continue

            # Overlapped, but no suspicious member verdicts: mark benign with an explicit reason.
            reason = "ooxml: overlapping members benign"
            region_out.append(RegionDecision(start=int(s), end=int(e), keep=False, reason=reason))
            continue

        # (zipfile already closed above in Phase 1)
        # If nothing overlapped AND we had a parse error, be conservative for early regions:
        # (Already handled per-region above, but this keeps file_reason aligned.)
        # If any kept region was due to early parse failure, surface that explicitly.
        if any_keep:
            file_reason = "ooxml: suspicious regions kept (member-start semantics)"
        else:
            file_reason = ("ooxml: all regions dropped" if not had_parse_error
                           else "ooxml: early metadata damaged but no region qualified")

        _dbg("FILE RESULT:", file_reason, "| any_keep:", any_keep)
        return FileAwareDecision(keep_file=any_keep, reason=file_reason, region_decisions=region_out or None)

