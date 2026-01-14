# detector/fileaware/handlers/pdf.py
# -----------------------------------------------------------------------------
# Stream-aware PDF handler with consistent image trust hashing.
# + prelude semantics for outside-stream regions (header/xref/trailer/obj/startxref)
#
# Key features:
#  - Robust mmap-based stream boundary scan (maps byte ranges -> streams)
#  - Lightweight dictionary parsing (Filters/DecodeParms and component typing)
#  - Supported filter decoding: Flate, ASCII85, ASCIIHex, RunLength (+ PNG predictor)
#  - Component-aware decisions (images/fonts/ICC/content/xref/objstm/embedded/XMP)
#  - Image trust: **decoded-pixel hash by default** (fallback to raw if undecodable)
#  - Strict but safe outside-stream heuristics + "metadata prelude" safety belt
#
# Config (ctx.params):
#   decompress_budget_bytes: int (default 32MB)
#   chi2_uniform_thresh: float (default 300.0)          # decoded χ² threshold
#   chi2_uniform_thresh_raw: float (default 240.0)      # raw χ² fallback
#   chi2_uniform_thresh_outside: float (default 220.0)  # outside-stream χ²
#   (χ² thresholds are no longer used for decisions; kept only for diagnostics)
#   metadata_prelude_slack_bytes: int (default 32768)
#   prefer_decoded_image_hash: bool (default True)      # <— default switched to decoded
# -----------------------------------------------------------------------------

import os
import re
import mmap
import zlib
import binascii
import base64
import hashlib
from typing import Optional, List, Tuple, Dict, Any

from ..types import (
    FileContext,
    SuspiciousFileRegion,
    FileAwareDecision,
    RegionDecision,
)

# ----------------------------- Constants -------------------------------------

EXTS = {"pdf"}

PDF_HEADER_RE = re.compile(rb"%PDF-\d\.\d")
PDF_BIN_MARK_RE = re.compile(rb"^%([^\r\n]{4,})", re.M)
OBJ_START_RE  = re.compile(rb"\b(\d+)\s+(\d+)\s+obj\b")
OBJ_END_RE    = re.compile(rb"\bendobj\b")
XREF_RE       = re.compile(rb"\bxref\b")
TRAILER_RE    = re.compile(rb"\btrailer\b")
STARTXREF_RE  = re.compile(rb"\bstartxref\b")
EOF_RE        = re.compile(rb"%%EOF\s*$", re.DOTALL)
DICT_BACK_RE  = re.compile(rb"<<.*?>>", re.DOTALL)
FILTER_RE     = re.compile(rb"/Filter\s+(?P<val>(\[.*?\]|/\S+))", re.DOTALL)
DECODEPARMS_RE= re.compile(rb"/DecodeParms\s+(?P<val>(\[.*?\]|<<.*?>>))", re.DOTALL)
NAME_RE       = re.compile(rb"/([A-Za-z0-9\-\+\.]+)")

SUPPORTED_FILTERS = {
    b"FlateDecode",
    b"ASCII85Decode",
    b"ASCIIHexDecode",
    b"RunLengthDecode",
}

def _filters_supported(fs: List[bytes]) -> bool:
    """True iff every filter is one we support (empty => True)."""
    if not fs:
        return True
    return all(_norm_filter_name(f) in SUPPORTED_FILTERS for f in fs)

def _norm_filter_name(f: bytes) -> bytes:
    """
    Normalize a parsed filter token to a clean name like b'FlateDecode'.
    Handles stray dict delimiters or whitespace that leaked into the token.
    """
    if not f:
        return f
    f = f.strip()
    # If caller gave a bare name, accept it; otherwise try NAME_RE on a prefixed '/' form.
    m = re.match(rb"^([A-Za-z0-9\-\+\.]+)$", f)
    if m:
        return m.group(1)
    m = NAME_RE.match(b"/" + f)
    return m.group(1) if m else f

def _declares_flate(st) -> bool:
    """
    Robustly detect a Flate declaration, tolerating odd dict formatting.
    """
    try:
        if st.filters and (b"FlateDecode" in st.filters):
            return True
        return (st.dict_bytes and (b"/FlateDecode" in st.dict_bytes))
    except Exception as e:
        return False

_INFO_TEXT_KEYS = {b"/Title", b"/Author", b"/Creator", b"/Subject", b"/Keywords", b"/Producer", b"/ModDate", b"/CreationDate"}

# ----------------------------- Utils -----------------------------------------

def _looks_like_pdf(magic: bytes) -> bool:
    return bool(magic and magic.startswith(b"%PDF-"))

def _sha256(b: bytes) -> str:
    h = hashlib.sha256()
    h.update(b)
    return h.hexdigest().lower()

def _chi2_uniform(data: bytes) -> float:
    if not data:
        return float("inf")
    freq = [0] * 256
    for b in data:
        freq[b] += 1
    n = len(data)
    exp = n / 256.0
    s = 0.0
    for c in freq:
        d = c - exp
        s += (d * d) / (exp if exp > 0 else 1.0)
    return s
 
def _looks_encrypted_fused(sample: bytes,
                           min_len: int = 48,
                           ascii_max: float = 0.18,
                           chi2_max: float = 240.0,
                           entropy_min: float = 7.5,
                           cr_min: float = 0.97) -> bool:
    """
    Same 'fused' rule used for content literal/hex strings:
      - long enough
      - very low ASCII ratio
      - near-uniform byte distribution (low χ²)
      - AND (high Shannon entropy OR poor zlib compression ratio ~1.0)
    This is deliberately stricter than generic _looks_random_bytes and
    should be applied when we want parity with literal-string handling.
    """
    if not sample or len(sample) < min_len:
        return False
    ascii_r = _ascii_ratio(sample)
    chi2    = _chi2_uniform(sample)
    H       = _shannon_entropy(sample[:4096])
    cr      = _zlib_compress_ratio(sample[:2048])
    return (ascii_r < ascii_max) and (chi2 <= chi2_max) and ((H >= entropy_min) or (cr >= cr_min))

def _looks_random_bytes(buf: bytes,
                        min_len: int = 1024,
                        ascii_max: float = 0.18,
                        chi2_max: float = 220.0,
                        entropy_min: float = 7.5,
                        cr_min: float = 0.97) -> bool:
    """
    Heuristic for ciphertext-like blobs:
    - long enough
    - very low ASCII ratio
    - near-uniform byte distribution (low χ²)
    - AND (high Shannon entropy OR poor zlib compression ratio ~1.0)
    """
    if not buf or len(buf) < min_len:
        return False
    ascii_r = _ascii_ratio(buf)
    chi2 = _chi2_uniform(buf)
    H = _shannon_entropy(buf[:4096])
    cr = _zlib_compress_ratio(buf[:4096])
    return (ascii_r < ascii_max) and (chi2 <= chi2_max) and ((H >= entropy_min) or (cr >= cr_min))

def _ascii_ratio(buf: bytes) -> float:
    if not buf:
        return 1.0
    printable = sum(1 for b in buf if b in (9, 10, 13) or 32 <= b <= 126)
    return printable / len(buf)

def _valid_utf8_first_error(b: bytes) -> Tuple[bool, Optional[int], Optional[str]]:
    """
    Return (ok, err_pos, err_msg). If ok=False and err_pos is not None, that is the
    .start index from UnicodeDecodeError where decoding failed.
    """
    if not b:
        return True, None, None
    try:
        b.decode("utf-8", "strict")
        return True, None, None
    except UnicodeDecodeError as e:
        return False, getattr(e, "start", None), f"{e.__class__.__name__}: {e}"
    except Exception as e:
        return False, None, f"{e.__class__.__name__}: {e}"


# -------- Absolute "zone at offset" probe (±R window) ------------------------
def _zone_at_absolute_offset(path: str, off: int, radius: int = 262144) -> Dict[str, Any]:
    """
    Probe a large window around `off`, find the enclosing `obj … endobj`, and
    determine the token *zone* covering `off`:
      - 'literal_string', 'hex_string', 'comment', or 'syntax'
    If `off` lies inside a string, return the string body (without () or <>).
    If the close delimiter is outside our window, return a partial body up to `off`.
    """
    try:
        import os, re
        fsize = os.path.getsize(path)
        a = max(0, off - radius)
        b = min(fsize, off + radius)
        with open(path, "rb") as f:
            f.seek(a)
            buf = f.read(b - a)
        rel = off - a

        # Best-effort: last 'obj' before rel, then the next 'endobj' after rel
        left_objs = list(re.finditer(rb"\b\d+\s+\d+\s+obj\b", buf[:rel]))
        if not left_objs:
            return {"zone": "syntax", "obj_range": [-1, -1], "body": b""}
        lo_tok = left_objs[-1]
        lo = lo_tok.end()

        m_end = re.search(rb"\bendobj\b", buf[rel:])
        if not m_end:
            # We still know we're in some object; return range with unknown end
            obj_lo_abs = a + lo_tok.start()
            return {"zone": "syntax", "obj_range": [obj_lo_abs, -1], "body": b""}

        hi = rel + m_end.start()
        obj_lo_abs = a + lo_tok.start()
        obj_hi_abs = a + (rel + m_end.start() + len(b"endobj"))

        s = buf[lo:hi]                # bytes between 'obj' and 'endobj'
        L = len(s)
        tgt = rel - lo                # position of `off` within `s`
        if tgt < 0 or tgt >= L:
            return {"zone": "syntax", "obj_range": [obj_lo_abs, obj_hi_abs], "body": b""}

        i = 0
        in_comment = False
        in_lit = False; lit_depth = 0; lit_escape = False; lit_s = -1
        in_hex = False;  hex_s = -1

        # Track zone at the moment we reach/past `tgt`,
        # and where its body starts (for strings).
        zone_at_tgt = None  # "literal_string" | "hex_string" | "comment" | "syntax"
        zstart = None

        while i < L:
            c = s[i]
            nxt = s[i+1] if i+1 < L else None

            # Linger in current zones and try to close them,
            # but also mark the zone at/after tgt exactly once.
            if in_comment:
                if zone_at_tgt is None and i >= tgt:
                    zone_at_tgt = "comment"
                if c in (0x0A, 0x0D):
                    in_comment = False
                i += 1
                continue

            if in_lit:
                if lit_escape:
                    lit_escape = False; i += 1; continue
                if c == 0x5C:  # backslash
                    lit_escape = True; i += 1; continue
                if c == 0x28:  # '(' nesting
                    lit_depth += 1; i += 1; continue
                if c == 0x29:  # ')'
                    lit_depth = max(0, lit_depth - 1); i += 1
                    if lit_depth == 0:
                        # Closed literal; if tgt was inside, we now have full body
                        if lit_s != -1 and lit_s <= tgt <= i - 2:
                            body = s[lit_s:i-1]
                            return {"zone": "literal_string", "obj_range": [obj_lo_abs, obj_hi_abs], "body": body}
                        in_lit = False
                    else:
                        if zone_at_tgt is None and i-1 >= tgt:
                            zone_at_tgt = "literal_string"; zstart = lit_s
                    continue
                if zone_at_tgt is None and i >= tgt:
                    zone_at_tgt = "literal_string"; zstart = lit_s
                i += 1; continue

            if in_hex:
                if c == 0x3E:  # '>'
                    # Closed hex; if tgt was inside, we now have full body
                    if hex_s != -1 and hex_s <= tgt <= i - 1:
                        body = s[hex_s:i]
                        return {"zone": "hex_string", "obj_range": [obj_lo_abs, obj_hi_abs], "body": body}
                    in_hex = False
                    i += 1
                    continue
                if zone_at_tgt is None and i >= tgt:
                    zone_at_tgt = "hex_string"; zstart = hex_s
                i += 1; continue

            # Outside protected zones: recognize entries
            if c == 0x25:  # '%'
                in_comment = True
                if zone_at_tgt is None and i >= tgt:
                    zone_at_tgt = "comment"
                i += 1; continue

            if c == 0x28:  # '('
                in_lit = True; lit_depth = 1; lit_escape = False; lit_s = i + 1
                if zone_at_tgt is None and i >= tgt:
                    zone_at_tgt = "literal_string"; zstart = lit_s
                i += 1; continue

            if c == 0x3C:  # '<' (hex) or '<<' (dict)
                if nxt == 0x3C:
                    if zone_at_tgt is None and i >= tgt:
                        zone_at_tgt = "syntax"
                    i += 2; continue
                in_hex = True; hex_s = i + 1
                if zone_at_tgt is None and i >= tgt:
                    zone_at_tgt = "hex_string"; zstart = hex_s
                i += 1; continue

            if zone_at_tgt is None and i >= tgt:
                zone_at_tgt = "syntax"
            i += 1

        # We left the loop without closing the zone that covered tgt.
        # Report the zone-at-tgt with a partial body if applicable.
        if zone_at_tgt == "literal_string" and zstart is not None and zstart <= tgt < L:
            body = s[zstart:min(L, tgt + 1)]
            return {"zone": "literal_string", "obj_range": [obj_lo_abs, obj_hi_abs], "body": body}
        if zone_at_tgt == "hex_string" and zstart is not None and zstart <= tgt <= L:
            body = s[zstart:min(L, tgt)]  # hex digits up to tgt-1
            return {"zone": "hex_string", "obj_range": [obj_lo_abs, obj_hi_abs], "body": body}
        if zone_at_tgt == "comment":
            return {"zone": "comment", "obj_range": [obj_lo_abs, obj_hi_abs], "body": b""}
        return {"zone": "syntax", "obj_range": [obj_lo_abs, obj_hi_abs], "body": b""}
    except Exception:
        return {"zone": "syntax", "obj_range": [-1, -1], "body": b""}

def _looks_encrypted_literal_or_hex(body: bytes, is_hex: bool = False) -> bool:
    """
    Apply the same fused rule used for content operands to the given string body.
    For hex strings, we first decode to raw bytes when possible.
    """
    try:
        sample = body
        if is_hex:
            raw = _decode_pdf_hex_string(re.sub(rb"\s+", b"", body or b""))
            sample = raw if raw is not None else b""
        return _looks_encrypted_fused(sample, min_len=48, ascii_max=0.18, chi2_max=240.0, entropy_min=7.5, cr_min=0.97)
    except Exception:
        return False
    
def _is_ascii_byte(x: int) -> bool:
    return (x in (0x09, 0x0A, 0x0D)) or (0x20 <= x <= 0x7E)

def _is_delim(x: Optional[int]) -> bool:
    # Token boundary helper (PDF delimiters + whitespace)
    if x is None:
        return True
    return x in (0x00, 0x09, 0x0A, 0x0D, 0x20, 0x28, 0x29, 0x3C, 0x3E, 0x5B, 0x5D, 0x7B, 0x7D, 0x2F)

def _match_kw(buf: bytes, i: int, kw: bytes) -> bool:
    L = len(buf); k = len(kw)
    if i < 0 or i + k > L:
        return False
    prev_ch = buf[i-1] if i > 0 else None
    next_ch = buf[i+k] if (i+k) < L else None
    return buf[i:i+k] == kw and _is_delim(prev_ch) and _is_delim(next_ch)

def _summarize_content_stream(buf: bytes) -> Dict[str, Any]:
    """
    Tokenize a content stream and return a summary with:
      - counts/bytes for comments, literal strings, hex strings
      - inline image dictionary byte count and payload spans (BI..ID..EI)
      - first ASCII-syntax violation (outside protected zones)
      - first UTF-8 error (whole-buffer decode attempt)
      - simple stats: ascii_ratio, chi2, textop_hits
    This is DIAGNOSTIC ONLY; it does not change classification.
    """
    out: Dict[str, Any] = {
        "len": len(buf), "ascii_ratio": _ascii_ratio(buf),
        "chi2": _chi2_uniform(buf), "textop_hits": _pdf_textop_hits(buf),
        "comments_bytes": 0, "comments_count": 0,
        "literal_bytes": 0, "literal_count": 0,
        "hex_bytes": 0, "hex_count": 0,
        "ii_dict_bytes": 0, "ii_payload_bytes": 0, "ii_count": 0,
        "ii_payload_spans": [],  # list of (start,end) in stream-relative offsets
        "lit_spans": [],         # NEW: list of (start,end) for literal-string bodies
        "hex_spans": [],         # NEW: list of (start,end) for hex-string bodies
        "first_ascii_syntax_violation": None,  # offset
        "utf8_ok": True, "utf8_err_pos": None, "utf8_err": None,
    }
    if not buf:
        return out

    ok, pos, msg = _valid_utf8_first_error(buf)
    out["utf8_ok"] = bool(ok)
    out["utf8_err_pos"] = pos
    out["utf8_err"] = msg

    i = 0; L = len(buf)
    in_comment = False
    in_lit = False; lit_depth = 0; lit_escape = False; lit_s = -1
    in_hex = False; hex_s = -1
    in_iid = False  # inline image dictionary
    in_iip = False  # inline image payload
    payload_s = None  # <— ensure defined for in_iip span accounting
    # When we see BI → enter dict (ASCII-constrained), then ID → enter payload (binary), then EI → back to syntax.
    while i < L:
        c = buf[i]
        nxt = buf[i+1] if i+1 < L else None

        if in_iip:
            # search for EI at token boundary
            if _match_kw(buf, i, b"EI"):
                # close payload at i-1
                # previous payload start is after ID + optional single whitespace
                # We recorded payload start as `payload_s` in dict scope.
                payload_e = i - 1
                if payload_s is not None and payload_e >= payload_s:
                    out["ii_payload_spans"].append((payload_s, payload_e))
                    out["ii_payload_bytes"] += (payload_e - payload_s + 1)
                # reset for safety before leaving payload zone
                payload_s = None
                in_iip = False
                i += 2
                continue
            i += 1
            continue

        if in_comment:
            if c in (0x0A, 0x0D):
                in_comment = False
            i += 1
            continue

        if in_lit:
            if lit_escape:
                lit_escape = False; i += 1; continue
            if c == 0x5C:
                lit_escape = True; i += 1; continue
            if c == 0x28:
                lit_depth += 1; i += 1; continue
            if c == 0x29:
                lit_depth = max(0, lit_depth-1)
                i += 1
                if lit_depth == 0:
                    in_lit = False
                    # lit_s points to first byte AFTER '(' ; close position is i-2
                    a, b = lit_s, i-2
                    if a is not None and a >= 0 and b >= a:
                        out["literal_count"] += 1
                        out["literal_bytes"] += (b - a + 1)
                        out["lit_spans"].append((a, b))
                continue
            i += 1
            continue

        if in_hex:
            if c == 0x3E:  # '>'
                in_hex = False
                a, b = hex_s, i-1
                if a is not None and a >= 0 and b >= a:
                    out["hex_count"] += 1
                    out["hex_bytes"] += (b - a + 1)
                    out["hex_spans"].append((a, b))
                i += 1
                continue
            i += 1
            continue

        if in_iid:
            # inside inline image dict; look for ID at token boundary
            if _match_kw(buf, i, b"ID"):
                in_iid = False
                in_iip = True
                # payload starts after 'ID' and optional one whitespace
                payload_s = i + 2
                if payload_s < L and buf[payload_s] in (0x20,0x0D,0x0A,0x09,0x0C,0x00):
                    payload_s += 1
                i += 2
                continue
            # dictionary bytes are ASCII-constrained
            if not _is_ascii_byte(c) and out["first_ascii_syntax_violation"] is None:
                out["first_ascii_syntax_violation"] = i
            out["ii_dict_bytes"] += 1
            i += 1
            continue

        # ----- outside protected zones -----
        if c == 0x25:  # '%'
            in_comment = True
            out["comments_count"] += 1
            # count the '%' itself as part of comment bytes
            out["comments_bytes"] += 1
            i += 1
            continue
        if c == 0x28:  # '('
            in_lit = True; lit_depth = 1; lit_escape = False; lit_s = i+1
            i += 1; continue
        if c == 0x3C:  # '<'
            if nxt == 0x3C:
                # dict start; leave ASCII enforcement to generic syntax (below)
               i += 2; continue
            else:
                in_hex = True; hex_s = i+1; i += 1; continue
        if _match_kw(buf, i, b"BI"):
            in_iid = True
            out["ii_count"] += 1
            i += 2
            continue
        # ASCII-constrained syntax zone
        if not _is_ascii_byte(c) and out["first_ascii_syntax_violation"] is None:
            out["first_ascii_syntax_violation"] = i
        i += 1
    return out

def _looks_utf8_text(buf: bytes, min_printable: float = 0.60) -> bool:
    """
    Return True iff `buf` decodes as UTF-8 (strict) and looks like text:
      - decoding succeeds
      - ratio of printable code points is above `min_printable`
    Uses a fast path on bytes that are already ASCII (valid UTF-8 subset).
    """
    if not buf:
        return False
    try:
        # Fast accept if ASCII-heavy and decodes
        s = buf.decode("utf-8", "strict")
        printable = sum(1 for ch in s if ch == "\t" or ch == "\n" or ch == "\r" or (0x20 <= ord(ch) <= 0x7E))
        return (printable / max(1, len(s))) >= min_printable
    except Exception:
        return False

 
def _inflate_any(b: bytes,
                 max_tries: int = 8,
                 want_ops: bool = True) -> Tuple[bool, Optional[bytes]]:
    """
    Probe for embedded DEFLATE (zlib) 'islands' inside an opaque blob.
    Return (ok, sample) where ok=True iff at least one inflate succeeds
    AND the result looks like text or (optionally) contains PDF content ops.
    We keep this conservative: try a handful of candidates only.
    """
    if not b or len(b) < 32:
        return (False, None)
    # Common zlib headers: 78 01/5E/9C/DA (+ CMF/FLG modulo check below).
    # We limit scans to avoid heavy work on long strings.
    hits = []
    i = 0; L = len(b)
    while i < L - 2 and len(hits) < (max_tries * 4):
        x = b[i]
        if x == 0x78 and b[i+1] in (0x01, 0x5E, 0x9C, 0xDA):
            # Minimal header validity: (CMF*256 + FLG) % 31 == 0
            cmf, flg = b[i], b[i+1]
            if (((cmf << 8) | flg) % 31) == 0:
                hits.append(i)
                if len(hits) >= max_tries: break
            i += 2; continue
        i += 1
    for off in hits[:max_tries]:
        try:
            import zlib
            out = zlib.decompress(b[off:])
            if not out:
                continue
            # Stronger acceptance:
            # A) text path requires BOTH valid UTF-8 and decent ASCII share
            if _looks_utf8_text(out) and _ascii_ratio(out) >= 0.60:
                return (True, out[:2048])
            # B) PDF-ops path requires more evidence: many ops AND sane paren use
            if want_ops:
                ops = _pdf_textop_hits(out)
                has_bt = (out.find(b"BT") != -1)
                has_et = (out.find(b"ET") != -1)
                if (ops >= 4 or (has_bt and has_et)) and _paren_balance_ok(out, limit=200_000):
                    # also guard against “binary noise” that accidentally trips tokens
                    if _ascii_ratio(out) >= 0.45:
                        return (True, out[:2048])
        except Exception:
            continue

    # --- RAW DEFLATE sweep (no zlib wrapper, e.g., wbits=-15) ---
    # Keep it cheap: sample a handful of offsets; if any inflate to text/ops, accept.
    try:
        step = max(32, min(256, max(1, len(b) // (max_tries * 8))))
        tried = 0
        j = 0
        while j < L - 32 and tried < (max_tries * 2):
            d = zlib.decompressobj(wbits=-15)
            try:
                out = d.decompress(b[j:j+65536]) + d.flush()
                if out:
                    # Same acceptance criteria as above
                    if _looks_utf8_text(out) and _ascii_ratio(out) >= 0.60:
                        return (True, out[:2048])
                    if want_ops:
                        ops = _pdf_textop_hits(out)
                        has_bt = (out.find(b"BT") != -1)
                        has_et = (out.find(b"ET") != -1)
                        if (ops >= 4 or (has_bt and has_et)) and _paren_balance_ok(out, limit=200_000) and _ascii_ratio(out) >= 0.45:
                            return (True, out[:2048])
            except Exception:
                pass
            tried += 1
            j += step
    except Exception:
        pass

    return (False, None)

# --- Whole-stream inflate probe for opaque blobs (zlib or raw-deflate) -------

def _inflate_probe_anywhere(b: bytes,
                            max_tries: int = 12) -> Tuple[bool, Dict[str, Any]]:
    """
    Look for zlib or raw-deflate that inflates to a sizable blob anywhere in b.
    Return (found, info) where info includes off, kind, out_len, texty, ops.
    Unlike _inflate_any (which is for string operands and prefers "benign islands"),
    this routine is for stream-level opaque compressed blobs *outside* operands.
    """
    import zlib
    L = len(b)
    if L < 64:
        return False, {}
    # Pass 1: zlib headers
    tried = 0
    i = 0
    while i < L - 2 and tried < max_tries:
        if b[i] == 0x78 and (((b[i] << 8) | b[i+1]) % 31) == 0:
            try:
                out = zlib.decompress(b[i:])
                ops = _pdf_textop_hits(out)
                texty = _looks_utf8_text(out) or (_ascii_ratio(out) >= 0.72)
                if len(out) >= 1024:
                    return True, {"off": i, "kind": "zlib", "out_len": len(out), "texty": bool(texty), "ops": ops}
            except Exception:
                pass
            tried += 1
            i += 2
            continue
        i += 1

    # Pass 2A: raw-deflate (wbits=-15), TIGHT scan near the head (first few KiB).
    # Many “hidden islands” begin within a handful of bytes; scan byte-by-byte here.
    head_lim = min(L - 32, 8192)
    tried = 0
    for j in range(0, max(0, head_lim)):
        if tried >= (max_tries * 8):  # keep a reasonable ceiling
            break
        d = zlib.decompressobj(wbits=-15)
        try:
            out = d.decompress(b[j:j+65536]) + d.flush()
            if len(out) >= 1024:
                ops = _pdf_textop_hits(out)
                texty = _looks_utf8_text(out) or (_ascii_ratio(out) >= 0.72)
                return True, {"off": j, "kind": "raw", "out_len": len(out), "texty": bool(texty), "ops": ops}
        except Exception:
            pass
        tried += 1

    # Pass 2B: raw-deflate (wbits=-15), sampled sweep across the rest.
    step = max(16, min(256, max(1, L // (max_tries * 6))))
    j = head_lim
    while j < L - 32 and tried < (max_tries * 12):
        d = zlib.decompressobj(wbits=-15)
        try:
            out = d.decompress(b[j:j+65536]) + d.flush()
            if len(out) >= 1024:
                ops = _pdf_textop_hits(out)
                texty = _looks_utf8_text(out) or (_ascii_ratio(out) >= 0.72)
                return True, {"off": j, "kind": "raw", "out_len": len(out), "texty": bool(texty), "ops": ops}
        except Exception:
            pass
        tried += 1
        j += step
    return False, {}

def _token_hits(buf: bytes) -> int:
    needles = [b" obj", b"endobj", b"xref", b"trailer", b"/Type", b"/Catalog", b"/Pages", b"/Length"]
    return sum(buf.count(n) for n in needles)

def _pdf_textop_hits(buf: bytes) -> int:
    """
    Count common PDF text/content operators in a decoded content stream.
    This is a coarse signal; we keep it simple and fast.
    """
    ops = [b"BT", b"ET", b"Tj", b"TJ", b"Tf", b"Td", b"Tm", b"Tr", b"Ts", b"Tw", b"Tc"]
    return sum(buf.count(op) for op in ops)

def _looks_like_contentish_raw(buf: bytes) -> bool:
    # NOTE: This is a *coarse* gate used to decide whether to apply
    # content-aware checks. Detailed zoning (e.g., inline image payload)
    # must be handled by callers before applying any “compressed blob” probes.
    """
    Fast, cheap signal that a raw (unfiltered, untyped) stream likely carries PDF
    content operators rather than arbitrary binary. We don't fully tokenize here;
    we just look for common operator tokens and a sane paren balance.
    """
    if not buf:
        return False
    hits = _pdf_textop_hits(buf)
    if hits >= 2 and _paren_balance_ok(buf, limit=200_000):
        return True
    # Also accept if we see BT..ET in-order at least once.
    try:
        i_bt = buf.find(b"BT")
        i_et = buf.find(b"ET")
        return (i_bt != -1 and i_et != -1 and i_bt < i_et)
    except Exception:
        return False
 
def _paren_balance_ok(buf: bytes, limit: int = 1_000_000) -> bool:
    """
    Very light sanity check: parentheses used for string literals shouldn't be outrageously unbalanced.
    We stop early if we exceed a small budget.
    """
    bal = 0
    esc = False
    L = min(len(buf), limit)
    for i in range(L):
        c = buf[i]
        if esc:
            esc = False
            continue
        if c == 0x5C:  # backslash
            esc = True
            continue
        if c == 0x28:  # '('
            bal += 1
        elif c == 0x29:  # ')'
            bal -= 1 if bal > 0 else 0
    # a few unmatched opens are common; we just avoid large pathological counts
    return bal < 32

def _locate_zone_in_raw_content(buf: bytes, rel_s: int, rel_e: int) -> Dict[str, Any]:
    """
    Given the RAW content stream bytes `buf` (unfiltered) and a stream-relative
    overlap [rel_s, rel_e], identify the *first* token/area that covers the
    overlap start:
        - 'comment'
        - 'literal_string'
        - 'hex_string'
        - 'inline_image_dict'   (BI … ID)
        - 'inline_image_payload' (ID … EI)
        - 'syntax'              (ASCII-constrained operators/operands)
        - 'out-of-buffer'       (if rel_s beyond loaded buf)
    Returns a dict with:
        { zone, cover: [z_start, z_end], overlap: [rel_s, rel_e] }
    """
    L = len(buf)
    if L == 0:
        return {"zone": "empty", "cover": [-1, -1], "overlap": [rel_s, rel_e]}
    if rel_s >= L:
        return {"zone": "out-of-buffer", "cover": [-1, -1], "overlap": [rel_s, rel_e]}
    rel_s = max(0, rel_s)
    rel_e = min(rel_e, L - 1)

    # States mirror _content_operand_anomaly
    i = 0
    in_comment = False
    in_lit = False; lit_depth = 0; lit_escape = False
    in_hex = False
    in_iid = False      # inline image dict (between BI and ID)
    in_iip = False      # inline image payload (between ID and EI)

    # record the zone we are in at the moment we enter rel_s
    zone = None
    z_start = rel_s

    # Helper: classify the current state
    def cur_zone() -> str:
        if in_iip:  return "inline_image_payload"
        if in_iid:  return "inline_image_dict"
        if in_comment: return "comment"
        if in_lit:  return "literal_string"
        if in_hex:  return "hex_string"
        return "syntax"

    # Walk until we've at least reached rel_e or we identified a full zone span
    while i < L:
        c = buf[i]
        nxt = buf[i+1] if i+1 < L else None

        # When we first reach rel_s, capture the current zone
        if i == rel_s and zone is None:
            zone = cur_zone()
            z_start = i

        # Inline image payload: scan to 'EI' boundary
        if in_iip:
            if _match_kw(buf, i, b"EI"):
                # end payload at i-1
                if zone == "inline_image_payload" and i > rel_e:
                    return {"zone": zone, "cover": [z_start, i-1], "overlap": [rel_s, rel_e]}
                in_iip = False
                i += 2
                continue
            i += 1
            continue

        # Comment
        if in_comment:
            if c in (0x0A, 0x0D):
                if zone == "comment" and i >= rel_e:
                    return {"zone": zone, "cover": [z_start, i], "overlap": [rel_s, rel_e]}
                in_comment = False
            i += 1
            continue

        # Literal string
        if in_lit:
            if lit_escape: lit_escape = False; i += 1; continue
            if c == 0x5C: lit_escape = True; i += 1; continue
            if c == 0x28: lit_depth += 1; i += 1; continue
            if c == 0x29:
                lit_depth = max(0, lit_depth-1); i += 1
                if lit_depth == 0:
                    if zone == "literal_string" and i-1 >= rel_e:
                        return {"zone": zone, "cover": [z_start, i-1], "overlap": [rel_s, rel_e]}
                    in_lit = False
                continue
            i += 1
            continue

        # Hex string
        if in_hex:
            if c == 0x3E:  # '>'
                if zone == "hex_string" and i >= rel_e:
                    return {"zone": zone, "cover": [z_start, i], "overlap": [rel_s, rel_e]}
                in_hex = False
            i += 1
            continue

        # Inline image dict: ends at 'ID'
        if in_iid:
            if _match_kw(buf, i, b"ID"):
                # payload starts after ID + optional single whitespace
                in_iid = False
                in_iip = True
                i += 2
                if i < L and buf[i] in (0x20,0x0D,0x0A,0x09,0x0C,0x00):
                    i += 1
                # If the suspicious range starts *right* at payload, record zone if not set
                if zone is None and i <= rel_s:
                    zone = "inline_image_payload"; z_start = i
                continue
            i += 1
            continue
 
        # ---- ASCII zone; check for entries into protected zones ----
        if c == 0x25:  # '%'
            in_comment = True; i += 1; continue
        if c == 0x28:  # '('
            in_lit = True; lit_depth = 1; lit_escape = False; i += 1; continue
        if c == 0x3C:  # '<' or '<<'
            if nxt == 0x3C:
                i += 2; continue
            in_hex = True; i += 1; continue
        if _match_kw(buf, i, b"BI"):
            in_iid = True; i += 2; continue
 
        # If we entered rel_s while in ASCII zone, we’ll keep scanning until we
        # cross rel_e or enter/exit a protected zone. If we pass rel_e still in
        # syntax, return that span.
        if zone == "syntax" and i >= rel_e:
            return {"zone": zone, "cover": [z_start, i], "overlap": [rel_s, rel_e]}

        i += 1

    # EOF: finalize
    if zone is None:
        zone = cur_zone()
        z_start = rel_s
    return {"zone": zone, "cover": [z_start, L-1], "overlap": [rel_s, rel_e]}

# ---- Small helpers for “compressed blob outside operands” probing ----
def _local_ascii_ratio(b: bytes, pos: int, win: int = 256) -> float:
    a = max(0, pos - win // 2)
    e = min(len(b), pos + win // 2)
    return _ascii_ratio(b[a:e]) if a < e else 1.0

# ---------- Inflate probe that ignores inline-image payload spans -----------
def _inflate_probe_excluding_spans(b: bytes, spans: list, max_tries: int = 12, *, local_ascii_thresh: float = 0.55, _dbg: bool = False):
    """
    Look for zlib/raw-deflate that inflates to sizable data in `b`, but **ignore**
    any offsets that fall inside `spans` (list of (start,end), inclusive) – typically
    BI..ID..EI inline image payloads and other operands. Also require that the
    candidate offset’s local neighborhood looks binary-ish (low ASCII ratio), which
    suppresses accidental “x?” zlib headers in ASCII syntax.
    Mirrors _inflate_probe_anywhere’s acceptance, but with masking.
    Returns (found, info|{}).
    """
    import zlib
    L = len(b)
    if L < 64:
        return False, {}

    # Normalize spans and build a quick membership test
    mask = []
    for (a, e) in (spans or []):
        if a is None or e is None: 
            continue
        a = max(0, int(a)); e = min(L-1, int(e))
        if a <= e:
            mask.append((a, e))
    mask.sort()

    def _masked(pos: int) -> bool:
        # binary search friendly linear check (spans count is usually small)
        for (a, e) in mask:
            if pos < a: 
                return False
            if a <= pos <= e:
                return True
        return False
 
    # Pass 1: zlib headers (context-gated)
    tried = 0
    i = 0
    while i < L - 2 and tried < max_tries:
        if b[i] == 0x78 and (((b[i] << 8) | b[i+1]) % 31) == 0:
            masked = _masked(i)
            lar = _local_ascii_ratio(b, i)
            if _dbg:
                print("[pdf-debug-inflate-cand-zlib]", {
                    "off": i, "masked": masked, "local_ascii": lar, "thresh": local_ascii_thresh
                })
            if not masked and lar < local_ascii_thresh:
                try:
                    out = zlib.decompress(b[i:])
                    ops = _pdf_textop_hits(out)
                    texty = _looks_utf8_text(out) or (_ascii_ratio(out) >= 0.72)
                    if len(out) >= 1024:
                        if _dbg:
                            print("[pdf-debug-inflate-hit-zlib]", {
                                "off": i, "out_len": len(out), "ops": ops, "texty": bool(texty)
                            })
                        return True, {"off": i, "kind": "zlib", "out_len": len(out), "texty": bool(texty), "ops": ops}
                except Exception as e:
                    if _dbg:
                        print("[pdf-debug-inflate-fail-zlib]", {"off": i, "err": f"{type(e).__name__}: {e}"})
                    pass
            tried += 1
            i += 2
            continue
        i += 1

    # Pass 2: raw-deflate (sampled), also masked and context-gated
    head_lim = min(L - 32, 8192)
    tried = 0
    for j in range(0, max(0, head_lim)):
        if tried >= (max_tries * 8): 
            break
        masked = _masked(j)
        lar = _local_ascii_ratio(b, j)
        if _dbg:
            print("[pdf-debug-inflate-cand-raw-head]", {
                "off": j, "masked": masked, "local_ascii": lar, "thresh": local_ascii_thresh
            })
        if masked or lar >= local_ascii_thresh:
            continue
        d = zlib.decompressobj(wbits=-15)
        try:
            out = d.decompress(b[j:j+65536]) + d.flush()
            if len(out) >= 1024:
                ops = _pdf_textop_hits(out)
                texty = _looks_utf8_text(out) or (_ascii_ratio(out) >= 0.72)
                if _dbg:
                    print("[pdf-debug-inflate-hit-raw-head]", {
                        "off": j, "out_len": len(out), "ops": ops, "texty": bool(texty)
                    })
                return True, {"off": j, "kind": "raw", "out_len": len(out), "texty": bool(texty), "ops": ops}
        except Exception as e:
            if _dbg:
                print("[pdf-debug-inflate-fail-raw-head]", {"off": j, "err": f"{type(e).__name__}: {e}"})
            pass
        tried += 1
 
    step = max(16, min(256, max(1, L // (max_tries * 6))))
    j = head_lim
    while j < L - 32 and tried < (max_tries * 12):
        masked = _masked(j)
        lar = _local_ascii_ratio(b, j)
        if _dbg:
            print("[pdf-debug-inflate-cand-raw-tail]", {
                "off": j, "masked": masked, "local_ascii": lar, "thresh": local_ascii_thresh
            })
        if (not masked) and (lar < local_ascii_thresh):
            d = zlib.decompressobj(wbits=-15)
            try:
                out = d.decompress(b[j:j+65536]) + d.flush()
                if len(out) >= 1024:
                    ops = _pdf_textop_hits(out)
                    texty = _looks_utf8_text(out) or (_ascii_ratio(out) >= 0.72)
                    if _dbg:
                        print("[pdf-debug-inflate-hit-raw-tail]", {
                            "off": j, "out_len": len(out), "ops": ops, "texty": bool(texty)
                        })
                    return True, {"off": j, "kind": "raw", "out_len": len(out), "texty": bool(texty), "ops": ops}
            except Exception as e:
                if _dbg:
                    print("[pdf-debug-inflate-fail-raw-tail]", {"off": j, "err": f"{type(e).__name__}: {e}"})
                pass
        tried += 1
        j += step
    return False, {}

def _debug_rawzone_report(st: "_PDFStream", s0: int, e0: int, ap: str, cap: int = 8*1024*1024) -> None:
    """
    Print a compact record of where [s0,e0] (file-absolute) lands inside `st`
    (assumed unfiltered content-ish). Uses stream-relative coordinates and the
    tokenizer above to label the zone.
    """
    try:
        # Overlap clamp
        os_ = max(st.data_start, s0)
        oe_ = min(st.data_end_incl, e0)
        if oe_ < os_:
            return
        raw = _read_span(ap, st.data_start, st.data_end_incl, cap=cap)
        rel_s = os_ - st.data_start
        rel_e = oe_ - st.data_start
        info = _locate_zone_in_raw_content(raw, rel_s, rel_e)
        print("[pdf-debug-rawzone]", {
            "region": [s0, e0],
            "stream": [st.data_start, st.data_end_incl],
            "rel_range": [rel_s, rel_e],
            "zone": info.get("zone"),
            "cover": info.get("cover"),
        })
    except Exception as _e:
        print("[pdf-debug-rawzone-error]", {"err": f"{type(_e).__name__}: {_e}"})

def _read_stream_raw(path: str, st: "_PDFStream", cap: int = 8*1024*1024) -> bytes:
    return _read_span(path, st.data_start, st.data_end_incl, cap=cap)
        
def _read_span(path: str, start: int, end_incl: int, cap: int) -> bytes:
    if end_incl < start:
        return b""
    length = min(end_incl - start + 1, cap)
    with open(path, "rb") as f:
        f.seek(start)
        return f.read(length)

def _any_overlap(a0: int, a1: int, b0: int, b1: int) -> bool:
    return not (a1 < b0 or b1 < a0)

def _overlap_len(a0: int, a1: int, b0: int, b1: int) -> int:
    if a1 < b0 or b1 < a0:
        return 0
    return min(a1, b1) - max(a0, b0) + 1

def _clip(a0: int, a1: int, b0: int, b1: int) -> Tuple[int, int]:
    return max(a0, b0), min(a1, b1)

# --- extra light-weight stats used only for prelude literal strings ---

def _shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    freq = [0]*256
    for b in data:
        freq[b] += 1
    n = len(data)
    import math
    return -sum((c/n)*math.log2(c/n) for c in freq if c)

def _zlib_compress_ratio(sample: bytes) -> float:
    """
    Return compressed_size / original_size using zlib on a small sample.
    For random/ciphertext, this ~1.00 (≥0.97 is a good tell).
    """
    if not sample:
        return 0.0
    try:
        # keep it cheap; 2 KiB is plenty for a decision here
        s = sample[:2048]
        comp = zlib.compress(s, 6)
        return (len(comp) / len(s)) if s else 0.0
    except Exception:
        return 1.0
 
def _looks_like_sfnt_font(buf: bytes) -> bool:
    """
    Very light sfnt/TrueType/OpenType sanity:
      - scalerType: 0x00010000 or 'OTTO' or 'true' or 'typ1'
      - reasonable numTables
      - a few table records with printable tags and in-bounds offsets
    """
    if len(buf) < 12:
        return False
    import struct
    try:
        scaler, num_tables, _sr, _es, _rs = struct.unpack(">IHHHH", buf[:12])
    except Exception:
        return False
    valid_scalers = {0x00010000, 0x4F54544F, 0x74727565, 0x74797031}  # 0x00010000, 'OTTO', 'true', 'typ1'
    if scaler not in valid_scalers:
        return False
    if not (1 <= num_tables <= 200):
        return False
    dir_len = 12 + num_tables * 16
    if len(buf) < dir_len:
        return False
    # spot-check up to 6 entries
    try:
        for i in range(min(num_tables, 6)):
            off = 12 + i * 16
            tag, _check, offset, length = struct.unpack(">4sIII", buf[off:off+16])
            if not all(32 <= c <= 126 for c in tag):
                return False
            if offset == 0 or length == 0:
                return False
            if offset + length > len(buf):
                return False
    except Exception:
        return False
    return True

def _looks_like_cff_font(buf: bytes) -> bool:
    """
    Light CFF/Type1C sanity:
      - header: major in {1,2}, hdrSize in [4..8], offSize in [1..4]
    Intentionally shallow but enough to distinguish from random ciphertext.
    """
    if len(buf) < 4:
        return False
    major = buf[0]
    hdr_size = buf[2]
    off_size = buf[3]
    return (major in (1, 2)) and (4 <= hdr_size <= 8) and (1 <= off_size <= 4) and (hdr_size <= len(buf))

# ---------- Pretty label for stream kind (for debug) -------------------------
def _stream_kind_label(st: "_PDFStream") -> str:
    if st.k_is_image:        return "image"
    if st.k_is_font:         return "font"
    if st.k_is_icc:          return "icc"
    if st.k_is_textish:      return "textish"
    if st.k_is_xref_stream:  return "xref_stream"
    if st.k_is_objstm:       return "objstm"
    if st.k_is_embedded:     return "embedded"
    if st.k_is_xmp:          return "xmp"
    if st.k_is_content:      return "content"
    return "untyped"

# --------------------- Zlib header sanity for Flate --------------------------
def _zlib_header_ok(b: bytes) -> bool:
    """
    Minimal zlib header validation:
      - CM must be 8 (DEFLATE)
      - CINFO <= 7 (window size up to 32K)
      - (CMF*256 + FLG) % 31 == 0
    """
    if len(b) < 2:
        return False
    cmf, flg = b[0], b[1]
    if (cmf & 0x0F) != 8:       # CM = 8
        return False
    if (cmf >> 4) > 7:          # CINFO <= 7
        return False
    return (((cmf << 8) | flg) % 31) == 0

# ---------------- Embedded zlib probes for member-first override -------------
def _scan_embedded_zlib_headers(raw: bytes, max_hits: int = 32) -> List[Dict[str, Any]]:
    """
    Find plausible zlib headers in 'raw' and try inflating from each.
    Returns a list of dicts: {"off": int, "ok": bool, "out_len": Optional[int], "err": Optional[str]}.
    """
    hits: List[Dict[str, Any]] = []
    if not raw or len(raw) < 2:
        return hits
    i, L = 0, len(raw)
    while i < L - 2 and len(hits) < max_hits:
        if raw[i] == 0x78:
            cmf, flg = raw[i], raw[i+1]
            # Minimal header validity: (CMF<<8 | FLG) % 31 == 0
            if (((cmf << 8) | flg) % 31) == 0:
                rec: Dict[str, Any] = {"off": i, "ok": False, "out_len": None, "err": None}
                try:
                    out = zlib.decompress(raw[i:])
                    rec["ok"] = True
                    rec["out_len"] = len(out)
                except Exception as e:
                    rec["ok"] = False
                    rec["err"] = f"{type(e).__name__}: {e}"
                hits.append(rec)
                i += 2
                continue
        i += 1
    return hits

def _member_has_broken_zlib(raw: bytes) -> Tuple[bool, List[Dict[str, Any]]]:
    """
    Heuristic: return True if the stream contains at least one plausible zlib
    header whose inflate fails. We bubble that suspicion to any region in the member.
    """
    hits = _scan_embedded_zlib_headers(raw)
    broken = any(not h.get("ok") for h in hits)
    return broken, hits

# --------------------- Binary header marker handling -------------------------

# NOTE: the two helpers below (_compute_binary_marker_window, _read_ctx) are the
# canonical versions. Earlier duplicates were removed to avoid drift.

def _read_ctx(path: str, center_lo: int, center_hi: int, radius: int = 16384, cap: int = 65536) -> Tuple[bytes, int]:
    fsize = os.path.getsize(path)
    a = max(0, center_lo - radius)
    b = min(fsize - 1, center_hi + radius) if fsize > 0 else 0
    if b < a:
        a, b = 0, min(fsize - 1, cap - 1)
    length = min(cap, b - a + 1)
    with open(path, "rb") as f:
        f.seek(a)
        return f.read(length), a

def _compute_binary_marker_window(path: str,
                                  scan_bytes: int = 4096,
                                  max_marker_bytes: int = 512) -> Tuple[int, int]:
    """
    Identify an allowed 'binary header marker' window near BOF.
    Rules:
      - Look only in the first `scan_bytes` bytes.
      - After the %PDF-x.y header line, allow consecutive comment lines (%...<EOL>)
        that contain >=4 bytes with value >= 128, up to `max_marker_bytes` total.
      - Return absolute [start, end_incl] of the allowed window. If none, return (-1,-1).
    """
    try:
        fsize = os.path.getsize(path)
        lim = min(scan_bytes, fsize)
        with open(path, "rb") as f:
            head = f.read(lim)
        # Find header line end
        m = re.search(rb"%PDF-\d\.\d[^\r\n]*([\r\n]|$)", head)
        if not m:
            return (-1, -1)
        pos = m.end()
        total = 0
        start_win = -1
        end_win = -1
        # Iterate line by line after header
        while pos < len(head):
            ln_end = head.find(b"\n", pos)
            cr = head.find(b"\r", pos)
            if ln_end == -1 and cr != -1:
                ln_end = cr
            if ln_end == -1:
                ln_end = len(head)
            line = head[pos:ln_end]
            if line.startswith(b"%"):
                # Count bytes >= 128 (non-ASCII)
                hi = sum(1 for b in line if b >= 128)
                if hi >= 4 and total < max_marker_bytes:
                    if start_win == -1:
                        start_win = pos
                    total += len(line) + 1  # include newline
                    end_win = ln_end
                    pos = ln_end + 1
                    continue
            break  # first non-marker (or weak) line ends the marker zone
        if start_win != -1 and end_win != -1:
            return (start_win, end_win)
        return (-1, -1)
    except Exception:
        return (-1, -1)

def _comment_highbit_anomaly(ctx_buf: bytes,
                             base_off: int,
                             s0: int, e0: int,
                             allowed_win: Tuple[int, int]) -> Optional[str]:
    """
    If any comment line (%...EOL) that overlaps [s0,e0] is found *outside* the
    allowed binary-marker window and contains any byte >=128, flag it.
    """
    aw_lo, aw_hi = allowed_win
    # Scan comment lines in ctx_buf
    for m in re.finditer(rb"(?m)^%[^\r\n]*", ctx_buf):
        a = base_off + m.start()
        b = base_off + m.end() - 1
        # Overlap with suspicious region?
        if not (e0 < a or b < s0):
            # Is this line outside the allowed window?
            outside_win = not (aw_lo != -1 and aw_hi != -1 and not (b < aw_lo or aw_hi < a))
            if outside_win:
                line = m.group(0)
                if any(ch >= 128 for ch in line):
                    return "pdf: prelude comment contains non-ASCII (post-marker)"
    return None

# --------------------- Prelude semantics: entity find/validate ----------------

def _read_ctx(path: str, center_lo: int, center_hi: int, radius: int = 16384, cap: int = 65536) -> Tuple[bytes, int]:
    """
    Read a window around [center_lo, center_hi]. Return (buf, base_offset).
    """
    fsize = os.path.getsize(path)
    a = max(0, center_lo - radius)
    b = min(fsize - 1, center_hi + radius) if fsize > 0 else 0
    if b < a:
        a, b = 0, min(fsize - 1, cap - 1)
    length = min(cap, b - a + 1)
    with open(path, "rb") as f:
        f.seek(a)
        return f.read(length), a

def _balance_ok(data: bytes, open_b: bytes, close_b: bytes, limit: int = 65536) -> bool:
    bal = 0
    L = min(len(data), limit)
    i = 0
    while i < L:
        if data[i:i+len(open_b)] == open_b:
            bal += 1
            i += len(open_b); continue
        if data[i:i+len(close_b)] == close_b:
            bal -= 1 if bal > 0 else 0
            i += len(close_b); continue
        i += 1
    return bal < 16

def _decode_pdf_literal_string(s: bytes) -> Optional[bytes]:
    """
    Decode a PDF literal string body (without outer parentheses).
    Handle escapes, octal, UTF-16BE BOM; fallback to PDFDocEncoding≈Latin-1.
    """
    out = bytearray()
    i = 0; L = len(s)
    while i < L:
        c = s[i]; i += 1
        if c != 0x5C:  # '\'
            out.append(c); continue
        if i >= L: break
        esc = s[i]; i += 1
        if esc in b"nrtbf()\\":
            table = {ord('n'):10, ord('r'):13, ord('t'):9, ord('b'):8, ord('f'):12,
                     ord('('):0x28, ord(')'):0x29, ord('\\'):0x5C}
            out.append(table[esc]); continue
        # octal \ddd
        if 0x30 <= esc <= 0x37:
            val = esc - 0x30
            for _ in range(2):
                if i < L and 0x30 <= s[i] <= 0x37:
                    val = (val << 3) + (s[i] - 0x30); i += 1
                else:
                    break
            out.append(val & 0xFF); continue
        # line continuation
        if esc in (0x0D, 0x0A):
            # swallow optional LF after CR
            if esc == 0x0D and i < L and s[i] == 0x0A: i += 1
            continue
        out.append(esc)
    b = bytes(out)
    # encoding
    if len(b) >= 2 and b[:2] in (b"\xFE\xFF", b"\xFF\xFE"):
        try:
            return b.decode("utf-16").encode("utf-8")
        except Exception:
            return None
    # try UTF-8 then latin-1
    try:
        return b.decode("utf-8").encode("utf-8")
    except Exception:
        try:
            return b.decode("latin-1").encode("utf-8")
        except Exception:
            return None

def _decode_pdf_hex_string(s: bytes) -> Optional[bytes]:
    """
    Decode a PDF hex string body (without <>). Odd nibble padded as per spec.
    """
    s = re.sub(rb"\s+", b"", s)
    if len(s) == 0:
        return b""
    if len(s) % 2 == 1:
        s += b"0"
    try:
        return binascii.unhexlify(s)
    except Exception:
        return None

def _is_texty(b: bytes, min_printable: float = 0.6) -> bool:
    if not b:
        return False
    printable = sum(1 for ch in b if ch in (9,10,13) or 32 <= ch <= 126)
    return (printable / len(b)) >= min_printable

def _find_enclosing_obj(buf: bytes) -> Optional[Tuple[int, int]]:
    m1 = OBJ_START_RE.search(buf)
    m2 = OBJ_END_RE.search(buf)
    if not m1 or not m2:
        return None
    if m2.start() <= m1.end():
        return None
    return (m1.start(), m2.end())

 
def _find_enclosing_obj_around(buf: bytes, pos: int) -> Optional[Tuple[int, int]]:
    if not buf or pos < 0 or pos >= len(buf):
        return None
    end_m = OBJ_END_RE.search(buf, pos)
    if not end_m:
        return None
    end_i = end_m.start()
    start_m = None
    for m in OBJ_START_RE.finditer(buf, 0, end_i):
        start_m = m
    if start_m is None:
        return None
    # ensure there isn’t an endobj between start and pos
    if OBJ_END_RE.search(buf, start_m.end(), pos):
        return None
    a = start_m.start()
    return (a, end_m.end()) if (a <= pos < end_m.end()) else None

def _find_xref_trailer(buf: bytes) -> Optional[Tuple[int, int]]:
    mx = XREF_RE.search(buf)
    mt = TRAILER_RE.search(buf)
    if not mx or not mt:
        return None
    # extend to end of dict after 'trailer'
    tail = buf[mt.end(): mt.end() + 65536]
    dm = re.search(rb"<<.*?>>", tail, re.DOTALL)
    if not dm:
        return None
    end = mt.end() + dm.end()
    return (mx.start(), end)

def _find_startxref(buf: bytes) -> Optional[Tuple[int, int]]:
    ms = STARTXREF_RE.search(buf)
    if not ms:
        return None
    # read integer after startxref
    tail = buf[ms.end(): ms.end() + 64]
    mm = re.search(rb"\s*(\d+)", tail)
    if not mm:
        return None
    end = ms.end() + mm.end()
    return (ms.start(), end)

def _validate_header(buf: bytes) -> Tuple[bool, str]:
    m = PDF_HEADER_RE.search(buf[:64])
    if not m:
        return False, "bad/missing %PDF header"
    # optional binary marker line (ignore if present)
    return True, ""

def _validate_obj_nonstream(obj_bytes: bytes) -> Tuple[bool, str]:
    # Quick delimiter sanity
    if not _balance_ok(obj_bytes, b"<<", b">>") or obj_bytes.count(b"[") - obj_bytes.count(b"]") >= 16:
        return False, "dict/array delimiter imbalance"
    # If Info-like dictionary is present, try decoding common textual keys
    # Scan minimal dict-like chunks
    for m in re.finditer(rb"<<.*?>>", obj_bytes, re.DOTALL):
        d = m.group(0)
        # Extract key/value pairs conservatively
        for km in re.finditer(rb"(/[\w\+\-\.]+)\s+(\((?:\\.|[^\\\)])*\)|<[^>]*>)", d, re.DOTALL):
            key = km.group(1)
            val = km.group(2)
            if key in _INFO_TEXT_KEYS:
                if val.startswith(b"("):
                    inner = val[1:-1] if val.endswith(b")") else val[1:]
                    dec = _decode_pdf_literal_string(inner)
                else:
                    inner = val[1:-1] if val.endswith(b">") else val[1:]
                    raw = _decode_pdf_hex_string(inner)
                    dec = None
                    if raw is not None:
                        # try utf-16/utf-8/latin-1
                        for enc in ("utf-16", "utf-8", "latin-1"):
                            try:
                                dec = raw.decode(enc).encode("utf-8")
                                break
                            except Exception:
                                continue
                if dec is None or not _is_texty(dec):
                    return False, f"undecodable or non-texty {key.decode('ascii', 'ignore')}"
    return True, ""

def _validate_xref_trailer(xref_bytes: bytes) -> Tuple[bool, str]:
    # Very light row shape check
    # Find first section header N M
    sect = re.search(rb"\bxref\s+(\d+)\s+(\d+)", xref_bytes)
    if not sect:
        return False, "missing xref section header"
    # rows look like: 0000000000 00000 n
    rows = re.findall(rb"\n(\d{10})\s(\d{5})\s[fn]\b", xref_bytes)
    if len(rows) == 0:
        return False, "no xref rows"
    # trailer with /Size
    tr = re.search(rb"trailer\s*<<.*?/Size\s+(\d+).*?>>", xref_bytes, re.DOTALL)
    if not tr:
        return False, "missing trailer/Size"
    return True, ""

def _validate_startxref(seg: bytes, fsize: int) -> Tuple[bool, str]:
    m = re.search(rb"startxref\s+(\d+)", seg)
    if not m:
        return False, "missing integer after startxref"
    try:
        off = int(m.group(1))
        if off < 0 or off >= fsize:
            return False, "startxref offset out of bounds"
    except Exception:
        return False, "startxref integer parse error"
    return True, ""

def _gap_stats(sample: bytes) -> Dict[str, Any]:
    """
    Lightweight stats for diagnostics only.
    """
    if sample is None:
        sample = b""
    return {
        "len": len(sample),
        "ascii_ratio": _ascii_ratio(sample),
        "chi2": _chi2_uniform(sample),
        "entropy": _shannon_entropy(sample[:4096]),
        "zlib_cr": _zlib_compress_ratio(sample[:2048]),
        "utf8_ok": _valid_utf8_first_error(sample)[0],
        "token_hits": _token_hits(sample),
    }

def _looks_random_interstream_gap(stats: Dict[str, Any]) -> bool:
    """
    Heuristic specifically for **inter-stream** gaps. True inter-stream scaffolding
    should be ASCII-ish and tokeny. Random/ciphertext-y gaps tend to have:
      - ascii_ratio well below "texty" (~0.6), typically ~0.37–0.45 for uniform bytes
      - near-uniform byte distribution (lower chi2)
      - high Shannon entropy or zlib CR ~ 1.0
      - zero PDF token hits
    Thresholds tuned to catch your FN (ascii~0.39, chi2~208–285, H~7.55+, CR~1.02, token_hits=0).
    """
    if not stats:
        return False
    return (stats.get("ascii_ratio", 1.0) < 0.55) and (stats.get("chi2", 9999.0) <= 285.0) \
           and ((stats.get("entropy", 0.0) >= 7.5) or (stats.get("zlib_cr", 0.0) >= 0.98)) and (stats.get("token_hits", 1) == 0)

def _classify_gap_kind(path: str,
                       s0: int, e0: int,
                       first_stream_start: int,
                       marker_win: Tuple[int,int]) -> Tuple[str, Dict[str, Any]]:
    """
    Best-effort semantic labeling for an outside-stream slice [s0,e0].
    Returns (kind, extra) where kind is one of:
      - prelude/header
      - prelude/marker-window
      - prelude/obj
      - prelude/xref-trailer
      - prelude/startxref
      - inter-stream/obj
      - inter-stream/plain
      - tail/startxref
      - tail/plain
      - unknown
    'extra' includes small stats and offsets to help triage FNs.
    """
    try:
        ctx_buf, base_off = _read_ctx(path, s0, e0, radius=16384, cap=65536)
        rel_s = max(0, s0 - base_off)
        rel_e = min(len(ctx_buf) - 1, e0 - base_off)
        window = ctx_buf[rel_s:rel_e+1] if 0 <= rel_s <= rel_e < len(ctx_buf) else b""
        stats = _gap_stats(window[:2048])
        aw_lo, aw_hi = marker_win
        rel_mid = (rel_s + rel_e) // 2 if (0 <= rel_s <= rel_e) else 0

        # Nearest-token hints (relative to file) to spot boundary misses.
        def _nearest(pattern: bytes) -> int:
            if not ctx_buf:
                return -1
            # search left and right within the context window for first occurrence
            left = ctx_buf.rfind(pattern, 0, rel_s) if rel_s >= 0 else -1
            right = ctx_buf.find(pattern, rel_e+1) if rel_e+1 <= len(ctx_buf) else -1
            # translate to absolute offsets
            left = (base_off + left) if left != -1 else -1
            right = (base_off + right) if right != -1 else -1
            # prefer the closer (by absolute distance), falling back to whichever exists
            if left == -1:
                return right
            if right == -1:
                return left
            dl = abs((base_off + rel_s) - left)
            dr = abs(right - (base_off + rel_e))
            return left if dl <= dr else right

        nearest_tokens = {
            "near_obj": _nearest(b" obj"),
            "near_endobj": _nearest(b"endobj"),
            "near_stream": _nearest(b"\nstream"),
            "near_endstream": _nearest(b"endstream"),
        }
        
        # Prelude-ish?
        in_prelude = s0 < first_stream_start
        if in_prelude:
            if aw_lo != -1 and aw_hi != -1 and s0 >= aw_lo and e0 <= aw_hi:
                return ("prelude/marker-window", {"stats": stats, "base_off": base_off, "nearest_tokens": nearest_tokens})
            # Look for entities within context window
            if _validate_header(ctx_buf[:4096])[0] and s0 < 1024:
                return ("prelude/header", {"stats": stats, "base_off": base_off, "nearest_tokens": nearest_tokens})
            if _find_xref_trailer(ctx_buf):
                return ("prelude/xref-trailer", {"stats": stats, "base_off": base_off, "nearest_tokens": nearest_tokens})
            if _find_startxref(ctx_buf):
                return ("prelude/startxref", {"stats": stats, "base_off": base_off, "nearest_tokens": nearest_tokens})
            if _find_enclosing_obj_around(ctx_buf, rel_mid) is not None:
                return ("prelude/obj", {"stats": stats, "base_off": base_off, "nearest_tokens": nearest_tokens})
            return ("prelude/plain", {"stats": stats, "base_off": base_off, "nearest_tokens": nearest_tokens})
        
        # Not prelude: tail if very near EOF?
        try:
            fsize = os.path.getsize(path)
        except Exception:
            fsize = -1
        near_eof = (fsize != -1 and (fsize - e0) <= 4096)
        if near_eof:
            if _find_startxref(ctx_buf):
                return ("tail/startxref", {"stats": stats, "base_off": base_off, "nearest_tokens": nearest_tokens})
            return ("tail/plain", {"stats": stats, "base_off": base_off, "nearest_tokens": nearest_tokens})
        # Inter-stream middle: try to see if sitting in a non-stream object
        if _find_enclosing_obj_around(ctx_buf, rel_mid) is not None:
            return ("inter-stream/obj", {"stats": stats, "base_off": base_off, "nearest_tokens": nearest_tokens})
        return ("inter-stream/plain", {"stats": stats, "base_off": base_off, "nearest_tokens": nearest_tokens})
    except Exception as _e:
        return ("unknown", {"error": f"{type(_e).__name__}: {_e}"})

# -------- token-scoped semantics for outside-stream prelude --------

def _prelude_token_semantics(ctx_buf: bytes, base_off: int, s0: int, e0: int) -> Optional[str]:
    """
    Inspect only tokens that *overlap* [s0,e0]: literal strings, hex strings,
    numbers, and dict blocks. Return a reason string on anomaly, else None.

    Strict Info-key validation is handled earlier in _validate_obj_nonstream.
    Here we add a *fused randomness* rule for generic prelude literals so
    benign but non-texty literals don't cause FPs.
    """
    def _ov(a0, a1, b0, b1):
        return not (a1 < b0 or b1 < a0)

    rel_s = max(0, s0 - base_off)
    rel_e = min(len(ctx_buf) - 1, e0 - base_off)
    if rel_s > rel_e:
        return None

    window = ctx_buf  # <= 64 KiB already

    # ---- Tunables for the fused rule (good starting points) ----
    MIN_LIT_LEN = 48         # raise to 96 if you want even fewer FPs
    ASCII_MAX   = 0.18
    CHI2_MAX    = 300.0      # lower = "more uniform"
    ENTROPY_MIN = 7.5
    CR_MIN      = 0.97       # zlib compressed size / raw size

    # 1) literal strings (…) with escapes / octal
    for m in re.finditer(rb"\((?:\\.|[^\\\)])*\)", window, re.DOTALL):
        a, b = m.start(), m.end() - 1
        if _ov(rel_s, rel_e, a, b):
            body = window[a+1:b]

            # Try to decode: if it's clean, treat as non-suspicious and continue.
            dec = _decode_pdf_literal_string(body)
            if dec is not None and _is_texty(dec):
                pass  # benign literal; keep scanning
            else:
                # Generic (non-Info) literal that isn't clearly texty → apply fused rule
                if len(body) >= MIN_LIT_LEN:
                    ascii_r = _ascii_ratio(body)
                    chi2    = _chi2_uniform(body)
                    H       = _shannon_entropy(body)
                    cr      = _zlib_compress_ratio(body)

                    if (ascii_r < ASCII_MAX) and (chi2 <= CHI2_MAX) and ((H >= ENTROPY_MIN) or (cr >= CR_MIN)):
                        return "pdf: prelude data encrypted"
                # Otherwise small/ambiguous non-texty literal → don't alarm here

    # 2) hex strings <…> (odd nibble allowed -> padded)
    for m in re.finditer(rb"<[0-9A-Fa-f\s]*>", window, re.DOTALL):
        a, b = m.start(), m.end() - 1
        if _ov(rel_s, rel_e, a, b):
            raw = _decode_pdf_hex_string(window[a+1:b])
            if raw is None:
                return "pdf: prelude hex string undecodable"
            # non-texty hex is allowed (often binary), so no extra alarm here

    # 3) numeric tokens: any non-ASCII byte inside a number is suspicious
    for m in re.finditer(rb"\b[+\-]?\d+\b", window):
        a, b = m.start(), m.end() - 1
        if _ov(rel_s, rel_e, a, b):
            tok = window[a:b+1]
            if any(ch < 0x20 or ch > 0x7E for ch in tok):
                return "pdf: prelude numeric token anomaly"

    # 4) dict blocks overlapping: require local delimiter sanity
    for m in re.finditer(rb"<<.*?>>", window, re.DOTALL):
        a, b = m.start(), m.end() - 1
        if _ov(rel_s, rel_e, a, b):
            chunk = window[a:b+1]
            if not _balance_ok(chunk, b"<<", b">>"):
                return "pdf: prelude dict delimiter imbalance"

    return None

# -------- ASCII-constrained prelude scanner (semantic, not entropy) ----------
def _prelude_ascii_constrained_check(ctx_buf: bytes, base_off: int, s0: int, e0: int, debug: bool = False) -> Optional[str]:
    """
    Walk a small window around the requested range and verify that bytes which are
    *not* inside comments (%...EOL), *not* inside literal strings (...), and *not*
    inside hex strings <...> (single angle form) are ASCII whitespace/visible only.
    This models the fact that pre-stream prelude is texty PDF syntax.
    Returns a reason string on anomaly else None.
    """
    if not ctx_buf:
        return None
    rel_s = max(0, s0 - base_off)
    rel_e = min(len(ctx_buf) - 1, e0 - base_off)
    if rel_s > rel_e:
        return None

    L = len(ctx_buf)
    i = 0
    in_comment = False
    in_lit = False     # literal string (...)
    lit_depth = 0
    lit_escape = False
    in_hex = False     # hex string <...> (but not '<<' dict)

    # Helper: does index j lie within the overlap slice we care about?
    def in_overlap(j: int) -> bool:
        return rel_s <= j <= rel_e
    # Helper: zone label for debugging
    def cur_zone() -> str:
        if in_comment: return "comment"
        if in_lit:     return "literal_string"
        if in_hex:     return "hex_string"
        return "syntax"
    
    while i < L:
        b = ctx_buf[i]
        nxt = ctx_buf[i+1] if i+1 < L else None

        # When we first *enter* the overlap, capture and log the zone we are in.
        if debug and i == rel_s:
            print("[pdf-debug-prelude-ascii-enter]", {
                "base_off": base_off,
                "rel_s": rel_s,
                "rel_e": rel_e,
                "zone_at_rel_s": cur_zone()
            })
        
        # Handle comment: % ... (until CR or LF)
        if in_comment:
            # end comment at line break; any bytes allowed within comment
            if b in (0x0A, 0x0D):
                in_comment = False
            i += 1
            continue

        # Inside literal string (...)
        if in_lit:
            if lit_escape:
                lit_escape = False
                i += 1
                continue
            if b == 0x5C:  # backslash
                lit_escape = True
                i += 1
                continue
            if b == 0x28:  # '(' nested
                lit_depth += 1
                i += 1
                continue
            if b == 0x29:  # ')'
                # close one level; leave when depth hits zero
                lit_depth -= 1 if lit_depth > 0 else 0
                if lit_depth == 0:
                    in_lit = False
                i += 1
                continue
            # bytes inside literal strings are not ASCII-constrained here
            i += 1
            continue

        # Inside hex string <...> (single angle, not dict '<<')
        if in_hex:
            if b == 0x3E:  # '>'
                in_hex = False
            i += 1
            continue

        # Not in any protected region: check for entries into protected regions
        if b == 0x25:  # '%': start of comment
            in_comment = True
            i += 1
            continue

        if b == 0x28:  # '(' : start of literal string
            in_lit = True
            lit_depth = 1
            lit_escape = False
            i += 1
            continue

        if b == 0x3C:  # '<' could be hex string or dict start '<<'
            if nxt == 0x3C:
                # dictionary start '<<' -> stay ASCII-constrained
                i += 2
                continue
            else:
                in_hex = True
                i += 1
                continue

        # Normal ASCII-constrained zone: only allow HT/LF/CR/space and 0x21..0x7E.
        # If current position is within the overlap, enforce; otherwise just skip.
        if in_overlap(i):
            if not (b in (0x09, 0x0A, 0x0D) or 0x20 <= b <= 0x7E):
                off = base_off + i
                # Debug: show a short hex/context window around the first offending byte.
                try:
                    pre = ctx_buf[max(0, i-8):i]
                    post = ctx_buf[i+1:i+9]
                    print(f"[pdf-debug-prelude-ascii] first_non_ascii_off={off} "
                          f"byte=0x{b:02x} pre={pre.hex()} post={post.hex()}")
                except Exception:
                    pass
                return f"pdf: prelude ASCII anomaly @{off}"

        i += 1

    return None

# --------------------- Content stream operand checks -------------------------

def _decode_string_operand_lit(body: bytes) -> Optional[bytes]:
    """Decode a literal string body (no outer parens) to UTF-8 bytes or None."""
    return _decode_pdf_literal_string(body)

def _decode_string_operand_hex(body: bytes) -> Optional[bytes]:
    """Decode a hex string body (no angle brackets) to UTF-8 bytes or None."""
    raw = _decode_pdf_hex_string(body)
    if raw is None:
        return None
    # Try common encodings
    if len(raw) >= 2 and raw[:2] in (b"\xFE\xFF", b"\xFF\xFE"):
        try:
            return raw.decode("utf-16").encode("utf-8")
        except Exception:
            pass
    for enc in ("utf-8", "latin-1"):
        try:
            return raw.decode(enc).encode("utf-8")
        except Exception:
            continue
    return None

def _content_operand_anomaly(buf: bytes, *, ctx: Optional[FileContext] = None, debug: Optional[bool] = None) -> Optional[str]:
    """
    Scan a decoded content stream:
      - Skip inline image payload (BI … ID … EI)
      - Validate *string operands* only (literal/hex)
      - Long high-entropy, non-texty strings → anomaly
    Return reason string on anomaly else None.
    """
    L = len(buf)
    i = 0
    in_comment = False
    in_lit = False; lit_depth = 0; lit_escape = False; lit_s = -1
    in_hex = False; hex_s = -1
    in_iid = False
    in_iip = False
    payload_s = None

    MIN_LIT_LEN = 48
    ASCII_MAX   = 0.18
    CHI2_MAX    = 240.0
    ENTROPY_MIN = 7.5
    CR_MIN      = 0.97

    # Stricter definition of “looks like text” for operands.
    # We accept ONLY if it’s valid UTF-8 OR has a fairly high ASCII share.
    # (latin-1 fallback alone shouldn’t green-light long ciphertext-y strings.)
    def _texty_enough(utf8_bytes: bytes) -> bool:
        try:
            # Require strict UTF-8 decode OR higher printable ASCII share.
            return _looks_utf8_text(utf8_bytes, min_printable=0.60) or (_ascii_ratio(utf8_bytes) >= 0.72)
        except Exception:
            return False
    
    # Local helper to decide if a suspicious string body is actually structured
    # compressed data (e.g., zlib islands) rather than ciphertext.
    def structured_via_islands(body: bytes) -> bool:
        ok, sample = _inflate_any(body, max_tries=6, want_ops=True)
        # Preserve legacy behavior: if no explicit debug is passed,
        # consult ctx.params flags (when ctx is available).
        _dbg = bool(debug) if debug is not None else bool(
            ctx and (ctx.params.get("debug_pdf_textish") or ctx.params.get("debug_pdf_streams"))
        )
        if _dbg:
            print("[pdf-debug-string-islands]", {"len": len(body), "has_islands": ok})
        return bool(ok)
    
    def looks_encrypted(sample: bytes) -> bool:
        if len(sample) < MIN_LIT_LEN:
            return False
        return (_ascii_ratio(sample) < ASCII_MAX
                and _chi2_uniform(sample) <= CHI2_MAX
                and (_shannon_entropy(sample) >= ENTROPY_MIN
                     or _zlib_compress_ratio(sample) >= CR_MIN))

    while i < L:
        c = buf[i]
        nxt = buf[i+1] if i+1 < L else None

        if in_iip:
            # Binary zone: scan for EI at token boundary and ignore payload bytes
            if _match_kw(buf, i, b"EI"):
                in_iip = False
                i += 2
                continue
            i += 1
            continue

        if in_comment:
            if c in (0x0A, 0x0D):
                in_comment = False
            i += 1; continue

        if in_lit:
            if lit_escape: lit_escape = False; i += 1; continue
            if c == 0x5C: lit_escape = True; i += 1; continue
            if c == 0x28: lit_depth += 1; i += 1; continue
            if c == 0x29:
                lit_depth = max(0, lit_depth-1); i += 1
                if lit_depth == 0:
                    in_lit = False
                    body = buf[lit_s:i-1]
                    dec = _decode_string_operand_lit(body)
                    # Stricter “texty” gate; latin-1 fallback isn’t enough on its own.
                    if dec is None or not _texty_enough(dec):
                        # NEW: accept long non-texty literals that hide structured zlib "islands"
                        if structured_via_islands(body):
                            # benign structured data, not ciphertext
                            pass
                        elif looks_encrypted(body):
                            return "pdf: content string looks encrypted"
                    else:
                        # Backstop: even if it decoded to something that *looks* texty,
                        # treat clear ciphertext patterns in the RAW literal body as suspicious.
                        if looks_encrypted(body):
                            return "pdf: content string looks encrypted"
                continue
            i += 1; continue

        if in_hex:
            if c == 0x3E:  # '>'
                in_hex = False
                body = buf[hex_s:i]
                dec = _decode_string_operand_hex(body)
                if dec is None or not _texty_enough(dec):
                    # hex often encodes binary snips; accept if it hosts structured zlib islands
                    if structured_via_islands(body):
                        pass
                    # otherwise, only alarm if random/long
                    elif looks_encrypted(body):
                        return "pdf: content hex string looks encrypted"
                else:
                    # Same backstop for hex strings after decode.
                    raw = _decode_pdf_hex_string(body) or b""
                    if looks_encrypted(raw):
                        return "pdf: content hex string looks encrypted"                    
                i += 1; continue
            i += 1; continue

        if c == 0x25:  # '%'
            in_comment = True; i += 1; continue
        if c == 0x28:  # '('
            in_lit = True; lit_depth = 1; lit_escape = False; lit_s = i+1; i += 1; continue
        if c == 0x3C:  # '<' or '<<'
            if nxt == 0x3C:
                i += 2; continue
            in_hex = True; hex_s = i+1; i += 1; continue
        if _match_kw(buf, i, b"BI"):
            in_iid = True; i += 2; continue
        if in_iid and _match_kw(buf, i, b"ID"):
            in_iid = False; in_iip = True
            i += 2
            if i < L and buf[i] in (0x20,0x0D,0x0A,0x09,0x0C,0x00):
                i += 1
            continue
        i += 1
    return None

# --- Debug hook: when gap/stream debug is on, annotate literal/hex zones that were probed ---
try:
    from typing import Any as _Any  # cheap import guard to avoid altering behavior
except Exception:
    pass

# ----------------------------- Parse helpers ---------------------------------

def _parse_filter_names(val: bytes) -> List[bytes]:
    """
    Parse /Filter value which can be:
      - /Name
      - [/Name /Name2 ...]
      - Arbitrary spacing/newlines
    Returns normalized names (without the leading slash).
    """
    if not val:
        return []
    try:
        v = val.strip()
        if v.startswith(b"["):
            # Collect every /Name inside the array
            return [_norm_filter_name(m.group(1)) for m in NAME_RE.finditer(v)]
        # Single filter value — find the first /Name token
        m = NAME_RE.search(v if v.startswith(b"/") else b"/" + v)
        return [_norm_filter_name(m.group(1))] if m else []
    except Exception:
        return []

def _parse_decodeparms(val: bytes) -> List[Dict[bytes, Any]]:
    def _parse_one(d: bytes) -> Dict[bytes, Any]:
        out: Dict[bytes, Any] = {}
        for key in (b"Predictor", b"Columns", b"Colors", b"BitsPerComponent"):
            m = re.search(rb"/%s\s+(\d+)" % key, d)
            if m:
                try:
                    out[key] = int(m.group(1))
                except Exception:
                    pass
        return out

    if not val:
        return []
    val = val.strip()
    try:
        if val.startswith(b"["):
            parts = []
            i, L = 1, len(val)
            while i < L-1:
                while i < L-1 and val[i] in b" \t\r\n": i += 1
                if i >= L-1: break
                if val[i:i+2] == b"<<":
                    depth = 1; j = i+2
                    while j < L-1 and depth > 0:
                        if val[j:j+2] == b"<<": depth += 1; j += 2
                        elif val[j:j+2] == b">>": depth -= 1; j += 2
                        else: j += 1
                    parts.append(_parse_one(val[i:j]))
                    i = j
                else:
                    j = i
                    while j < L-1 and val[j] not in (b" \t\r\n]"): j += 1
                    i = j
            return parts
        elif val.startswith(b"<<"):
            return [_parse_one(val)]
    except Exception:
        pass
    return []

# ----------------------------- Stream record ---------------------------------

class _PDFStream:
    __slots__ = (
        "dict_start","dict_end","data_start","data_end_incl",
        "filters","decodeparms","raw_len","dict_bytes",
        "k_is_image","k_is_font","k_is_icc","k_is_content",
        "k_is_xref_stream","k_is_objstm","k_is_embedded","k_is_xmp",
        "k_is_textish",
    )
    def __init__(
        self,
        ds: int, de: int, s: int, e: int,
        filters: List[bytes],
        decodeparms: Optional[List[Dict[bytes, Any]]],
        raw_len: int,
        dict_bytes: bytes,
    ):
        self.dict_start = ds
        self.dict_end = de
        self.data_start = s
        self.data_end_incl = e
        self.filters = filters
        self.decodeparms = decodeparms or []
        self.raw_len = raw_len
        self.dict_bytes = dict_bytes or b""

        d = self.dict_bytes
        # Normalize filter names defensively (some dicts can be oddly formatted)
        self.filters = [ _norm_filter_name(f) for f in (self.filters or []) ]

        self.k_is_image = ((b"/Type/XObject" in d or b"/XObject" in d) and
                           (b"/Subtype/Image" in d or (b"/Subtype" in d and b"/Image" in d))) or \
                          (b"/DCTDecode" in d or b"/JPXDecode" in d or b"/CCITTFaxDecode" in d or b"/JBIG2Decode" in d)
        self.k_is_font = ((b"/Subtype" in d and (b"/Type1C" in d or b"/OpenType" in d or b"/CIDFontType0C" in d)) or
                          (b"/FontFile" in d or b"/FontFile2" in d or b"/FontFile3" in d))
        self.k_is_icc = (b"/ICCBased" in d or b"/Type/ICCBased" in d)
        self.k_is_content = (b"/Length" in d and b"/Subtype" not in d and b"/Type/Metadata" not in d and b"/Type/XRef" not in d and b"/Type/ObjStm" not in d)
        self.k_is_xref_stream = (b"/Type/XRef" in d or b"/XRef" in d)
        self.k_is_objstm = (b"/Type/ObjStm" in d or b"/ObjStm" in d)
        self.k_is_embedded = (b"/Subtype/EmbeddedFile" in d or b"/Type/EmbeddedFile" in d or b"/EF" in d)
        self.k_is_xmp = (b"/Type/Metadata" in d or b"/Subtype/XML" in d or b"/XMP" in d)
        # Streams we should treat as "text-ish" (UTF-8 validation replaces other textiness checks)
        self.k_is_textish = (
            self.k_is_content
            or self.k_is_xmp
            or (b"/Subtype/Text" in d)            # occasional textual subtypes
            or (b"/Subtype/XML" in d)             # alias of k_is_xmp but keep explicit
            or (b"/Subtype/Type1" in d and b"/Metadata" in d)  # stray textual metadata blobs
        )
        
# ----------------------------- Scanner ---------------------------------------

def _scan_pdf_streams(path: str, max_streams: int = 200000) -> Tuple[List[_PDFStream], str]:
    streams: List[_PDFStream] = []
    try:
        size = os.path.getsize(path)
        with open(path, "rb") as fh, mmap.mmap(fh.fileno(), 0, access=mmap.ACCESS_READ) as mm:
            if not PDF_HEADER_RE.match(mm[:16]):
                return [], "pdf: metadata encrypted (bad or missing header)"
            if EOF_RE.search(mm[-2048:]) is None and EOF_RE.search(mm) is None:
                return [], "pdf: metadata encrypted (missing EOF)"

            start = 0
            found = 0
            while True:
                s_idx = mm.find(b"stream", start)
                if s_idx < 0:
                    break

                # Skip when we matched the 'stream' inside 'endstream'
                if s_idx >= 3 and mm[s_idx-3:s_idx] == b"end":
                    start = s_idx + 6
                    continue

                # Require a sane token boundary before 'stream' (space/newline/>)
                if s_idx > 0 and mm[s_idx-1] not in (9, 10, 13, 32, 0x3E):
                    start = s_idx + 6
                    continue

                scan_end = min(size, s_idx + 256)
                cr = mm.find(b"\r", s_idx, scan_end)
                lf = mm.find(b"\n", s_idx, scan_end)
                if cr == -1 and lf == -1:
                    scan_end = min(size, s_idx + 2048)
                    cr = mm.find(b"\r", s_idx, scan_end)
                    lf = mm.find(b"\n", s_idx, scan_end)
                    if cr == -1 and lf == -1:
                         # Fail fast: a 'stream' token must terminate its line with CR/LF.
                         return [], "pdf: structural truncation (unterminated 'stream' line)"
                if cr != -1 and lf != -1 and lf == cr + 1:
                    data_start = lf + 1
                elif lf != -1 and (cr == -1 or lf < cr):
                    data_start = lf + 1
                else:
                    data_start = cr + 1

                e_idx = mm.find(b"endstream", data_start)
                if e_idx < 0:
                     # Fail fast: opened stream not closed before trailer/EOF → poisoned structure.
                     return [], "pdf: structural truncation (missing 'endstream')"

                data_end = e_idx - 1
                while data_end >= data_start and mm[data_end] in (0x0A, 0x0D):
                    data_end -= 1

                look_back_start = max(0, s_idx - 65536)  # 64 KiB window
                slice_back = mm[look_back_start:s_idx]
                m = None
                for match in DICT_BACK_RE.finditer(slice_back):
                    m = match

                dict_bytes = b""
                filters: List[bytes] = []
                dparms: List[Dict[bytes, Any]] = []
                if m:
                    dict_start = look_back_start + m.start()
                    dict_end = look_back_start + m.end()
                    dict_bytes = slice_back[m.start():m.end()]
                    f_m = FILTER_RE.search(dict_bytes)
                    p_m = DECODEPARMS_RE.search(dict_bytes)
                    filters = _parse_filter_names(f_m.group("val")) if f_m else []
                    dparms = _parse_decodeparms(p_m.group("val")) if p_m else []
                else:
                    dict_start = dict_end = s_idx

                raw_len = max(0, (data_end - data_start + 1))
                streams.append(_PDFStream(dict_start, dict_end, data_start, data_end,
                                          filters, dparms, raw_len, dict_bytes))
                found += 1
                if found >= max_streams:
                    break
                start = e_idx + len(b"endstream")
        return streams, ""
    except FileNotFoundError as e:
        return [], f"pdf: io error (ENOENT: {e})"
    except PermissionError as e:
        return [], f"pdf: io error (EPERM: {e})"
    except Exception as e:
        import traceback; traceback.print_exc()
        return [], f"pdf: metadata encrypted (parse error); parse error ({type(e).__name__}: {e})"

# ----------------------- Decoders & Predictors -------------------------------

def _ascii85_decode(data: bytes, budget: int) -> bytes:
    out = base64.a85decode(data, adobe=True)
    return out[:budget] if len(out) > budget else out

def _asciihex_decode(data: bytes, budget: int) -> bytes:
    buf = []
    hexchars = b"0123456789ABCDEFabcdef"
    have_half = False
    half = 0
    i = 0
    L = len(data)
    while i < L:
        c = data[i]; i += 1
        if c in b" \t\r\n\f\0": continue
        if c == ord(">"): break
        if c not in hexchars:
            raise ValueError("ASCIIHex: non-hex char")
        v = int(bytes([c]).decode("ascii"), 16)
        if not have_half:
            half = v; have_half = True
        else:
            buf.append((half << 4) | v); have_half = False
        if len(buf) >= budget: break
    if have_half and len(buf) < budget:
        buf.append(half << 4)
    return bytes(buf)

def _runlength_decode(data: bytes, budget: int) -> bytes:
    out = bytearray()
    i = 0
    L = len(data)
    while i < L and len(out) < budget:
        b = data[i]; i += 1
        if b == 128: break  # EOD
        if b < 128:
            n = b + 1
            if i + n > L: n = max(0, L - i)
            out.extend(data[i:i+n]); i += n
        else:
            if i >= L: break
            val = data[i]; i += 1
            n = 257 - b
            out.extend(bytes([val]) * n)
        if len(out) >= budget: break
    return bytes(out[:budget]) if len(out) > budget else bytes(out)

def _apply_png_predictor(buf: bytes, parms: Dict[bytes, Any]) -> bytes:
    predictor = int(parms.get(b"Predictor", 1) or 1)
    if predictor in (1, 2):
        return buf
    if predictor not in (10, 11, 12, 13, 14, 15):
        return buf

    colors = int(parms.get(b"Colors", 1) or 1)
    bpc = int(parms.get(b"BitsPerComponent", 8) or 8)
    columns = int(parms.get(b"Columns", 1) or 1)
    if columns <= 0 or bpc not in (1,2,4,8,16) or colors <= 0:
        return buf

    bpp = (colors * bpc + 7) // 8
    row_size = bpp * columns
    out = bytearray()
    i = 0
    L = len(buf)
    prev = bytearray(row_size)

    def paeth(a,b,c):
        p = a + b - c
        pa = abs(p - a); pb = abs(p - b); pc = abs(p - c)
        if pa <= pb and pa <= pc: return a
        if pb <= pc: return b
        return c

    while i < L:
        if i >= L: break
        filt = buf[i]; i += 1
        if i + row_size > L:
            break
        row = bytearray(buf[i:i+row_size])
        i += row_size

        if filt == 0:  # None
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
                row[x] = (row[x] + paeth(a,b,c)) & 0xFF

        out.extend(row)
        prev = row
    return bytes(out)

def _decode_supported_filters(raw: bytes,
                              filters: List[bytes],
                              decodeparms: List[Dict[bytes, Any]],
                              budget: int) -> Tuple[Optional[bytes], bool]:
    # If no filters, treat raw as decoded
    if not filters:
        return (raw[:budget] if len(raw) > budget else raw), True

    data = raw
    fully_supported = True

    parms_list = decodeparms if decodeparms else []
    if len(parms_list) not in (0, 1, len(filters)):
        parms_list = []

    # Normalize names once here as well, in case callers didn’t.
    norm_filters = [_norm_filter_name(f) for f in (filters or [])]
    for idx, f in enumerate(norm_filters):
        parms = parms_list[idx] if parms_list and len(parms_list) == len(filters) else (parms_list[0] if parms_list else {})
        try:
            if f == b"ASCII85Decode":
                data = _ascii85_decode(data, budget)
            elif f == b"ASCIIHexDecode":
                data = _asciihex_decode(data, budget)
            elif f == b"RunLengthDecode":
                data = _runlength_decode(data, budget)
            elif f == b"FlateDecode":
                data = zlib.decompress(data)
                if parms:
                    data = _apply_png_predictor(data, parms)
                if len(data) > budget:
                    data = data[:budget]
            else:
                fully_supported = False
                return None, False
        except Exception:
            return None, False

    return data, fully_supported

# ----------------------------- Handler ---------------------------------------

class PDFHandler:
    """
    Stream-aware PDF logic with consistent image trust hashing.

    Strategy:
      - For each suspicious region, pick the **encompassing stream** with MAX overlap.
      - Images: compute a **decoded-pixel hash** by default; if undecodable, fall back to RAW.
      - Cache per-stream hashes, and compare against ctx.trusted_hashes.
      - Other stream types use decoded/RAW χ² as before; outside streams are triaged strictly.
    """
    exts = EXTS

    @staticmethod
    def supports(ext: str, magic: Optional[bytes]) -> bool:
        e = (ext or "").lstrip(".").lower()
        return e in PDFHandler.exts or _looks_like_pdf(magic or b"")

    def decide(self, ctx: FileContext, reg: SuspiciousFileRegion) -> FileAwareDecision:
        if not ctx.fs_root:
            return FileAwareDecision(
                keep_file=True,
                reason="pdf: no fs_root; escalate",
                region_decisions=[
                    RegionDecision(start=s, end=e, keep=True, reason="pdf: no fs_root; escalate")
                    for (s, e) in (reg.byte_ranges or [])
                ] or None,
            )

        ap = os.path.join(ctx.fs_root, ctx.file_path.lstrip("/"))

        # budgets / thresholds
        decompress_budget = int(ctx.params.get("decompress_budget_bytes", 32 * 1024 * 1024))
        raw_budget_small  = min(decompress_budget, 1 * 1024 * 1024)   # outside snippets
        raw_budget_stream = min(decompress_budget, 8 * 1024 * 1024)   # stream payloads (aligns with manifest)
        prelude_slack        = int(ctx.params.get("metadata_prelude_slack_bytes", 32768))

        # image trust mode: **decoded by default**; fall back to RAW if undecodable
        prefer_decoded_image_hash = bool(ctx.params.get("prefer_decoded_image_hash", True))
        debug_prelude = bool(ctx.params.get("debug_pdf_prelude", False))
        debug_textish = bool(ctx.params.get("debug_pdf_textish", False))
        # Extra toggles for deeper triage
        debug_streams = bool(ctx.params.get("debug_pdf_streams", False))
        debug_gaps = bool(ctx.params.get("debug_pdf_gaps", False))
        debug_gap_kinds = bool(ctx.params.get("debug_pdf_gap_kinds", False))
        
        # parse streams
        streams, err = _scan_pdf_streams(ap)
        if debug_textish:
            for st in streams:
                print("[pdf-debug-stream-map]",
                      {"range":[st.data_start, st.data_end_incl],
                       "textish": st.k_is_textish,
                       "image": st.k_is_image,
                       "filters":[f.decode("latin-1","ignore") for f in (st.filters or [])]})
        if err:
            return FileAwareDecision(
                keep_file=True,
                reason=err,
                region_decisions=[
                    RegionDecision(start=s, end=e, keep=True, reason=err)
                    for (s, e) in (reg.byte_ranges or [])
                ] or None,
            )

        file_size = os.path.getsize(ap)
        first_stream_start = min((st.data_start for st in streams), default=1 << 60)
        # preamble allowance near BOF
        marker_win = _compute_binary_marker_window(ap)
        if debug_prelude:
            print(f"[pdf-debug] file={ctx.file_path} first_stream_start="
                  f"{min((st.data_start for st in streams), default=-1)} "
                  f"marker_win={marker_win}")

        def _overlapping_streams(s: int, e: int) -> List[_PDFStream]:
            """
            Return ALL streams that overlap [s,e], sorted by overlap length (desc).
            This lets us detect small, localized edits at the head of any stream.
            """
            if debug_streams:
                print(f"[pdf-debug-overlap] query=[{s},{e}] "
                      f"first_stream_start={first_stream_start} total_streams={len(streams)}")

            out: List[_PDFStream] = []
            for st in streams:
                if not (e < st.data_start or st.data_end_incl < s):
                    out.append(st)
            out.sort(
                key=lambda st: _overlap_len(s, e, st.data_start, st.data_end_incl),
                reverse=True,
            )
            # Extra visibility: list what we will evaluate, in order.
            if debug_streams or debug_gaps:
                try:
                    report = []
                    for st in out[:6]:  # cap to keep log short
                        report.append({
                            "range": [st.data_start, st.data_end_incl],
                            "kind": _stream_kind_label(st),
                            "filters": [f.decode("latin-1","ignore") for f in (st.filters or [])],
                        })
                    print("[pdf-debug-overlap-streams]", {"query":[s,e], "overlap_top": report, "count": len(out)})
                except Exception:
                    pass
            return out

        def _raw_overlap_slice(st: _PDFStream, s: int, e: int, cap: int) -> bytes:
            """
            Read the RAW bytes of st that overlap [s,e], up to cap.
            This lets us test small encrypted patches without whole-stream averaging.
            """
            os_ = max(st.data_start, s)
            oe_ = min(st.data_end_incl, e)
            if oe_ < os_:
                return b""
            return _read_span(ap, os_, oe_, cap=cap)

        # --- stream/member verdict cache (maps stream id -> (keep, reason)) ---
        stream_verdict_cache: Dict[int, Tuple[bool, str]] = {}

        # Helper to give a stable id for caching
        def _sid(st: _PDFStream) -> int:
            return (st.data_start << 1) ^ st.data_end_incl

        # Localized fragment classifier for small overlaps (prevents whole-stream dilution)
        def _local_frag_looks_encrypted(frag: bytes) -> bool:
            if not frag:
                return False
            chi2 = _chi2_uniform(frag)
            ascii_r = _ascii_ratio(frag)
            toks = _token_hits(frag)
            # Tight because fragments are small; ciphertext should be near-uniform and low-ascii and token-poor
            return (chi2 <= 220.0) and (ascii_r < 0.22) and (toks <= 1)

        # Member/stream-level evaluator (ZIP-like): compute once, reuse
        def _eval_stream(st: _PDFStream) -> Tuple[bool, str]:
            sid = _sid(st)
            # Cached verdicts are authoritative and inherited by all overlapping regions.
            if sid in stream_verdict_cache:
                if debug_streams:
                    k, r = stream_verdict_cache[sid]
                    print("[pdf-debug-stream-cache-hit]", {
                        "range": [st.data_start, st.data_end_incl],
                        "keep": k,
                        "reason": r,
                        "filters": [f.decode('latin-1','ignore') for f in (st.filters or [])],
                        "supported": all(_norm_filter_name(f) in SUPPORTED_FILTERS for f in (st.filters or [])),
                        "types": {
                            "image": st.k_is_image, "textish": st.k_is_textish, "font": st.k_is_font,
                            "icc": st.k_is_icc, "xref": st.k_is_xref_stream, "objstm": st.k_is_objstm, "embedded": st.k_is_embedded
                        }
                    })
                return stream_verdict_cache[sid]

            raw = _read_span(ap, st.data_start, st.data_end_incl, cap=raw_budget_stream)

            # Quick escalate for Flate streams with invalid zlib header at the very start
            if _declares_flate(st):
                head2 = _read_span(ap, st.data_start, st.data_start + 1, cap=2)
                if len(head2) >= 2 and not _zlib_header_ok(head2):
                    if debug_streams:
                        print("[pdf-debug-stream] bad zlib header", {
                            "range": [st.data_start, st.data_end_incl],
                            "filters": [f.decode('latin-1','ignore') for f in (st.filters or [])]
                        })
                    stream_verdict_cache[sid] = (True, "pdf: nested metadata encrypted (stream undecodable)")
                    return stream_verdict_cache[sid]

            decoded, fully_supported = _decode_supported_filters(
                raw, st.filters or [], st.decodeparms or [], budget=raw_budget_stream
            )
            if debug_streams:
                print("[pdf-debug-stream-decode]", {
                    "range": [st.data_start, st.data_end_incl],
                    "raw_len": len(raw),
                    "decoded_len": (len(decoded) if decoded is not None else None),
                    "filters": [f.decode('latin-1','ignore') for f in (st.filters or [])],
                    "fully_supported": fully_supported,
                    "supported_all": all(_norm_filter_name(f) in SUPPORTED_FILTERS for f in (st.filters or [])),
                    "types": {
                        "image": st.k_is_image, "textish": st.k_is_textish, "font": st.k_is_font,
                        "icc": st.k_is_icc, "xref": st.k_is_xref_stream, "objstm": st.k_is_objstm, "embedded": st.k_is_embedded
                    }
                })
            # Deterministic escalation: if filters are supported but decode failed
            if _filters_supported(st.filters or []) and (decoded is None or not fully_supported):
                stream_verdict_cache[sid] = (True, "pdf: nested metadata encrypted (stream undecodable)")
                if debug_streams:
                    print("[pdf-debug-stream-keep] decode_failed_escalate", {
                        "range": [st.data_start, st.data_end_incl]
                    })
                return stream_verdict_cache[sid]

            # --- TEXT-ISH PATH (operand-level validation) ---
            if st.k_is_textish:
                data_for_text = decoded if (decoded is not None and fully_supported) else raw
                # Validate only string operands; skip inline image payloads.
                why = _content_operand_anomaly(data_for_text or b"", ctx=ctx, debug=(debug_textish or debug_streams))
                if why is not None:
                    stream_verdict_cache[sid] = (True, why)
                    if debug_textish or debug_streams:
                        print("[pdf-debug-textish-keep]", {
                            "range": [st.data_start, st.data_end_incl],
                            "reason": why
                        })
                else:
                    stream_verdict_cache[sid] = (False, "pdf: text stream operands benign")
                    if debug_textish or debug_streams:
                        print("[pdf-debug-textish-benign]", {
                            "range": [st.data_start, st.data_end_incl]
                        })
                return stream_verdict_cache[sid]

            # --- Non text-ish deterministic path (no χ², no fragment probes) ---

            # Heuristic guardrail for untyped, no-filter streams:
            # Neither human-readable (content-ish) nor application-attributed -> suspicious.
            is_untyped = not (st.k_is_image or st.k_is_font or st.k_is_icc or st.k_is_xref_stream
                              or st.k_is_objstm or st.k_is_embedded or st.k_is_xmp or st.k_is_content)
            no_filters = not (st.filters or [])
             
            # Typed streams
            if st.k_is_embedded:
                stream_verdict_cache[sid] = (True, "pdf: embedded file present; delegate to inner format")
                if debug_streams:
                    print("[pdf-debug-stream-keep] embedded_file", {"range": [st.data_start, st.data_end_incl]})
                return stream_verdict_cache[sid]

            if st.k_is_image:
                # trust on content hash (decoded preferred)
                if decoded is not None and fully_supported:
                    h = _sha256(decoded); used = "decoded"
                else:
                    h = _sha256(raw);     used = "raw"
                if ctx.trusted_hashes and h in ctx.trusted_hashes:
                    stream_verdict_cache[sid] = (False, f"pdf: image stream (trusted {used}) sha256={h}")
                    if debug_streams:
                        print("[pdf-debug-image-benign]", {"range": [st.data_start, st.data_end_incl], "hash_used": used, "trusted": True})
                else:
                    stream_verdict_cache[sid] = (True,  f"pdf: image stream (untrusted {used}) sha256={h}")
                    if debug_streams:
                        print("[pdf-debug-image-keep]", {"range": [st.data_start, st.data_end_incl], "hash_used": used, "trusted": False})
                return stream_verdict_cache[sid]

            # ICC remains benign; fonts get decode-and-validate (no trust-on-hash).
            if st.k_is_icc:
                stream_verdict_cache[sid] = (False, "pdf: icc stream (benign)")
                if debug_streams:
                    print("[pdf-debug-stream-benign] icc", {"range": [st.data_start, st.data_end_incl]})
                return stream_verdict_cache[sid]

            if st.k_is_font:
                if debug_streams or debug_gaps:
                    print("[pdf-debug-font] enter", {
                        "range": [st.data_start, st.data_end_incl],
                        "filters": [f.decode("latin-1","ignore") for f in (st.filters or [])],
                        "decodeparms": st.decodeparms,
                    })
                # extra visibility: header at offset 0
                try:
                    raw_head = _read_span(ap, st.data_start, st.data_start + 1, cap=2)
                    if debug_streams:
                        print("[pdf-debug-font-zlib-hdr]", {"has_zlib_hdr_at_0": bool(len(raw_head) >= 2 and _zlib_header_ok(raw_head[:2]))})
                except Exception:
                    pass
                   
                # 1) Read raw bytes
                raw = _read_span(ap, st.data_start, st.data_end_incl, cap=raw_budget_stream)

                # 2) Decode if filters say so OR if raw starts with a plausible zlib header
                dec = None
                used_decoded = False
                try:
                    if st.filters:
                        dec, fully_supported = _decode_supported_filters(raw, st.filters or [], st.decodeparms or [], budget=raw_budget_stream)
                        used_decoded = (dec is not None and fully_supported)
                    elif len(raw) >= 2 and _zlib_header_ok(raw[:2]):
                        try:
                            dec = zlib.decompress(raw)
                        except Exception as _zerr:
                            # If it looks like zlib but won't inflate, treat as suspicious.
                            stream_verdict_cache[sid] = (True, "pdf: font payload undecodable (zlib header present)")
                            if debug_streams:
                                print("[pdf-debug-font-keep]", {
                                    "reason": "zlib_hdr_but_decompress_failed",
                                    "range": [st.data_start, st.data_end_incl],
                                })
                            return stream_verdict_cache[sid]
                        if len(dec) > raw_budget_stream:
                            dec = dec[:raw_budget_stream]
                        used_decoded = True
                except Exception:
                    dec = None
                    used_decoded = False

                if debug_streams:
                    try:
                        print("[pdf-debug-font-bytes]", {
                            "range": [st.data_start, st.data_end_incl],
                            "raw_len": len(raw),
                            "decoded": used_decoded,
                            "dec_len": (len(dec) if dec is not None else None),
                        })
                    except Exception:
                        pass

                # 3) If filters are supported but we couldn’t decode => escalate
                if st.filters and _filters_supported(st.filters or []) and not used_decoded:
                    stream_verdict_cache[sid] = (True, "pdf: nested metadata encrypted (stream undecodable)")
                    if debug_streams:
                        print("[pdf-debug-font-keep]", {"reason": "decode_failed", "range": [st.data_start, st.data_end_incl]})
                    return stream_verdict_cache[sid]

                # --- continue with deeper font triage (always) ---
                data = dec if used_decoded else raw
 
 
                # 4a) Try 'inflate and check' FIRST (parity with literal-string path).
                #     If we can inflate an inner island to readable text or PDF ops,
                #     treat as structured/benign rather than ciphertext.
                try:
                    ok_island, sample = _inflate_any(data or b"", max_tries=6, want_ops=True)
                except Exception:
                    ok_island, sample = (False, None)
                if debug_streams:
                    try:
                        print("[pdf-debug-font-inflate-any]", {
                            "range": [st.data_start, st.data_end_incl],
                            "ok": bool(ok_island),
                            "sample_prefix": (sample[:64].hex() if sample else "")
                        })
                    except Exception:
                        pass
                if ok_island:
                    stream_verdict_cache[sid] = (False, "pdf: font stream contains structured compressed data (benign)")
                    if debug_streams:
                        print("[pdf-debug-font-benign]", {
                            "range": [st.data_start, st.data_end_incl],
                            "reason": "inflate_any_ok"
                        })
                    return stream_verdict_cache[sid]

                # 4b) Light structure checks for common font containers
                is_sfnt = _looks_like_sfnt_font(data or b"")
                is_cff  = _looks_like_cff_font(data or b"")
                looks_font = (is_sfnt or is_cff)

                if debug_streams:
                    try:
                        stats = {
                            "ascii_ratio": _ascii_ratio(data or b""),
                            "chi2": _chi2_uniform(data or b""),
                            "entropy": _shannon_entropy((data or b"")[:4096]),
                            "zlib_cr": _zlib_compress_ratio((data or b"")[:2048]),
                        }
                        print("[pdf-debug-font-shape]", {
                            "range": [st.data_start, st.data_end_incl],
                            "decoded": used_decoded,
                            "is_sfnt": is_sfnt,
                            "is_cff": is_cff,
                            **stats
                        })
                    except Exception:
                        pass

                # 5) Parity with literal strings: if it doesn't look like a font,
                #    apply the same fused-encryption rule before generic randomness.
                if not looks_font and _looks_encrypted_fused(data or b"", min_len=48):
                    stream_verdict_cache[sid] = (True, "pdf: font payload looks encrypted")
                    if debug_streams:
                        print("[pdf-debug-font-keep]", {
                            "reason": "fused_encrypted_like",
                            "range": [st.data_start, st.data_end_incl],
                            "decoded": used_decoded,
                        })
                    return stream_verdict_cache[sid]

                # 6) Final fallback: randomness/ciphertext heuristic tuned for streams
                #    (parity with inter-stream gap rule so uniform-ish blobs don't slip by).
                if (not looks_font) and _looks_encrypted_fused(
                        data or b"",
                        min_len=512,
                        ascii_max=0.55,
                        chi2_max=300.0,
                        entropy_min=7.5,
                        cr_min=0.98):
                    stream_verdict_cache[sid] = (True, "pdf: font payload looks encrypted")
                    if debug_streams:
                        print("[pdf-debug-font-keep]", {
                            "reason": "fused_encrypted_like_stream",
                            "range": [st.data_start, st.data_end_incl],
                            "decoded": used_decoded,
                        })
                    return stream_verdict_cache[sid]

                # Otherwise: treat as benign font
                stream_verdict_cache[sid] = (False, "pdf: font stream (benign)")
                if debug_streams:
                    try:
                        print("[pdf-debug-stream-benign] font", {
                            "range": [st.data_start, st.data_end_incl],
                            "decoded": used_decoded,
                            "looks_font": looks_font,
                            "is_sfnt": is_sfnt,
                            "is_cff": is_cff,
                        })
                    except Exception:
                        pass
                return stream_verdict_cache[sid]
            
            # New path: unattributed, no-filter streams
            if is_untyped and no_filters:
                # Use RAW (there is no decoding to do).
                data_for_probe = raw
 

                # Case A: Looks like content -> run operand checks on the raw bytes.
                if _looks_like_contentish_raw(data_for_probe):
                    if debug_streams or debug_gaps:
                        head = data_for_probe[:512]
                        print("[pdf-debug-untyped-contentish]", {
                            "range": [st.data_start, st.data_end_incl],
                            "head_ascii": _ascii_ratio(head),
                            "token_hits": _pdf_textop_hits(data_for_probe),
                            "paren_ok": _paren_balance_ok(data_for_probe, limit=200_000)
                        })
                    why = _content_operand_anomaly(data_for_probe or b"", ctx=ctx, debug=debug_streams)
                    if why is not None:
                        stream_verdict_cache[sid] = (True, why)
                        if debug_streams:
                            print("[pdf-debug-untyped-keep] contentish_raw", {
                                "range": [st.data_start, st.data_end_incl],
                                "reason": why
                            })
                        return stream_verdict_cache[sid]

                    # Summarize to get spans we must ignore (inline image + string operands)
                    summary = _summarize_content_stream(data_for_probe or b"")
                    if debug_streams or debug_gaps:
                        # Show counts and first few spans to verify masking
                        print("[pdf-debug-summarize-content]", {
                            "range": [st.data_start, st.data_end_incl],
                            "len": summary.get("len"),
                            "comments": summary.get("comments_count"),
                            "literal_count": summary.get("literal_count"),
                            "hex_count": summary.get("hex_count"),
                            "ii_count": summary.get("ii_count"),
                            "lit_spans_sample": (summary.get("lit_spans") or [])[:3],
                            "hex_spans_sample": (summary.get("hex_spans") or [])[:3],
                            "ii_payload_spans_sample": (summary.get("ii_payload_spans") or [])[:3],
                        })
                    ii_spans  = summary.get("ii_payload_spans") or []
                    lit_spans = summary.get("lit_spans") or []
                    hex_spans = summary.get("hex_spans") or []
                    mask_spans = ii_spans + lit_spans + hex_spans

                    # Context-aware inflate probe *outside* operands/payloads
                    ok_inflate, info = _inflate_probe_excluding_spans(
                        data_for_probe or b"", mask_spans, max_tries=12, _dbg=(debug_streams or debug_gaps)
                    )
 
                    # --- NEW: principled structural gate before escalating on inflate ---
                    # Derive ASCII-constrained zone share and content-signal from the summary.
                    total_len = int(summary.get("len") or 0)
                    comments_bytes = int(summary.get("comments_bytes") or 0)
                    literal_bytes  = int(summary.get("literal_bytes") or 0)
                    hex_bytes      = int(summary.get("hex_bytes") or 0)
                    ii_payload_bytes = int(summary.get("ii_payload_bytes") or 0)
                    # Inline-image *dict* bytes are part of ASCII-constrained syntax.
                    ascii_zone_bytes = max(0, total_len - (comments_bytes + literal_bytes + hex_bytes + ii_payload_bytes))
                    ascii_zone_share = (ascii_zone_bytes / total_len) if total_len > 0 else 0.0
 
                    ops_total = int(summary.get("textop_hits") or 0)
                    lit_cnt   = int(summary.get("literal_count") or 0)
                    hex_cnt   = int(summary.get("hex_count") or 0)
                    content_signal = (ops_total >= 3) or ((lit_cnt + hex_cnt) >= 4)
 
                    if debug_streams or debug_gaps:
                        print("[pdf-debug-untyped-struct]", {
                            "range": [st.data_start, st.data_end_incl],
                            "ascii_zone_share": round(ascii_zone_share, 3),
                            "ops_total": ops_total, "lit_cnt": lit_cnt, "hex_cnt": hex_cnt,
                            "inflate_found": bool(ok_inflate),
                            "inflate_texty": bool(info.get("texty") if ok_inflate else False),
                            "inflate_ops": int(info.get("ops") if ok_inflate else 0)
                        })
 
                    if ok_inflate:
                        # Escalate only if: no structural content signal AND ASCII zone dominates,
                        # AND the inflated member itself isn't texty/ops-ish.
                        if (not content_signal) and (ascii_zone_share >= 0.60) and not (info.get("texty") or (info.get("ops", 0) >= 3)):
                            stream_verdict_cache[sid] = (True, "pdf: content stream embeds compressed blob (outside operands)")
                            if debug_streams:
                                meta = dict(info); meta.update({
                                    "range": [st.data_start, st.data_end_incl],
                                    "ascii_zone_share": round(ascii_zone_share, 3),
                                    "content_signal": content_signal,
                                    "masked_spans_counts": {"ii": len(ii_spans), "lit": len(lit_spans), "hex": len(hex_spans)},
                                })
                                print("[pdf-debug-untyped-keep] inflate-outside-operands-structural", meta)
                        else:
                            # Structural content present => treat as benign.
                            stream_verdict_cache[sid] = (False, "pdf: inflate allowed outside operands (structural content present)")
                            if debug_streams:
                                meta = dict(info); meta.update({
                                    "range": [st.data_start, st.data_end_incl],
                                    "ascii_zone_share": round(ascii_zone_share, 3),
                                    "content_signal": content_signal,
                                    "masked_spans_counts": {"ii": len(ii_spans), "lit": len(lit_spans), "hex": len(hex_spans)},
                                })
                                print("[pdf-debug-untyped-benign] inflate-outside-operands-structural", meta)
                        return stream_verdict_cache[sid]
                    else:
                        if debug_streams:
                            meta = dict(info); meta.update({
                                "range": [st.data_start, st.data_end_incl],
                                "ascii_zone_share": round(ascii_zone_share, 3),
                                "content_signal": content_signal,
                                "masked_spans_counts": {"ii": len(ii_spans), "lit": len(lit_spans), "hex": len(hex_spans)},
                            })
                            print("[pdf-debug-untyped-benign] inflate-allowed-structural", meta)

                    # MEMBER-FIRST OVERRIDE: if this stream hosts broken embedded zlib,
                    # inherit suspicion to any overlapping region inside this member.
                    member_broken, zhits = _member_has_broken_zlib(data_for_probe or b"")
                    if member_broken:
                        if debug_streams:
                            print("[pdf-debug-stream-decode]", {
                                "range": [st.data_start, st.data_end_incl],
                                "raw_len": len(data_for_probe or b""),
                                "decoded_len": len(data_for_probe or b""),
                                "filters": [f.decode('latin-1','ignore') for f in (st.filters or [])],
                                "fully_supported": True,
                                "supported_all": True,
                                "types": {
                                    "image": st.k_is_image, "textish": st.k_is_textish, "font": st.k_is_font,
                                    "icc": st.k_is_icc, "xref": st.k_is_xref_stream, "objstm": st.k_is_objstm, "embedded": st.k_is_embedded
                                },
                                "embedded_zlib": zhits,
                            })
                        stream_verdict_cache[sid] = (True, "pdf: member has broken zlib (inherit to region)")
                        return stream_verdict_cache[sid]
                    
                # Summarize content to locate inline image payload spans (BI..ID..EI)
                summary = _summarize_content_stream(data_for_probe or b"")
                ii_spans = summary.get("ii_payload_spans") or []

                # Probe for compressed blobs *outside* operands and *outside* inline-image payloads.
                ok_inflate, info = _inflate_probe_excluding_spans(data_for_probe or b"", ii_spans, max_tries=12)
                if ok_inflate and not (info.get("texty") or (info.get("ops", 0) >= 4)):
                    stream_verdict_cache[sid] = (True, "pdf: content stream embeds compressed blob (outside operands)")
                    if debug_streams:
                        meta = dict(info); meta["range"] = [st.data_start, st.data_end_incl]
                        meta["ii_payload_spans"] = ii_spans
                        print("[pdf-debug-untyped-keep] inflate-outside-operands", meta)
                    return stream_verdict_cache[sid]

                # otherwise benign contentish raw
                stream_verdict_cache[sid] = (False, "pdf: text stream operands benign (raw-contentish)")
                if debug_streams:
                    print("[pdf-debug-untyped-benign] contentish_raw", {
                        "range": [st.data_start, st.data_end_incl],
                        "ii_count": summary.get("ii_count"),
                        "masked_spans_counts": {"ii": len(ii_spans), "lit": len(lit_spans), "hex": len(hex_spans)}
                    })
                return stream_verdict_cache[sid]
 
                # Case B: Not content-ish → check for ciphertext-like random blob.
                if _looks_random_bytes(data_for_probe):
                    stream_verdict_cache[sid] = (True, "pdf: nested metadata encrypted (unattributed stream)")
                    if debug_streams:
                        print("[pdf-debug-untyped-keep] random_blob", {
                            "range": [st.data_start, st.data_end_incl],
                            "ascii_ratio": _ascii_ratio(data_for_probe),
                            "chi2": _chi2_uniform(data_for_probe),
                        })
                    return stream_verdict_cache[sid]
 
                # Otherwise, tolerate as generic untyped stream (benign).
                stream_verdict_cache[sid] = (False, "pdf: generic untyped stream (benign)")
                if debug_streams:
                    print("[pdf-debug-stream-benign] untyped_no_filters", {
                        "range": [st.data_start, st.data_end_incl]
                    })
                return stream_verdict_cache[sid]
            
            # XRef/ObjStm/Generic non-textish:
            # If filters are supported but decode failed we already escalated above.
            # Otherwise treat as benign (deterministic, no entropy).
            stream_verdict_cache[sid] = (False, "pdf: non-textish stream (benign)")
            if debug_streams:
                print("[pdf-debug-stream-benign] generic_non_textish", {"range": [st.data_start, st.data_end_incl]})
            return stream_verdict_cache[sid]

        # --- helper: run preamble checks on a specific slice [ps,pe] ---
        # (plus a helper to find gaps outside streams)
        def _compute_gap_slices(ps: int, pe: int, overlapping: List[_PDFStream]) -> List[Tuple[int,int]]:
            """
            Within [ps,pe], return the list of sub-intervals that are **outside** all
            overlapping stream payloads (data_start..data_end_incl).
            """
            if ps > pe:
                return []
            cov = []
            for st in overlapping:
                cov.append((max(ps, st.data_start), min(pe, st.data_end_incl)))
            cov = sorted([(a,b) for (a,b) in cov if a <= b])
            gaps = []
            cur = ps
            for a,b in cov:
                if cur < a: gaps.append((cur, a-1))
                cur = max(cur, b+1)
            if cur <= pe: gaps.append((cur, pe))
            if debug_gaps:
                print(f"[pdf-debug-gap-slices] region=[{ps},{pe}] gaps={gaps}")
            return gaps

        def _preamble_check_slice(ps: int, pe: int) -> Tuple[bool, str, bool]:
            """
            Return (keep, reason, ran_checks) for a pre-stream slice [ps,pe].
            Mirrors the logic from the 'outside-stream' branch so regions that
            straddle the first stream still get proper preamble semantics.
            """
            # Only treat as "preamble" inside a tight metadata zone around BOF.
            # This prevents 'prelude string undecodable' from firing far into the file.
            _prelude_cap = 2048
            meta_limit = min(first_stream_start + prelude_slack, first_stream_start + _prelude_cap)
            if ps >= meta_limit:
                if debug_prelude:
                    print(f"[pdf-debug-pre-slice] skip (beyond meta_limit) region=[{ps},{pe}] meta_limit={meta_limit}")
                return False, "", False
            if ps > pe:
                return False, "", False

            # If fully in the allowed binary marker window → benign
            if marker_win != (-1, -1):
                aw_lo, aw_hi = marker_win
                if ps >= aw_lo and pe <= aw_hi:
                    if debug_prelude:
                        print(f"[pdf-debug] pre-slice [{ps},{pe}] -> benign: marker-window overlap {marker_win}")
                    return False, "pdf: binary header marker (benign)", True

            ctx_buf, base_off = _read_ctx(ap, ps, pe, radius=16384, cap=65536)
            if debug_prelude:
                print(f"[pdf-debug-pre-slice] region=[{ps},{pe}] base_off={base_off} len={len(ctx_buf)} marker_win={marker_win}")
            
            # Comment high-bit anomaly past marker window
            why_c = _comment_highbit_anomaly(ctx_buf, base_off, ps, pe, marker_win)
            if why_c is not None:
                if debug_prelude:
                    print(f"[pdf-debug] pre-slice [{ps},{pe}] -> keep: {why_c}")
                return True, why_c, True

            # Header / obj / xref+trailer / startxref semantics (only if slice covers BOF-ish)
            kept_sem = False
            if ps < 1024:
                ok, why = _validate_header(ctx_buf[:4096])
                if not ok:
                    if debug_prelude:
                        print(f"[pdf-debug-pre-slice] header_anomaly: {why}")
                    return True, f"pdf: prelude header anomaly ({why})", True
                kept_sem = True
            if not kept_sem:
                # Use region midpoint within the context to decide object enclosure
                rel_s = max(0, ps - base_off)
                rel_e = min(len(ctx_buf) - 1, pe - base_off)
                rel_mid = (rel_s + rel_e) // 2 if (0 <= rel_s <= rel_e) else 0
                rng = _find_enclosing_obj_around(ctx_buf, rel_mid)
                if rng:
                    ok, why = _validate_obj_nonstream(ctx_buf[rng[0]:rng[1]])
                    if not ok:
                        if debug_prelude:
                            print(f"[pdf-debug-pre-slice] obj_anomaly: {why}")
                        return True, f"pdf: prelude object anomaly ({why})", True
            if not kept_sem:
                xr = _find_xref_trailer(ctx_buf)
                if xr:
                    ok, why = _validate_xref_trailer(ctx_buf[xr[0]:xr[1]])
                    if not ok:
                        if debug_prelude:
                            print(f"[pdf-debug-pre-slice] xref_trailer_anomaly: {why}")
                        return True, f"pdf: prelude xref/trailer anomaly ({why})", True
            if not kept_sem:
                sx = _find_startxref(ctx_buf)
                if sx:
                    ok, why = _validate_startxref(ctx_buf[sx[0]:sx[1]], os.path.getsize(ap))
                    if not ok:
                        if debug_prelude:
                            print(f"[pdf-debug-pre-slice] startxref_anomaly: {why}")
                        return True, f"pdf: prelude startxref anomaly ({why})", True

            # Token-level semantics
            why = _prelude_token_semantics(ctx_buf, base_off, ps, pe)
            if why is not None:
                if debug_prelude:
                    print(f"[pdf-debug] pre-slice [{ps},{pe}] -> keep: {why}")
                return True, why, True

            # ASCII-constrained pass
            why2 = _prelude_ascii_constrained_check(ctx_buf, base_off, ps, pe, debug=debug_prelude)
            if debug_prelude:
                print("[pdf-debug-prelude-ascii-call]", {
                    "region": [ps, pe],
                    "base_off": base_off,
                    "ran": True,
                    "reason": (why2 or "")
                })
            if why2 is not None:
                if debug_prelude:
                    print(f"[pdf-debug] pre-slice [{ps},{pe}] -> keep: {why2}")
                return True, why2, True
            # Deterministic only: if no anomaly triggered, treat as benign prelude slice
            if debug_prelude:
                print(f"[pdf-debug] pre-slice [{ps},{pe}] -> benign: syntactically valid")
            return False, "pdf: prelude syntactically valid", True

        # Cache stream hashes by (start,end,mode)
        stream_hash_cache: Dict[Tuple[int, int, bool], str] = {}

        def _hash_image_stream(st: _PDFStream) -> Tuple[str, bool]:
            """
            Return (hash, used_decoded) for the whole stream payload with an 8 MiB cap.
            If prefer_decoded_image_hash and filters fully supported, hash decoded bytes
            (post Flate/ASCII85/ASCIIHex/RunLength + PNG predictor). Else hash raw.
            """
            key = (st.data_start, st.data_end_incl, bool(prefer_decoded_image_hash))
            if key in stream_hash_cache:
                h = stream_hash_cache[key]
                return h, prefer_decoded_image_hash

            raw = _read_span(ap, st.data_start, st.data_end_incl, cap=raw_budget_stream)

            used_decoded = False
            if prefer_decoded_image_hash:
                decoded, fully_supported = _decode_supported_filters(
                    raw, st.filters or [], st.decodeparms or [], budget=raw_budget_stream
                )
                if decoded is not None and fully_supported:
                    h = _sha256(decoded)
                    used_decoded = True
                else:
                    h = _sha256(raw)
            else:
                h = _sha256(raw)

            stream_hash_cache[key] = h
            return h, used_decoded

        region_out: List[RegionDecision] = []
        any_keep = False
        NESTED_UNDEC_REASON = "pdf: nested metadata encrypted (stream undecodable)"

        for (s, e) in (reg.byte_ranges or []):
            keep = False
            reason = "pdf: benign"
            try:
                s0, e0 = _clip(int(s), int(e), 0, max(0, file_size - 1))
                print(f"[pdf-debug] s0={s0}, e0={e0}")
                if s0 > e0:
                    region_out.append(RegionDecision(start=int(s), end=int(e), keep=False, reason="pdf: empty"))
                    continue

                sts = _overlapping_streams(s0, e0)

                # NEW: If the region includes bytes before the first stream, run preamble checks
                pre_keep = False
                pre_reason = ""
                pre_ran = False
                if s0 < first_stream_start:
                    pre_s = s0
                    pre_e = min(e0, first_stream_start - 1)
                    pre_keep, pre_reason, pre_ran = _preamble_check_slice(pre_s, pre_e)
                    if debug_prelude:
                        print(f"[pdf-debug-region-prelude] region=[{s0},{e0}] "
                              f"pre_s=[{pre_s},{pre_e}] keep={pre_keep} reason={pre_reason!s}")

                # Outside streams: strict triage
                if not sts:
                    print(f"[pdf-debug] chk 4-1")
                    # --- NEW: prelude semantic validators ---
                    # BEFORE doing gap-kind heuristics, probe the absolute zone with a large radius.
                    # If the offset sits inside a literal/hex string, apply the fused rule (parity with content streams).
                    try:
                        zp = _zone_at_absolute_offset(ap, s0, radius=262144)
                        if debug_prelude:
                            print("[pdf-debug-abs-zone]", {
                                "region": [s0, e0],
                                "zone": zp.get("zone"),
                                "obj_range": zp.get("obj_range")
                            })
                        if zp.get("zone") in ("literal_string","hex_string"):
                            body = zp.get("body") or b""
                            if _looks_encrypted_literal_or_hex(body, is_hex=(zp["zone"] == "hex_string")):
                                keep = True
                                reason = "pdf: prelude data encrypted"
                                if debug_prelude or debug_gaps:
                                    print("[pdf-debug-prelude-zone-keep]", {
                                        "region": [s0, e0],
                                        "zone": zp.get("zone"),
                                        "obj_range": zp.get("obj_range")
                                    })
                                any_keep = any_keep or keep
                                region_out.append(RegionDecision(start=int(s), end=int(e), keep=bool(keep), reason=str(reason)))
                                continue
                    except Exception:
                        # If the absolute-zone probe fails for any reason, fall back to the normal path.
                        pass
                    ctx_buf, base_off = _read_ctx(ap, s0, e0, radius=16384, cap=65536)
                    rel_s = max(0, s0 - base_off)
                    rel_e = min(len(ctx_buf) - 1, e0 - base_off)
                    if debug_prelude:
                        print(f"[pdf-debug] region=[{s0},{e0}] outside-stream "
                              f"rel=[{rel_s},{rel_e}] base_off={base_off}")

                    # If region is fully contained within the allowed binary marker window, treat as benign.
                    if marker_win != (-1, -1):
                        aw_lo, aw_hi = marker_win
                        # Be strict: only benign if the suspicious slice lies entirely within the marker window.
                        if s0 >= aw_lo and e0 <= aw_hi:
                            keep = False
                            reason = "pdf: binary header marker (benign)"
                            if debug_prelude:
                                print(f"[pdf-debug]  -> benign: marker-window overlap {marker_win}")
                            any_keep = any_keep or keep
                            region_out.append(RegionDecision(start=int(s), end=int(e), keep=bool(keep), reason=str(reason)))
                            continue

                    # Comment high-bit anomalies beyond the marker window?
                    why_c = _comment_highbit_anomaly(ctx_buf, base_off, s0, e0, marker_win)
                    if why_c is not None:
                        keep = True
                        reason = why_c
                        if debug_prelude:
                            print(f"[pdf-debug]  -> keep: {reason}")
                        any_keep = any_keep or keep
                        region_out.append(RegionDecision(start=int(s), end=int(e), keep=bool(keep), reason=str(reason)))
                        continue

                    # Try entity kinds in order of likelihood near file start:
                    kept_semantic = False
                    keep_reason = ""
                    # Header near BOF
                    if s0 < 1024:
                        ok, why = _validate_header(ctx_buf[:4096])
                        if not ok:
                            keep = True; reason = f"pdf: prelude header anomaly ({why})"
                            kept_semantic = True
                            if debug_prelude:
                                print(f"[pdf-debug]  -> keep: {reason}")
                    if not kept_semantic:
                        # Enclosing non-stream object (use midpoint of region inside this ctx window)
                        rel_s = max(0, s0 - base_off)
                        rel_e = min(len(ctx_buf) - 1, e0 - base_off)
                        rel_mid = (rel_s + rel_e) // 2 if (0 <= rel_s <= rel_e) else 0
                        rng = _find_enclosing_obj_around(ctx_buf, rel_mid)
                        if rng:
                            ok, why = _validate_obj_nonstream(ctx_buf[rng[0]:rng[1]])
                            if not ok:
                                keep = True; reason = f"pdf: prelude object anomaly ({why})"
                                kept_semantic = True
                                if debug_prelude:
                                    print(f"[pdf-debug]  -> keep: {reason}")
                    if not kept_semantic:
                        # xref + trailer block
                        xr = _find_xref_trailer(ctx_buf)
                        if xr:
                            ok, why = _validate_xref_trailer(ctx_buf[xr[0]:xr[1]])
                            if not ok:
                                keep = True; reason = f"pdf: prelude xref/trailer anomaly ({why})"
                                kept_semantic = True
                                if debug_prelude:
                                    print(f"[pdf-debug]  -> keep: {reason}")
                    if not kept_semantic:
                        # startxref segment
                        sx = _find_startxref(ctx_buf)
                        if sx:
                            ok, why = _validate_startxref(ctx_buf[sx[0]:sx[1]], os.path.getsize(ap))
                            if not ok:
                                keep = True; reason = f"pdf: prelude startxref anomaly ({why})"
                                kept_semantic = True
                                if debug_prelude:
                                    print(f"[pdf-debug]  -> keep: {reason}")

                    if kept_semantic:
                        any_keep = any_keep or keep
                        region_out.append(RegionDecision(start=int(s), end=int(e), keep=bool(keep), reason=str(reason)))
                        continue

                    # Token-level semantics on overlapping entities only
                    why = _prelude_token_semantics(ctx_buf, base_off, s0, e0)
                    if why is not None:
                        keep = True
                        reason = why
                        if debug_prelude:
                            print(f"[pdf-debug]  -> keep: {reason}")
                        any_keep = any_keep or keep
                        region_out.append(
                            RegionDecision(start=int(s), end=int(e), keep=bool(keep), reason=str(reason))
                        )
                        continue

                    # ASCII-constrained pass: outside strings/comments/hex, prelude must be ASCII.
                    # This is robust to tiny ciphertext flips in headers/xref/obj scaffolding.
                    why2 = _prelude_ascii_constrained_check(ctx_buf, base_off, s0, e0, debug=debug_prelude)
                    if debug_prelude:
                        print("[pdf-debug-pre-slice-ascii-call]", {
                            "slice": [s0, e0],
                            "base_off": base_off,
                            "ran": True,
                            "reason": (why2 or "")
                        })
                    if why2 is not None:
                        keep = True
                        reason = why2
                        if debug_prelude:
                            print(f"[pdf-debug]  -> keep: {reason}")
                        any_keep = any_keep or keep
                        region_out.append(
                            RegionDecision(start=int(s), end=int(e), keep=bool(keep), reason=str(reason))
                        )
                        # When we *do* keep, also dump gap-kind context to help attribution
                        if debug_gap_kinds or debug_gaps:
                            kind, extra = _classify_gap_kind(ap, s0, e0, first_stream_start, marker_win)
                            print("[pdf-debug-gap-kind]", {
                                "region": [s0, e0],
                                "kind": kind,
                                **(extra or {})
                            })
                     
                    # FN-oriented: if no anomaly fired outside-stream, still record what this gap looked like
                    else:
                        if debug_gap_kinds or debug_gaps:
                            kind, extra = _classify_gap_kind(ap, s0, e0, first_stream_start, marker_win)
                            print("[pdf-debug-gap-kind-benign]", {
                                "region": [s0, e0],
                                "kind": kind,
                                **(extra or {})
                            })

                        # FN fallback: If it's an inter-stream gap that *looks random*,
                        # keep with a dedicated reason. This covers binary junk/padding
                        # or missed stream-boundary bytes that shouldn't be texty here.
                        try:
                            if kind.startswith("inter-stream"):
                                stats = (extra or {}).get("stats", {})
                                if _looks_random_interstream_gap(stats):
                                    keep = True
                                    reason = "pdf: inter-stream random bytes"
                                    if debug_gap_kinds or debug_gaps:
                                        print("[pdf-debug-gap-kind-upgrade]", {
                                            "region": [s0, e0],
                                            "kind": kind,
                                            "reason": reason,
                                            "stats": stats,
                                            "nearest": (extra or {}).get("nearest_tokens", {})
                                        })
                        except Exception:
                            # never fail hard here; this is just a safety net
                            pass

                else:
                    # MEMBER PATH (ZIP-like): evaluate each overlapping stream once,
                    # inherit their verdicts (no entropy-based fragment probe).
                    
                    # NEW: also run the same outside-stream ASCII/token checks
                    # on any **gaps** within [s0,e0] not covered by streams.
                    keep_any: bool = False
                    reasons: List[str] = []
                    gap_keep_any: bool = False
                    gap_reasons: List[str] = []

                    # If we already ran a preamble decision for a prefix gap, fold that in.
                    if pre_ran:
                        if pre_keep:
                            keep_any = True
                        if pre_reason:
                            reasons.append(pre_reason)

                    # Run prelude checks over every gap slice once (no duplication).
                    for (gs, ge) in _compute_gap_slices(s0, e0, sts):
                        gk, gr, gran = _preamble_check_slice(gs, ge)
                        # Insert the same absolute-zone probe for each gap slice, before other upgrades.
                        if not gk:
                            try:
                                # Use the slice start as the representative offset (covers the FN case at 96768)
                                zp = _zone_at_absolute_offset(ap, s0, radius=262144)
                                if debug_prelude:
                                    print("[pdf-debug-abs-zone] chk", {
                                        "region": [s0, e0],
                                        "zone": zp.get("zone"),
                                        "obj_range": zp.get("obj_range")
                                    })
                                if zp.get("zone") in ("literal_string","hex_string"):
                                    body = zp.get("body") or b""
                                    if _looks_encrypted_literal_or_hex(body, is_hex=(zp["zone"] == "hex_string")):
                                        gk = True
                                        gr = "pdf: prelude data encrypted"
                                        if debug_prelude or debug_gaps:
                                            print("[pdf-debug-gap-slice-prelude-zone-keep]", {
                                                "slice": [gs, ge],
                                                "zone": zp.get("zone"),
                                                "obj_range": zp.get("obj_range")
                                            })
                            except Exception:
                                pass
                        if gran and gr: gap_reasons.append(gr)   # same validators as non-overlap branch
                        if gk: gap_keep_any = True
                        # Regardless of keep, emit gap-kind diagnostics so we can see where FNs hide.
                        if debug_gap_kinds or debug_gaps:
                            kind, extra = _classify_gap_kind(ap, gs, ge, first_stream_start, marker_win)
                            # Tag whether our prelude checks fired for this slice.
                            print("[pdf-debug-gap-kind-slice]", {
                                "slice": [gs, ge],
                                "kind": kind,
                                "kept": bool(gk),
                                "reason": gr or "",
                                **(extra or {})
                            })
                        # FN fallback per-slice: upgrade to keep if random-looking inter-stream gap.
                        if not gk:
                            try:
                                if kind.startswith("inter-stream"):
                                    stats = (extra or {}).get("stats", {})
                                    if _looks_random_interstream_gap(stats):
                                        gk = True
                                        gr = "pdf: inter-stream random bytes"
                                        gap_keep_any = True
                                        gap_reasons.append(gr)
                                        if debug_gap_kinds or debug_gaps:
                                            print("[pdf-debug-gap-kind-slice-upgrade]", {
                                                "slice": [gs, ge],
                                                "kind": kind,
                                                "reason": gr,
                                                "stats": stats,
                                                "nearest": (extra or {}).get("nearest_tokens", {})
                                            })
                            except Exception:
                                pass

                    if gap_keep_any:
                        keep_any = True
                        reasons.extend(gap_reasons)
                        # Do not return; still analyze overlapping streams.
                    for st in sts:
                        # Inherit ONLY the member (stream) verdict. No localized fragment probe.
                        k2, r2 = _eval_stream(st)
                        
                        # Extra diagnostics: for *unfiltered content-ish raw* streams,
                        # show which token zone this region lands on. Reuse debug_gaps flag.
                        if debug_gaps:
                            try:
                                is_untyped = not (st.k_is_image or st.k_is_font or st.k_is_icc or st.k_is_xref_stream
                                                  or st.k_is_objstm or st.k_is_embedded or st.k_is_xmp or st.k_is_content)
                                no_filters = not (st.filters or [])
                                if is_untyped and no_filters:
                                    # Quick content-ish check on RAW payload we already have
                                    raw_probe = _read_span(ap, st.data_start, st.data_end_incl, cap=raw_budget_stream)
                                    if _looks_like_contentish_raw(raw_probe):
                                        _debug_rawzone_report(st, s0, e0, ap, cap=raw_budget_stream)
                            except Exception as _e:
                                print("[pdf-debug-rawzone-error]", {"err": f"{type(_e).__name__}: {_e}"})

                        if k2:
                            keep_any = True
                            reasons.append(r2)

                    # finalize region from all overlapping streams
                    keep = keep_any
                    reason = " | ".join(reasons) if reasons else "pdf: benign"
                    if debug_streams or debug_gaps or debug_prelude:
                        print(f"[pdf-debug-region-final] region=[{s0},{e0}] keep={keep} reason={reason}")

            except Exception as ex:
                # Keep legacy escalate, but surface the exception type; show traceback only if any debug flag is on.
                if (debug_prelude or debug_textish or debug_streams or debug_gaps or debug_gap_kinds):
                    import traceback
                    print("[pdf-debug-exc]", {
                        "region": [int(s), int(e)],
                        "type": type(ex).__name__,
                        "msg": str(ex),
                    })
                    traceback.print_exc()
                keep = True
                # Keep the exact legacy reason string to avoid baseline churn.
                reason = "pdf: analysis error; escalate (9555)"
                # Emit exception type only when any PDF debug flag is on.
                if debug_streams or debug_textish or debug_prelude or debug_gaps or debug_gap_kinds:
                    try:
                        print("[pdf-debug-exc]", {"type": type(ex).__name__, "msg": str(ex)})
                    except Exception:
                        pass
                region_out.append(RegionDecision(start=int(s), end=int(e), keep=True, reason=reason))

            any_keep = any_keep or keep
            region_out.append(RegionDecision(start=int(s), end=int(e), keep=bool(keep), reason=str(reason)))

        # --- end per-region loop ---
        # Safety belt: demote ONLY when the region was explicitly the binary marker window.
        if any_keep:
            kept_non_prelude = any(
                (r.keep and not (r.reason.startswith("pdf: data encrypted (outside)") and r.end < first_stream_start))
                for r in region_out
            )
            if not kept_non_prelude:
                aw_hi = -1
                if marker_win != (-1, -1):
                    _, aw_hi = marker_win
                for r in region_out:
                    if r.keep and r.reason == "pdf: binary header marker (benign)":
                        r.keep = False
                        r.reason = "pdf: metadata prelude (benign)"
                any_keep = any(r.keep for r in region_out)

        # If any region was kept due to nested-encrypted streams, elevate the file verdict.
        # Match by prefix so we also catch variants like "pdf: nested metadata encrypted (2 streams)".
        nested_any = any(
            r.keep and isinstance(r.reason, str)
            and r.reason.startswith("pdf: nested metadata encrypted")
            for r in (region_out or [])
        )
        if nested_any:
            file_reason = "pdf: nested metadata encrypted"
        else:
            file_reason = "pdf: suspicious regions kept" if any_keep else "pdf: all regions dropped"
        return FileAwareDecision(keep_file=any_keep, reason=file_reason, region_decisions=region_out or None)
