#!/usr/bin/env python3
import argparse
import csv
import hashlib
import os
import sys
from pathlib import Path
from typing import Iterable, List, Dict, Optional, Tuple, Any, Set
import zipfile
import re
import mmap
import base64
import zlib

from io import BytesIO

# Optional PDF parser (pikepdf uses QPDF under the hood)
try:
    import pikepdf
    _HAVE_PIKEPDF = True
except Exception:
    _HAVE_PIKEPDF = False

# -------- Config --------
MEDIA_FILE_EXTS = {
    # images
    "jpg", "jpeg", "png", "webp", "gif", "bmp", "tif", "tiff", "j2k", "jp2",
    # audio
    "mp3", "wav", "ogg", "m4a", "flac", "aac",
    # video
    "mp4", "m4v", "mov", "webm", "avi", "mkv",
    # vector-ish we may see embedded
    "emf", "wmf", "svg", "ico",
}

OOXML_EXTS = {"docx", "pptx", "xlsx"}
ZIPLIKE_EXTS = {"zip", "jar", "apk"}  # jar/apk are zips

# OOXML thumbnails live under docProps/thumbnail.(jpeg|jpg|png)
def is_ooxml_thumbnail(path_in_zip: str) -> bool:
    p = (path_in_zip or "").lower().replace("\\", "/")
    return p.startswith("docprops/thumbnail.") and \
           (p.endswith(".jpg") or p.endswith(".jpeg") or p.endswith(".png") or p.endswith(".jfif"))

# Must match detector/fileaware/handlers/pdf.py (raw_budget_stream)
RAW_HASH_BUDGET = 8 * 1024 * 1024

# -------- Utils --------
def sha256_bytes(b: bytes) -> str:
    h = hashlib.sha256()
    h.update(b)
    return h.hexdigest()

def sha256_file(path: str, chunk: int = 1024 * 1024) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while True:
            buf = f.read(chunk)
            if not buf:
                break
            h.update(buf)
    return h.hexdigest()

def ext_of(path: str) -> str:
    e = (os.path.splitext(path)[1] or "").lower()
    return e[1:] if e.startswith(".") else e

def is_media_name(name: str) -> bool:
    return ext_of(name) in MEDIA_FILE_EXTS

def is_ooxml_name(path: str) -> bool:
    return ext_of(path) in OOXML_EXTS

def is_ziplike_name(path: str) -> bool:
    return ext_of(path) in ZIPLIKE_EXTS

def _is_zip_magic(buf: bytes) -> bool:
    # PK\x03\x04|PK\x05\x06|PK\x01\x02 (local hdr, EOCD, central dir)
    return len(buf) >= 4 and buf[:2] == b"PK"

# =========================
# PDF decode helpers (same set as handler)
# =========================
SUPPORTED_FILTERS = {
    b"FlateDecode",
    b"ASCII85Decode",
    b"ASCIIHexDecode",
    b"RunLengthDecode",
}

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
        if len(buf) >= RAW_HASH_BUDGET: break
    if have_half and len(buf) < RAW_HASH_BUDGET:
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

        if filt == 0:      # None
            pass
        elif filt == 1:    # Sub
            for x in range(row_size):
                left = row[x - bpp] if x >= bpp else 0
                row[x] = (row[x] + left) & 0xFF
        elif filt == 2:    # Up
            for x in range(row_size):
                row[x] = (row[x] + prev[x]) & 0xFF
        elif filt == 3:    # Average
            for x in range(row_size):
                left = row[x - bpp] if x >= bpp else 0
                up = prev[x]
                row[x] = (row[x] + ((left + up) // 2)) & 0xFF
        elif filt == 4:    # Paeth
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
    """
    Try to decode using the subset of filters we support.
    Returns (decoded_bytes_or_None, fully_supported_bool).
    """
    if not filters:
        return (raw[:budget] if len(raw) > budget else raw), True

    data = raw
    fully_supported = True

    parms_list = decodeparms if decodeparms else []
    if len(parms_list) not in (0, 1, len(filters)):
        parms_list = []

    for idx, f in enumerate(filters):
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

# =========================
# PDF (fallback) scanner with decoded hashing
# =========================
PDF_HEADER_RE = re.compile(rb"%PDF-\d\.\d")
EOF_RE        = re.compile(rb"%%EOF\s*$", re.DOTALL)
DICT_BACK_RE  = re.compile(rb"<<.*?>>", re.DOTALL)
FILTER_RE     = re.compile(rb"/Filter\s+(?P<val>(\[.*?\]|/\S+))", re.DOTALL)
DECODEPARMS_RE= re.compile(rb"/DecodeParms\s+(?P<val>(\[.*?\]|<<.*?>>))", re.DOTALL)
NAME_PAIR_RE  = re.compile(rb"/([A-Za-z0-9\.\-\+]+)")

LOOKBACK_LIMIT = 65536  # 64 KiB robust window

def _parse_filter_names(val: bytes) -> List[bytes]:
    if not val:
        return []
    val = val.strip()
    try:
        if val.startswith(b"["):
            return [m.group(1).split()[0] for m in NAME_PAIR_RE.finditer(val)]
        if val.startswith(b"/"):
            return [val[1:].split()[0]]
    except Exception:
        pass
    return []

def _parse_decodeparms_bytes(val: bytes) -> List[Dict[bytes, Any]]:
    def _one(d: bytes) -> Dict[bytes, Any]:
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
    v = val.strip()
    try:
        if v.startswith(b"["):
            parts = []
            i, L = 1, len(v)
            while i < L-1:
                while i < L-1 and v[i] in b" \t\r\n": i += 1
                if i >= L-1: break
                if v[i:i+2] == b"<<":
                    depth = 1; j = i+2
                    while j < L-1 and depth > 0:
                        if v[j:j+2] == b"<<": depth += 1; j += 2
                        elif v[j:j+2] == b">>": depth -= 1; j += 2
                        else: j += 1
                    parts.append(_one(v[i:j]))
                    i = j
                else:
                    j = i
                    while j < L-1 and v[j] not in (b" \t\r\n]"): j += 1
                    i = j
            return parts
        elif v.startswith(b"<<"):
            return [_one(v)]
    except Exception:
        pass
    return []

def _filters_lower_set(filters: List[bytes]) -> set:
    return {f.lower() for f in filters}

def _pdf_guess_ext_from_filters(filters: List[bytes]) -> str:
    fs = _filters_lower_set(filters)
    if b"dctdecode" in fs:      return "jpg"
    if b"jpxdecode" in fs:      return "jp2"
    if b"ccittfaxdecode" in fs: return "tiff"
    if b"jbig2decode" in fs:    return "jbig2"
    if b"flatedecode" in fs:    return "flate"  # PNG-like scanlines post-predictor
    return ""

def _find_stream_payload_bounds(mm: mmap.mmap, s_idx: int, size: int) -> Optional[Tuple[int,int,int]]:
    # Handle CRLF/LF/CR after 'stream'
    scan_end = min(size, s_idx + 256)
    cr = mm.find(b"\r", s_idx, scan_end)
    lf = mm.find(b"\n", s_idx, scan_end)
    if cr == -1 and lf == -1:
        return None
    if cr != -1 and lf != -1 and lf == cr + 1:
        data_start = lf + 1           # CRLF
    elif lf != -1 and (cr == -1 or lf < cr):
        data_start = lf + 1           # LF
    else:
        data_start = cr + 1           # CR
    e_idx = mm.find(b"endstream", data_start)
    if e_idx < 0:
        return None
    data_end = e_idx - 1
    while data_end >= data_start and mm[data_end] in (0x0A, 0x0D):
        data_end -= 1
    return (data_start, data_end, e_idx)

def _is_image_dict_loose(dict_bytes: bytes, filters: List[bytes]) -> bool:
    d = dict_bytes
    has_xobject = (b"/Type/XObject" in d or b"/XObject" in d)
    has_subtype_image = (b"/Subtype/Image" in d or (b"/Subtype" in d and b"/Image" in d))
    has_dims = (b"/Width" in d and b"/Height" in d)
    has_bits = (b"/BitsPerComponent" in d or b"/ImageMask" in d)
    fs = _filters_lower_set(filters)
    has_image_codec = any(c in fs for c in (b"dctdecode", b"jpxdecode", b"ccittfaxdecode", b"jbig2decode"))
    if (has_xobject and has_subtype_image and (has_dims or has_bits)):
        return True
    if has_subtype_image and (has_dims or has_image_codec or has_bits):
        return True
    if has_image_codec:
        return True
    return False

def _walk_pdf_streams_fallback(pdf_path: str) -> List[Dict[str, str]]:
    """
    Raw mmap scanner that detects image streams and hashes **decoded bytes** when
    the filter chain is supported; otherwise hashes RAW stream bytes.
    """
    rows: List[Dict[str, str]] = []
    try:
        size = os.path.getsize(pdf_path)
        with open(pdf_path, "rb") as fh, mmap.mmap(fh.fileno(), 0, access=mmap.ACCESS_READ) as mm:
            if not PDF_HEADER_RE.match(mm[:16]):
                return rows
            if EOF_RE.search(mm[-2048:]) is None and EOF_RE.search(mm) is None:
                return rows
            start = 0
            abs_pdf = os.path.abspath(pdf_path)
            while True:
                s_idx = mm.find(b"stream", start)
                if s_idx < 0:
                    break
                bounds = _find_stream_payload_bounds(mm, s_idx, size)
                if not bounds:
                    start = s_idx + len(b"stream")
                    continue
                data_start, data_end, e_idx = bounds

                # Look back for dict
                look_back_start = max(0, s_idx - LOOKBACK_LIMIT)
                slice_back = mm[look_back_start:s_idx]
                m = None
                for match in DICT_BACK_RE.finditer(slice_back):
                    m = match

                filters: List[bytes] = []
                dparms: List[Dict[bytes, Any]] = []
                is_image = False
                if m:
                    dict_bytes = slice_back[m.start():m.end()]
                    f_m = FILTER_RE.search(dict_bytes)
                    filters = _parse_filter_names(f_m.group("val")) if f_m else []
                    p_m = DECODEPARMS_RE.search(dict_bytes)
                    dparms = _parse_decodeparms_bytes(p_m.group("val")) if p_m else []
                    is_image = _is_image_dict_loose(dict_bytes, filters)
                if is_image:
                    raw = mm[data_start:min(data_end + 1, data_start + RAW_HASH_BUDGET)]
                    if raw:
                        decoded, fully_supported = _decode_supported_filters(raw, filters or [], dparms or [], RAW_HASH_BUDGET)
                        h = sha256_bytes(decoded) if (decoded is not None and fully_supported) else sha256_bytes(raw)
                        rows.append({
                            "sha256": h,
                            "source": "pdf",
                            "container": abs_pdf,
                            "entry": f"stream@{data_start}-{data_end}",
                            "media_ext": _pdf_guess_ext_from_filters(filters),
                        })
                start = e_idx + len(b"endstream")
    except Exception as e:
        print(f"[warn] PDF scan failed (fallback): {pdf_path}: {e}", file=sys.stderr)
    return rows

# =========================
# PDF via pikepdf (preferred) with decoded hashing
# =========================
def _name_equals_pike(obj: Any, literal: str) -> bool:
    try:
        return isinstance(obj, pikepdf.Name) and str(obj) == literal
    except Exception:
        return False

def _extract_filters_decodeparms_from_stream_dict(sd: "pikepdf.Dictionary") -> Tuple[List[bytes], List[Dict[bytes, Any]]]:
    filters: List[bytes] = []
    dparms: List[Dict[bytes, Any]] = []

    try:
        # Filters can be Name or Array of Names
        filt = sd.get("/Filter", None)
        if isinstance(filt, pikepdf.Name):
            filters.append(str(filt).lstrip("/").encode("ascii", "ignore"))
        elif isinstance(filt, pikepdf.Array):
            for el in filt:
                if isinstance(el, pikepdf.Name):
                    filters.append(str(el).lstrip("/").encode("ascii", "ignore"))
    except Exception:
        pass

    try:
        # DecodeParms can be Dictionary or Array of Dictionaries
        dp = sd.get("/DecodeParms", None)
        def _one(d: "pikepdf.Dictionary") -> Dict[bytes, Any]:
            out: Dict[bytes, Any] = {}
            if not isinstance(d, pikepdf.Dictionary):
                return out
            for k in ("/Predictor", "/Columns", "/Colors", "/BitsPerComponent"):
                v = d.get(k, None)
                try:
                    if v is not None:
                        out[k.lstrip("/").encode("ascii", "ignore")] = int(v)
                except Exception:
                    pass
            return out
        if isinstance(dp, pikepdf.Dictionary):
            dparms.append(_one(dp))
        elif isinstance(dp, pikepdf.Array):
            for el in dp:
                if isinstance(el, pikepdf.Dictionary):
                    dparms.append(_one(el))
    except Exception:
        pass

    return filters, dparms

def _pdf_guess_ext_from_stream_dict(sd: "pikepdf.Dictionary") -> str:
    filters, _ = _extract_filters_decodeparms_from_stream_dict(sd)
    return _pdf_guess_ext_from_filters(filters)

def _walk_pdf_images_pikepdf(pdf_path: str) -> List[Dict[str, str]]:
    """
    Enumerate referenced Image XObjects by walking:
      Pages -> /Resources -> /XObject (recursing into /Subtype /Form)
    Hash **decoded bytes** when the filter chain is supported; otherwise hash RAW.
    """
    rows: List[Dict[str, str]] = []
    abs_pdf = os.path.abspath(pdf_path)

    def _stream_hash_decoded_or_raw(obj: "pikepdf.Stream", sd: "pikepdf.Dictionary") -> Optional[str]:
        try:
            raw = obj.read_bytes(decode=False) or b""
            if len(raw) > RAW_HASH_BUDGET:
                raw = raw[:RAW_HASH_BUDGET]
            if not raw:
                return None
            filters, dparms = _extract_filters_decodeparms_from_stream_dict(sd)
            decoded, fully_supported = _decode_supported_filters(raw, filters or [], dparms or [], RAW_HASH_BUDGET)
            return sha256_bytes(decoded) if (decoded is not None and fully_supported) else sha256_bytes(raw)
        except Exception:
            return None

    def _objref_key(ref: Any) -> Tuple[int, int]:
        try:
            if isinstance(ref, pikepdf.ObjectRef):
                return ref.objgen
            if isinstance(ref, (tuple, list)) and len(ref) >= 2:
                return (int(ref[0]), int(ref[1]))
        except Exception:
            pass
        return (-1, 0)

    def _dfs_xobject_dict(xobj_dict: "pikepdf.Dictionary", pdf: "pikepdf.Pdf", seen_refs: Set[Tuple[int, int]]):
        if not isinstance(xobj_dict, pikepdf.Dictionary):
            return
        for _, ref in list(xobj_dict.items()):
            try:
                obj = pdf.get_object(ref) if isinstance(ref, pikepdf.ObjectRef) else ref
                if not isinstance(obj, pikepdf.Stream):
                    continue

                sd = obj.get_dict()
                subtype = sd.get("/Subtype", None)

                # Image XObject
                if _name_equals_pike(subtype, "/Image"):
                    h = _stream_hash_decoded_or_raw(obj, sd)
                    if h:
                        objnum, gennum = _objref_key(ref)
                        rows.append({
                            "sha256": h,
                            "source": "pdf",
                            "container": abs_pdf,
                            "entry": f"obj {objnum} {gennum} R",
                            "media_ext": _pdf_guess_ext_from_stream_dict(sd),
                        })
                    continue

                # Recurse into Form XObjects
                if _name_equals_pike(subtype, "/Form"):
                    key = _objref_key(ref)
                    if key in seen_refs:
                        continue
                    seen_refs.add(key)
                    form_res = sd.get("/Resources", None)
                    if isinstance(form_res, pikepdf.Dictionary):
                        inner_xobj = form_res.get("/XObject", None)
                        if isinstance(inner_xobj, pikepdf.Dictionary):
                            _dfs_xobject_dict(inner_xobj, pdf, seen_refs)
            except Exception:
                continue

    with pikepdf.open(pdf_path) as pdf:
        # Walk every page’s (inherited) resources
        for page in pdf.pages:
            try:
                res = page.Resources
            except Exception:
                res = page.get("/Resources", None)
            if not isinstance(res, pikepdf.Dictionary):
                continue
            try:
                xobj = res.get("/XObject", None)
                if isinstance(xobj, pikepdf.Dictionary):
                    _dfs_xobject_dict(xobj, pdf, seen_refs=set())
            except Exception:
                continue

    return rows

def walk_pdf_media(pdf_path: str) -> List[Dict[str, str]]:
    """
    Preferred: pikepdf walk of Image XObjects via page Resources/XObject (with Form recursion),
    hashing **decoded** bytes when supported (fallback to raw).
    Fallback: mmap scanner with the same decoded-or-raw hashing.
    """
    if _HAVE_PIKEPDF:
        try:
            rows = _walk_pdf_images_pikepdf(pdf_path)
            if rows:
                return rows
        except Exception as e:
            print(f"[warn] pikepdf walk failed for {pdf_path}: {e}", file=sys.stderr)
    return _walk_pdf_streams_fallback(pdf_path)

# =========================
# ZIP/OOXML walkers
# =========================
def walk_zip_media(container_path: str, restrict_to_ooxml_media_dirs: bool = False) -> List[Dict[str, str]]:
    """
    For ZIP/OOXML/JAR/APK:
      - Hash decompressed file bytes of embedded media to be robust to compression churn.
      - For OOXML (restrict=True), only trust media under */media/* (word/xl/ppt).
    """
    rows: List[Dict[str, str]] = []
    abs_container = os.path.abspath(container_path)
    try:
        with zipfile.ZipFile(container_path, "r") as zf:
            for info in zf.infolist():
                name = info.filename

                if restrict_to_ooxml_media_dirs:
                    lowered = name.lower()
                    in_ooxml_media_dir = (
                        "/media/" in lowered and
                        (lowered.startswith("word/") or lowered.startswith("ppt/") or lowered.startswith("xl/"))
                    )
                    # Accept OOXML thumbnails in docProps as trusted media as well
                    if not (in_ooxml_media_dir or is_ooxml_thumbnail(name)):
                        continue

                if not is_media_name(name):
                    continue

                try:
                    data = zf.read(name)  # decompressed bytes
                except Exception:
                    continue
                if not data:
                    continue

                rows.append({
                    "sha256": sha256_bytes(data),
                    "source": "ooxml" if is_ooxml_name(abs_container) else "zip",
                    "container": abs_container,
                    "entry": name,
                    "media_ext": ext_of(name),
                })
    except Exception as e:
        print(f"[warn] ZIP parse failed: {container_path}: {e}", file=sys.stderr)
    return rows

# =========================
# OOXML embedded media (e.g., word/embeddings/*.bin that are ZIPs)
# =========================
def walk_ooxml_embedded_media(container_path: str) -> List[Dict[str, str]]:
    """
    Read OOXML embedding/ActiveX parts and, when a part is itself a ZIP,
    enumerate any media inside it. Hash **decompressed** inner media bytes.

    Emits rows with:
      - source="ooxml-embedded"
      - container=<abs path to outer OOXML file>
      - entry="<outer-part>!<inner/path/to/media>"
    """
    rows: List[Dict[str, str]] = []
    abs_container = os.path.abspath(container_path)
    try:
        with zipfile.ZipFile(container_path, "r") as outer:
            for info in outer.infolist():
                name = info.filename
                lname = name.lower()
                # Target typical embedded buckets
                if not (lname.startswith("word/embeddings/")
                        or lname.startswith("ppt/embeddings/")
                        or lname.startswith("xl/embeddings/")
                        or lname.startswith("word/activex/")
                        or lname.startswith("ppt/activex/")
                        or lname.startswith("xl/activex/")):
                    continue
                # Read outer part DECOMPRESSED
                try:
                    data = outer.read(name)
                except Exception:
                    continue
                if not data:
                    continue
                # If the embedded part is itself a ZIP container, scan it for media
                if _is_zip_magic(data):
                    try:
                        with zipfile.ZipFile(BytesIO(data), "r") as inner:
                            for sub in inner.infolist():
                                sub_name = sub.filename
                                if not is_media_name(sub_name):
                                    continue
                                try:
                                    inner_data = inner.read(sub_name)  # DECOMPRESSED inner media
                                except Exception:
                                    continue
                                if not inner_data:
                                    continue
                                rows.append({
                                    "sha256": sha256_bytes(inner_data),
                                    "source": "ooxml-embedded",
                                    "container": abs_container,
                                    "entry": f"{name}!{sub_name}",
                                    "media_ext": ext_of(sub_name),
                                })
                    except Exception:
                        # Not a valid ZIP or failed to parse; skip silently.
                        pass
                else:
                    # Non-ZIP embedded object (likely OLE CFB). Without olefile,
                    # we skip. If you add 'olefile', you can parse here.
                    continue
    except Exception as e:
        print(f"[warn] OOXML embedded scan failed: {container_path}: {e}", file=sys.stderr)
    return rows

# =========================
# Top-level media
# =========================
def row_for_media_file(path: str) -> Optional[Dict[str, str]]:
    try:
        return {
            "sha256": sha256_file(path),
            "source": "file",
            "container": os.path.abspath(path),
            "entry": "",
            "media_ext": ext_of(path),
        }
    except Exception as e:
        print(f"[warn] Hashing failed for {path}: {e}", file=sys.stderr)
        return None

# =========================
# Discovery
# =========================
def iter_files(paths: List[str]) -> Iterable[str]:
    for p in paths:
        pth = Path(p)
        if pth.is_dir():
            for f in pth.rglob("*"):
                if f.is_file():
                    yield str(f)
        elif pth.is_file():
            yield str(pth)
        else:
            print(f"[warn] Skipping non-existent path: {p}", file=sys.stderr)

# =========================
# Main build
# =========================
def build_manifest(inputs: List[str],
                   include_ooxml_embedded: bool = False) -> List[Dict[str, str]]:
    out: List[Dict[str, str]] = []
    seen: Set[Tuple[str, str, str]] = set()  # (source, container, entry)

    def add_row(r: Dict[str, str]):
        key = (r["source"], r["container"], r["entry"])
        if key not in seen:
            seen.add(key)
            out.append(r)

    for path in iter_files(inputs):
        e = ext_of(path)

        # PDFs: enumerate Image XObjects (decoded hashing preferred), fallback to raw scan
        if e == "pdf":
            for r in walk_pdf_media(path):
                add_row(r)
            continue

        # OOXML containers: only */media/* entries
        if is_ooxml_name(path):
            for r in walk_zip_media(path, restrict_to_ooxml_media_dirs=True):
                add_row(r)
            if include_ooxml_embedded:
                for r in walk_ooxml_embedded_media(path):
                    add_row(r)
            continue

        # Generic ZIP-like (zip/jar/apk): all media entries
        if is_ziplike_name(path):
            for r in walk_zip_media(path, restrict_to_ooxml_media_dirs=False):
                add_row(r)
            continue

        # Standalone media files
        if e in MEDIA_FILE_EXTS:
            r = row_for_media_file(path)
            if r:
                add_row(r)
            continue

        # Non-media file -> no entry (extend here for nested containers if needed)

    return out

def write_csv(rows: List[Dict[str, str]], out_csv: str) -> None:
    Path(out_csv).parent.mkdir(parents=True, exist_ok=True)
    with open(out_csv, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=["sha256", "source", "container", "entry", "media_ext"])
        w.writeheader()
        for r in rows:
            w.writerow(r)

def main():
    ap = argparse.ArgumentParser(description="Build trusted manifest for media in files, OOXML/ZIP/JAR/APK, and PDFs.")
    ap.add_argument("inputs", nargs="+", help="Files or directories to scan")
    ap.add_argument("-o", "--out", default="input/trusted_manifest.csv", help="Output CSV path")
    ap.add_argument("--include-ooxml-embedded", action="store_true",
                    help="Also hash media found inside embedded OOXML parts (e.g., word/embeddings/*.bin that are ZIPs).")
    args = ap.parse_args()

    rows = build_manifest(args.inputs, include_ooxml_embedded=args.include_ooxml_embedded)
    write_csv(rows, args.out)

    print(f"[ok] Wrote {len(rows)} entries to {args.out}")

if __name__ == "__main__":
    main()
