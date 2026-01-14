# detector/fileaware/handlers/zip.py
import os
import io
import struct
import zlib
import gzip
from typing import Optional, List, Tuple, Dict, Any, Iterable

from ..types import (
    FileContext,
    SuspiciousFileRegion,
    FileAwareDecision,
    RegionDecision,
)

from zlib import error as _ZlibError

# ---- ZIP constants ----
SIG_EOCD        = 0x06054B50  # End of central directory
SIG_CEN         = 0x02014B50  # Central directory file header
SIG_LOC         = 0x04034B50  # Local file header
SIG_ZIP64_EOCD  = 0x06064B50  # ZIP64 EOCD (unsupported here -> escalate)
SIG_ZIP64_LOC   = 0x07064B50  # ZIP64 EOCD locator

METHOD_STORE    = 0  # no compression
METHOD_DEFLATE  = 8
METHOD_AES      = 99  # WinZip AES wrapper (actual method recorded in extra 0x9901)

# ---- This handler targets generic containers (OOXML handled elsewhere) ----
EXTS = {"zip", "jar", "apk"}

# ---------- Utils ----------

def _ext_of(path: str) -> str:
    return (os.path.splitext(path)[1] or "").lstrip(".").lower()

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

def _any_overlap(a0: int, a1: int, b0: int, b1: int) -> bool:
    return not (a1 < b0 or b1 < a0)

def _overlap_len(a0: int, a1: int, b0: int, b1: int) -> int:
    if _any_overlap(a0, a1, b0, b1):
        return min(a1, b1) - max(a0, b0) + 1
    return 0

def _clip(a0: int, a1: int, b0: int, b1: int) -> Tuple[int, int]:
    return max(a0, b0), min(a1, b1)

def _read(path: str, start: int, n: int) -> bytes:
    with open(path, "rb") as f:
        f.seek(start)
        return f.read(max(0, n))

def _read_span(path: str, start: int, end_incl: int, cap: int) -> bytes:
    if end_incl < start:
        return b""
    length = min(end_incl - start + 1, cap)
    return _read(path, start, length)

def _looks_like_zip(magic: Optional[bytes]) -> bool:
    if not magic or len(magic) < 4:
        return False
    sig = struct.unpack_from("<I", magic, 0)[0]
    return sig in (SIG_LOC, SIG_EOCD, SIG_CEN)

# ---------- Magic sniffers ----------

def _magic(buf: bytes) -> str:
    if len(buf) >= 8:
        if buf.startswith(b"\x50\x4B\x03\x04") or buf.startswith(b"\x50\x4B\x05\x06") or buf.startswith(b"\x50\x4B\x01\x02"):
            return "zip"
        if buf.startswith(b"\x1F\x8B"):
            return "gzip"
        if buf.startswith(b"%PDF"):
            return "pdf"
        if buf.startswith(b"\x89PNG\r\n\x1a\n"):
            return "png"
        if buf.startswith(b"\xFF\xD8\xFF"):
            return "jpeg"
        if buf[:3] == b"ID3" or (buf[0] == 0xFF and (buf[1] & 0xE0) == 0xE0):
            return "mp3"
        if buf[:4] == b"RIFF":
            return "riff"
    return "unknown"

def _is_container(kind: str) -> bool:
    return kind in ("zip", "gzip")

# ---------- Parse directory & entries ----------

class _ZipEntry:
    __slots__ = ("name", "method", "comp_size", "uncomp_size",
                 "flags", "lh_off", "data_start", "data_end_incl", "is_aes")

    def __init__(self):
        self.name = ""
        self.method = 0
        self.comp_size = 0
        self.uncomp_size = 0
        self.flags = 0
        self.lh_off = 0
        self.data_start = 0
        self.data_end_incl = -1
        self.is_aes = False

def _read_tail(fh, max_back: int) -> bytes:
    fh.seek(0, os.SEEK_END)
    size = fh.tell()
    take = min(size, max_back)
    fh.seek(size - take, os.SEEK_SET)
    return fh.read(take)

def _find_eocd(fh) -> Tuple[int, Dict[str, Any]]:
    """
    Return (eocd_offset, eocd_fields) or (-1, {}).
    EOCD layout (22 bytes + comment):
      0  4  signature 0x06054b50
      4  2  disk number
      6  2  disk with central dir
      8  2  entries on this disk
      10 2  total entries
      12 4  size of central directory
      16 4  offset of central directory
      20 2  comment length
    """
    tail = _read_tail(fh, 66_000 + 22)
    # ZIP64 markers present → unsupported here (treat as metadata-encrypted)
    if tail.rfind(b"PK\x06\x06") >= 0 or tail.rfind(b"PK\x06\x07") >= 0:
        return -1, {"zip64": True}
    idx = tail.rfind(b"PK\x05\x06")
    if idx < 0 or len(tail) - idx < 22:
        return -1, {}
    sig, disk, cd_disk, n_this, n_total, cd_size, cd_off, com_len = struct.unpack_from(
        "<IHHHHIIH", tail, idx
    )
    fh.seek(0, os.SEEK_END)
    size = fh.tell()
    eocd_off = size - (len(tail) - idx)
    eocd_end = eocd_off + 22 + int(com_len) - 1
    return eocd_off, {
        "disk": disk, "cd_disk": cd_disk,
        "n_total": n_total, "cd_size": cd_size, "cd_off": cd_off,
        "com_len": com_len, "file_size": size,
        "eocd_span": (eocd_off, eocd_end),
    }

def _has_winzip_aes_extra(extra: bytes) -> bool:
    # Extra fields: [2B header id][2B data size][data]...
    i = 0
    L = len(extra)
    while i + 4 <= L:
        hid = struct.unpack_from("<H", extra, i)[0]
        sz  = struct.unpack_from("<H", extra, i + 2)[0]
        i  += 4
        if i + sz > L:
            break
        if hid == 0x9901:  # WinZip AES
            return True
        i += sz
    return False

def _parse_directory_and_entries(fp: str) -> Tuple[List[_ZipEntry], Dict[str, Any], str]:
    """
    Parse EOCD + Central Directory, then derive each entry's local header & data span.
    Returns (entries, eocd_info, err_reason). On fatal/unsupported structures, err_reason != "".
    """
    try:
        with open(fp, "rb") as f:
            size = os.fstat(f.fileno()).st_size
            eocd_off, eocd = _find_eocd(f)
            if eocd_off < 0:
                return [], {}, "zip: metadata encrypted (missing/unsupported EOCD or ZIP64)"
            cd_off = int(eocd["cd_off"]); cd_size = int(eocd["cd_size"]); n_total = int(eocd["n_total"])
            if cd_off < 0 or cd_size < 0 or cd_off + cd_size > size:
                return [], {}, "zip: metadata encrypted (central directory OOB)"

            entries: List[_ZipEntry] = []
            pos = cd_off
            cd_end = cd_off + cd_size
            with open(fp, "rb") as z:
                while pos < cd_end:
                    if pos + 4 > cd_end:
                        return [], {}, "zip: metadata encrypted (short CD at end)"
                    z.seek(pos)
                    sig_bytes = z.read(4)
                    if len(sig_bytes) < 4:
                        return [], {}, "zip: metadata encrypted (short CD)"
                    sig = struct.unpack("<I", sig_bytes)[0]
                    if sig != SIG_CEN:
                        return [], {}, "zip: metadata encrypted (bad CD signature)"
                    if pos + 46 > cd_end:
                        return [], {}, "zip: metadata encrypted (short CD fixed)"
                    fixed = z.read(42)
                    if len(fixed) != 42:
                        return [], {}, "zip: metadata encrypted (short CD fixed)"
                    (
                        ver_made, ver_need, flags, method, mtime, mdate,
                        crc32, csize, usize, nlen, xlen, clen,
                        disk_no, int_attr, ext_attr, lho
                    ) = struct.unpack("<HHHHHHIIIHHHHHII", fixed)

                    # ZIP64 not supported here
                    if csize == 0xFFFFFFFF or usize == 0xFFFFFFFF or lho == 0xFFFFFFFF:
                        return [], {}, "zip: metadata encrypted (ZIP64 not supported)"

                    if pos + 46 + nlen + xlen + clen > cd_end:
                        return [], {}, "zip: metadata encrypted (CD var fields OOB)"

                    name = z.read(nlen or 0)
                    extra = z.read(xlen or 0)
                    _ = z.read(clen or 0)

                    # Derive local header position → data start/end
                    if lho + 30 > size:
                        return [], {}, "zip: metadata encrypted (local header OOB)"
                    z.seek(lho)
                    l_sig = struct.unpack("<I", z.read(4))[0]
                    if l_sig != SIG_LOC:
                        return [], {}, "zip: metadata encrypted (bad local header sig)"
                    l_fixed = z.read(26)
                    if len(l_fixed) != 26:
                        return [], {}, "zip: metadata encrypted (short local header)"
                    (_ver, l_flags, l_method, _t, _d, _crc, _csz, _usz, lnlen, lxlen) = struct.unpack("<HHHHHIIIHH", l_fixed)

                    data_start = lho + 30 + lnlen + lxlen
                    data_end_incl = data_start + int(csize) - 1 if int(csize) > 0 else data_start - 1
                    if csize > 0 and (data_start < 0 or data_end_incl >= size):
                        return [], {}, "zip: metadata encrypted (data range OOB)"

                    ent = _ZipEntry()
                    try:
                        ent.name = name.decode("utf-8", "replace")
                    except Exception:
                        ent.name = str(name)
                    ent.method = int(method)
                    ent.comp_size = int(csize)
                    ent.uncomp_size = int(usize)
                    ent.flags = int(flags)
                    ent.lh_off = int(lho)
                    ent.data_start = int(data_start)
                    ent.data_end_incl = int(data_end_incl)
                    ent.is_aes = (ent.method == METHOD_AES) or _has_winzip_aes_extra(extra)
                    entries.append(ent)

                    pos = cd_end if (46 + nlen + xlen + clen) == 0 else (pos + 46 + nlen + xlen + clen)

            eocd["cd_span"] = (cd_off, cd_off + cd_size - 1)
            return entries, eocd, ""
    except Exception:
        return [], {}, "zip: metadata encrypted (parse error)"

# ---------- Member reading / hashing ----------

def _read_member_raw(path: str, ent: _ZipEntry, cap: int) -> bytes:
    return _read_span(path, ent.data_start, ent.data_end_incl, cap)

def _decompress_deflate_member(path: str, ent: _ZipEntry, budget: int) -> bytes:
    comp = _read_member_raw(path, ent, cap=ent.comp_size if ent.comp_size > 0 else budget)
    d = zlib.decompressobj(-15)
    try:
        out = d.decompress(comp, budget)
    except Exception:
        return b""
    return out

def _member_payload(path: str, ent: _ZipEntry, budget: int) -> Tuple[bytes, bool]:
    """
    Return (payload_bytes, is_full_payload) where payload is:
      - DEFLATE → decompressed (bounded by budget)
      - STORE   → raw
      - AES/unknown → raw (unknown compression)
    """
    if ent.method == METHOD_DEFLATE:
        out = _decompress_deflate_member(path, ent, budget=budget)
        return out, (len(out) >= min(ent.uncomp_size, budget) if ent.uncomp_size > 0 else len(out) > 0)
    elif ent.method == METHOD_STORE:
        raw = _read_member_raw(path, ent, cap=budget if ent.comp_size > 0 else budget)
        return raw, (len(raw) >= min(ent.comp_size, budget) if ent.comp_size > 0 else len(raw) > 0)
    else:
        raw = _read_member_raw(path, ent, cap=budget)
        return raw, False

def _sha256_bytes_iter(buf_iter: Iterable[bytes]) -> str:
    import hashlib
    h = hashlib.sha256()
    for chunk in buf_iter:
        if not chunk:
            continue
        h.update(chunk)
    return h.hexdigest()

def _sha256_bytes(b: bytes) -> str:
    import hashlib
    return hashlib.sha256(b).hexdigest()

# ---------- Flattening expander (nested containers) ----------

class _ExpandBudget:
    __slots__ = ("depth", "max_depth", "decoded_so_far", "decoded_limit",
                 "components", "component_limit", "per_component_budget")

    def __init__(self, max_depth: int, decoded_limit: int, component_limit: int, per_component_budget: int):
        self.depth = 0
        self.max_depth = max_depth
        self.decoded_so_far = 0
        self.decoded_limit = decoded_limit
        self.components = 0
        self.component_limit = component_limit
        self.per_component_budget = per_component_budget

def _cap_bytes(b: bytes, bud: _ExpandBudget) -> bytes:
    cap = min(len(b), bud.per_component_budget)
    bud.decoded_so_far += cap
    return b[:cap]

def _expand_zip_bytes(buf: bytes, bud: _ExpandBudget) -> List[Tuple[str, bytes]]:
    out: List[Tuple[str, bytes]] = []
    if len(buf) < 22:
        return out

    # Find EOCD quickly from tail
    tail = buf[-(66_000 + 22):]
    idx = tail.rfind(b"PK\x05\x06")
    if idx < 0 or len(tail) - idx < 22:
        return out

    # Read CD size/off from EOCD (best-effort; ignore comment length parsing exactness)
    try:
        # EOCD fields: sig, d1, d2, n_this, n_total, cd_size, cd_off, com_len
        _, _, _, _, _, cd_size, cd_off, _ = struct.unpack_from("<IHHHHIIH", tail, idx)
    except Exception:
        return out

    if cd_off + cd_size > len(buf) or cd_size == 0:
        return out

    pos = cd_off
    cd_end = cd_off + cd_size
    while pos < cd_end and bud.components < bud.component_limit:
        if pos + 46 > cd_end:
            break
        if buf[pos:pos+4] != b"PK\x01\x02":
            break
        fixed = buf[pos+4:pos+46]
        try:
            (_vm, _vn, flags, method, _mt, _md, _crc, csz, usz, nlen, xlen, clen, _dno, _ia, _ea, lho) = struct.unpack("<HHHHHHIIIHHHHHII", fixed)
        except Exception:
            break
        pos = pos + 46
        if pos + nlen + xlen + clen > cd_end:
            break
        name = buf[pos:pos+nlen]; pos += nlen
        extra = buf[pos:pos+xlen]; pos += xlen
        pos += clen  # skip comment

        if lho + 30 > len(buf):
            continue
        if buf[lho:lho+4] != b"PK\x03\x04":
            continue
        try:
            lnlen = struct.unpack_from("<H", buf, lho+26)[0]
            lxlen = struct.unpack_from("<H", buf, lho+28)[0]
        except Exception:
            continue
        data_start = lho + 30 + lnlen + lxlen
        data_end = data_start + csz
        if data_end > len(buf):
            continue
        raw = buf[data_start:data_end]

        # skip encrypted or unknown methods to avoid FPs
        if (flags & 0x1) != 0 or method not in (METHOD_STORE, METHOD_DEFLATE):
            continue

        if method == METHOD_STORE:
            view = raw
        else:
            try:
                view = zlib.decompress(raw, -15, bud.per_component_budget)
            except Exception:
                continue

        vname = name.decode("utf-8", "replace") if name else ""
        kind = _magic(view[:8])
        if _is_container(kind) and bud.depth + 1 <= bud.max_depth and bud.decoded_so_far < bud.decoded_limit:
            bud.depth += 1
            out.extend(_expand_nested(view, vname or "_.zip", bud))
            bud.depth -= 1
        else:
            view = _cap_bytes(view, bud)
            out.append((vname or "_.zip_member", view))
            bud.components += 1

    return out

def _expand_gzip_bytes(buf: bytes, bud: _ExpandBudget) -> List[Tuple[str, bytes]]:
    out: List[Tuple[str, bytes]] = []
    try:
        with gzip.GzipFile(fileobj=io.BytesIO(buf)) as gz:
            view = gz.read(bud.per_component_budget)
    except Exception:
        return out
    view = _cap_bytes(view, bud)
    kind = _magic(view[:8])
    if _is_container(kind) and bud.depth + 1 <= bud.max_depth and bud.decoded_so_far < bud.decoded_limit:
        bud.depth += 1
        out.extend(_expand_nested(view, "_.gz", bud))
        bud.depth -= 1
    else:
        out.append(("_.gz", view))
        bud.components += 1
    return out

def _expand_nested(buf: bytes, parent: str, bud: _ExpandBudget) -> List[Tuple[str, bytes]]:
    kind = _magic(buf[:8])
    if kind == "zip":
        items = _expand_zip_bytes(buf, bud)
        return [(f"{parent}/{n}", b) for (n, b) in items]
    if kind == "gzip":
        items = _expand_gzip_bytes(buf, bud)
        return [(f"{parent}/{n}", b) for (n, b) in items]
    # not a container: return as a leaf
    return [(parent, _cap_bytes(buf, bud))]

# ---------- Member classification ----------

_MEDIA_EXTS = {
    "jpg","jpeg","png","gif","webp","bmp","tiff","ico",
    "mp3","m4a","aac","wav","flac","ogg","opus",
    "mp4","m4v","mov","avi","mkv","webm","wmv","riff"
}

_TEXTISH_EXTS = {
    "txt","xml","json","csv","yaml","yml","ini","cfg","conf",
    "html","htm","css","js","md","rst","properties","gradle","pom","mf"
}

_CODE_OR_RUNTIME_EXTS = {
    "class","dex","so","o","a","dll","exe","lib","bin","arsc","oat"
}

def _classify_member(name: str) -> str:
    nm = (name or "").lower()
    if not nm or nm.endswith("/"):
        return "dir"
    ext = _ext_of(nm)
    if nm.startswith("meta-inf/") or "/meta-inf/" in nm:
        return "signature"   # JAR/APK signatures
    if ext in _MEDIA_EXTS:
        return "media"
    if ext in _TEXTISH_EXTS or nm.endswith(".xml"):
        return "text"
    if ext in _CODE_OR_RUNTIME_EXTS:
        return "code"
    return "other"

# ---------- Handler ----------

class ZipContainerHandler:
    """
    Generic ZIP/JAR/APK handler with decoded-leaf flattening.

    Policy:
      - If EOCD/CD parse fails or ZIP64 present → KEEP only tail-overlapping regions (metadata); others benign.
      - For each region:
          * If it overlaps Central Directory or EOCD:
              - χ²/ASCII/token on a bounded raw slice; keep ONLY if sizable overlap and uniform-like.
          * If it overlaps one or more members:
              - If entry has encryption bit (flags & 0x1) or AES → KEEP (suspicious).
              - Build a decoded-leaf set:
                  · STORE  → raw bytes
                  · DEFLATE → inflated bytes
                  · Recurse into nested ZIP/GZIP until leaf or limits
              - Leaf decision:
                  · media (by magic or ext): compare decoded SHA-256 to ctx.trusted_hashes; if magic sane → benign; mismatch → KEEP.
                  · textish (by ext or content traits): χ² + ASCII/token on decoded bytes:
                        plaintext-like ⇒ DROP; uniform-like (and long) ⇒ KEEP.
                  · code/runtime/signature/other: benign by default; do NOT KEEP purely by entropy.
          * Gaps (no metadata, no members): small → benign; large and uniform → KEEP.
      - keep_file = any(region.keep == True).
    """
    exts = EXTS

    @staticmethod
    def supports(ext: str, magic: Optional[bytes]) -> bool:
        e = (ext or "").lstrip(".").lower()
        return (e in ZipContainerHandler.exts) or _looks_like_zip(magic or b"")

    def decide(self, ctx: FileContext, reg: SuspiciousFileRegion) -> FileAwareDecision:
        # Require FS access
        if not ctx.fs_root:
            # lightweight debug helper (works even before params below)
            zip_debug = bool((ctx.params or {}).get("zip_debug", False))
            if zip_debug:
                print(f"[ZIP][DBG] file={ctx.file_path} no fs_root → escalate all")

            return FileAwareDecision(
                keep_file=True,
                reason="zip: no fs_root; escalate",
                region_decisions=[
                    RegionDecision(start=s, end=e, keep=True, reason="zip: no fs_root; escalate")
                    for (s, e) in (reg.byte_ranges or [])
                ] or None,
            )

        ap = os.path.join(ctx.fs_root, ctx.file_path.lstrip("/"))

        # Debug toggle
        zip_debug = bool(ctx.params.get("zip_debug", False))
        def _dbg(msg: str):
            if zip_debug:
                try: print(msg, flush=True)
                except Exception: pass

        # Tunables (defaults chosen conservatively)
        decompress_budget   = int(ctx.params.get("decompress_budget_bytes", 32 * 1024 * 1024))
        hash_budget         = int(ctx.params.get("hash_budget_bytes", 64 * 1024 * 1024))
        chi2_thresh         = float(ctx.params.get("chi2_uniform_thresh", 350.0))
        ascii_min           = float(ctx.params.get("ascii_min_ratio", 0.25))    # for content/textish
        token_min           = float(ctx.params.get("token_min_ratio", 0.02))
        meta_ascii_min      = float(ctx.params.get("meta_ascii_min_ratio", 0.10))
        min_region_len      = int(ctx.params.get("min_region_len_bytes", 4096))
        meta_min_overlap    = int(ctx.params.get("meta_min_overlap_bytes", 8192))
        gap_large_thresh    = int(ctx.params.get("gap_large_bytes", 64 * 1024))
        min_slice_len       = int(ctx.params.get("min_region_len_slice", 128))
        # Parse-fail fallback tail guard
        tail_guard_bytes    = int(ctx.params.get("zip_tail_guard_bytes", 128 * 1024))

        # Flatten budgets
        max_recursion_depth = int(ctx.params.get("max_recursion_depth", 3))
        max_total_decoded   = int(ctx.params.get("max_total_decoded_bytes", 256 * 1024 * 1024))
        max_components      = int(ctx.params.get("max_components", 5000))
        per_component_budget= int(ctx.params.get("per_component_budget", 32 * 1024 * 1024))

        # Trust set for decoded payloads
        trusted_components = set((ctx.trusted_hashes or []))

        # Parse directory
        entries, eocd, err = _parse_directory_and_entries(ap)
        file_size = os.path.getsize(ap)
        _dbg(f"[ZIP][DBG] file={ctx.file_path} size={file_size} "
             f"entries={len(entries)} err={'OK' if not err else err}")
         
        # If parse failed: only keep regions overlapping the metadata tail
        if err:
            tail_s = max(0, file_size - tail_guard_bytes)
            region_out: List[RegionDecision] = []
            any_keep = False
            for (s, e) in (reg.byte_ranges or []):
                s0, e0 = _clip(int(s), int(e), 0, max(0, file_size - 1))
                overlaps_tail = _any_overlap(s0, e0, tail_s, file_size - 1)
                keep = bool(overlaps_tail)
                _dbg(f"[ZIP][REG][PARSE-FAIL] region=[{s0}..{e0}] "
                     f"tail=[{tail_s}..{file_size-1}] ov={overlaps_tail} "
                     f"→ keep={keep}")
                any_keep = any_keep or keep
                reason = err if overlaps_tail else "zip: benign (parse failed; outside tail)"
                region_out.append(RegionDecision(start=int(s), end=int(e), keep=keep, reason=reason))
            file_reason = err if any_keep else "zip: parse failed; no tail overlap"
            return FileAwareDecision(keep_file=any_keep, reason=file_reason, region_decisions=region_out or None)

        # Normal path with metadata spans
        cd_s, cd_e = eocd["cd_span"]
        eocd_s, eocd_e = eocd["eocd_span"]
        _dbg(f"[ZIP][DBG] cd_span=[{cd_s}..{cd_e}] eocd_span=[{eocd_s}..{eocd_e}]")
        meta_spans = [(cd_s, cd_e), (eocd_s, eocd_e)]

        # Quick index for members
        members = entries  # already have data_start/end_incl

        def _overlapping_members(s: int, e: int) -> List[_ZipEntry]:
            return [m for m in members if _any_overlap(s, e, m.data_start, m.data_end_incl)]

        def _overlap_metadata(s: int, e: int) -> int:
            return sum(_overlap_len(s, e, ms, me) for (ms, me) in meta_spans)

        region_out: List[RegionDecision] = []
        any_keep = False
        kept_due_to_nested_meta = False
        
        for (s, e) in (reg.byte_ranges or []):
            _dbg(f"[ZIP][REG] file={ctx.file_path} region=[{int(s)}..{int(e)}]")
            keep = False
            reason = "zip: benign"
            try:
                s0, e0 = _clip(int(s), int(e), 0, max(0, file_size - 1))
                if s0 > e0:
                    region_out.append(RegionDecision(start=int(s), end=int(e), keep=False, reason="zip: empty"))
                    continue

                # 1) Member overlaps? (OOXML parity: member-evidence-first)
                ov = _overlapping_members(s0, e0)

                if ov:
                    _dbg(f"[ZIP][REG][MEM] overlaps={len(ov)}")
                else:
                    _dbg(f"[ZIP][REG][MEM] overlaps=0")

                # 4) Evaluate against overlapping members; keep if ANY says suspicious
                reasons: List[str] = []
                member_keep = False

                for ent in ov:
                    # Load member payload once (inflated for DEFLATE, raw for STORE/unknown)
                    # This is bounded by per_component_budget to avoid excessive work.
                    payload, _is_full = _member_payload(ap, ent, budget=per_component_budget)

                    # Encryption bit or AES -> definite suspicious
                    if (ent.flags & 0x1) != 0 or ent.is_aes:
                        member_keep = True
                        reasons.append(f"zip: member encrypted ({ent.name})")
                        continue

                    if not payload:
                        # Escalate only when full-member inflate from true data_start fails for DEFLATE.
                        # (No raw tiny-head probes.)
                        if ent.method == METHOD_DEFLATE and (ent.flags & 0x1) == 0:
                            member_keep = True
                            reasons.append(f"zip: deflate inflate failure ({ent.name})")
                        else:
                            # Keep previous behavior for other cases (unknown methods, encrypted members, etc.)
                            # Note: encrypted members are handled earlier via (flags & 0x1) or AES extra.
                            reasons.append(f"zip: undecodable ({ent.name})")
                        continue
                    
                    # Flatten nested containers into decoded leaves
                    bud = _ExpandBudget(
                        max_depth=max_recursion_depth,
                        decoded_limit=max_total_decoded,
                        component_limit=max_components,
                        per_component_budget=per_component_budget,
                    )
                    leaves: List[Tuple[str, bytes]] = []
                    k0 = _magic(payload[:8])
                    if _is_container(k0) and bud.max_depth > 0:
                        bud.depth = 1
                        leaves = _expand_nested(payload, ent.name or "_.zip", bud)
                    else:
                        leaves = [(ent.name or "_.member", _cap_bytes(payload, bud))]

                    # Decide on leaves
                    for (leaf_name, leaf_view) in leaves:
                        if not leaf_view:
                            continue
                        k = _magic(leaf_view[:8])
                        ext = _ext_of(leaf_name)
                        # MEDIA path: prefer semantics over entropy
                        if k in ("jpeg","png","mp3","riff") or ext in _MEDIA_EXTS:
                            # normalized decoded hash (not raw inside ZIP)
                            mh = _sha256_bytes(leaf_view)
                            if mh and mh in trusted_components:
                                reasons.append(f"zip: media trusted ({leaf_name})")
                                continue
                            # If magic says media and looks sane -> benign; if name says media but magic not -> suspicious
                            if k in ("jpeg","png","mp3","riff"):
                                reasons.append(f"zip: media sane ({leaf_name})")
                                continue
                            else:
                                member_keep = True
                                reasons.append(f"zip: media type mismatch ({leaf_name})")
                                continue

                        # TEXTISH: by ext or content traits
                        head = leaf_view[:max(8192, min(len(leaf_view), 1 << 20))]
                        ascii_r = _ascii_ratio(head)
                        token_r = _token_ratio(head)
                        chi2    = _chi2_uniform(head)
                        if ext in _TEXTISH_EXTS or ascii_r >= 0.35 or token_r >= 0.05:
                            if chi2 <= chi2_thresh and ascii_r < ascii_min and token_r < token_min and len(leaf_view) >= min_region_len:
                                member_keep = True
                                reasons.append(f"zip: text uniform-like ({leaf_name})")
                            else:
                                reasons.append(f"zip: text plaintext-like ({leaf_name})")
                            continue

                        # CODE/SIGNATURE/OTHER: benign by default; don't KEEP purely by entropy
                        cls = _classify_member(leaf_name)
                        if cls in ("code", "signature"):
                            reasons.append(f"zip: {cls} benign ({leaf_name})")
                        else:
                            # fallback observation (non-binding)
                            if chi2 <= chi2_thresh and ascii_r < ascii_min and len(leaf_view) >= min_region_len:
                                reasons.append(f"zip: other high-entropy ({leaf_name})")
                            else:
                                reasons.append(f"zip: other benign ({leaf_name})")

                if ov:
                    # Aggregate member-first decision
                    if member_keep:
                        # Prefer explicit suspicious reasons
                        strong = [r for r in reasons if ("encrypted" in r)
                                  or ("uniform-like" in r)
                                  or ("mismatch" in r)
                                  or ("inflate failure" in r)]
                        reason = "; ".join(strong[:3]) if strong else (reasons[0] if reasons else "zip: suspicious")
                        keep = True
                        _dbg(f"[ZIP][REG][MEM] DECISION KEEP reason={reason}")
                    else:
                        for key in ("trusted", "plaintext-like", "media sane", "benign"):
                            matches = [r for r in reasons if key in r]
                            if matches:
                                reason = matches[0]
                                break
                        else:
                            reason = reasons[0] if reasons else "zip: benign"
                        keep = False
                        _dbg(f"[ZIP][REG][MEM] DECISION DROP reason={reason}")
                    any_keep = any_keep or keep
                    region_out.append(RegionDecision(start=int(s), end=int(e), keep=keep, reason=reason))
                    continue

                # ---- No member overlap → handle metadata (CD/EOCD) WITHOUT meta_min_overlap gate
                meta_ov = _overlap_metadata(s0, e0)
                _dbg(f"[ZIP][REG][META] region=[{s0}..{e0}] meta_ov={meta_ov} meta_min_overlap={meta_min_overlap} (ignored)")
                if meta_ov > 0:
                    raw = _read_span(ap, s0, e0, cap=min(decompress_budget, 1_048_576))
                    if len(raw) < min_slice_len:
                        # treat tiny slices as benign (OOXML-style small floor)
                        ascii_r = _ascii_ratio(raw)
                        chi2_d  = _chi2_uniform(raw)
                        _dbg(f"[ZIP][REG][META] small/plain len={len(raw)} chi2={chi2_d:.3f} ascii={ascii_r:.3f} → drop")
                        keep, reason = False, "zip: metadata small/plaintext-like"
                    else:
                        chi2 = _chi2_uniform(raw)
                        ascii_r = _ascii_ratio(raw)
                        token_r = _token_ratio(raw)
                        if chi2 <= chi2_thresh and ascii_r < meta_ascii_min and token_r < token_min:
                            _dbg(f"[ZIP][REG][META] KEEP (uniform) chi2={chi2:.3f} ascii={ascii_r:.3f}")
                            keep, reason = True, "zip: metadata encrypted (uniform)"
                            kept_due_to_nested_meta = True
                        else:
                            _dbg(f"[ZIP][REG][META] drop (structured) chi2={chi2:.3f} ascii={ascii_r:.3f}")
                            keep, reason = False, "zip: metadata structured"
                    any_keep = any_keep or keep
                    region_out.append(RegionDecision(start=int(s), end=int(e), keep=keep, reason=reason))
                    continue

                # ---- Gap area (no member, no metadata)
                _dbg(f"[ZIP][REG][GAP] region=[{s0}..{e0}] no member/metadata overlap")
                raw = _read_span(ap, s0, e0, cap=min(decompress_budget, 1_048_576))
                if (e0 - s0 + 1) < gap_large_thresh:
                    keep, reason = False, "zip: small gap"
                else:
                    chi2 = _chi2_uniform(raw)
                    ascii_r = _ascii_ratio(raw)
                    token_r = _token_ratio(raw)
                    if chi2 <= chi2_thresh and ascii_r < ascii_min and token_r < token_min:
                        _dbg(f"[ZIP][REG][GAP] KEEP (uniform) chi2={chi2:.3f} ascii={ascii_r:.3f} token={token_r:.3f}")
                        keep, reason = True, "zip: large gap uniform-like"
                    else:
                        _dbg(f"[ZIP][REG][GAP] drop (structured) chi2={chi2:.3f} ascii={ascii_r:.3f} token={token_r:.3f}")
                        keep, reason = False, "zip: large gap structured"
                any_keep = any_keep or keep
                region_out.append(RegionDecision(start=int(s), end=int(e), keep=keep, reason=reason))
                continue

            except Exception as ex:
                keep, reason = True, f"zip: analysis error; escalate ({ex})"
                _dbg(f"[ZIP][REG][ERR] region=[{s0}..{e0}] → keep=True reason={reason}")
                
            any_keep = any_keep or keep
            region_out.append(RegionDecision(start=int(s), end=int(e), keep=bool(keep), reason=str(reason)))

        if any_keep:
            if kept_due_to_nested_meta:
                file_reason = "zip: nested metadata encrypted"
            else:
                file_reason = "zip: suspicious regions kept"
        else:
            file_reason = "zip: all regions dropped"
        _dbg(f"[ZIP][FILE] file={ctx.file_path} keep_file={any_keep} reason={file_reason}")
        return FileAwareDecision(keep_file=any_keep, reason=file_reason, region_decisions=region_out or None)
