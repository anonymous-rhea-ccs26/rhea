#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
pdf_partition.py — Partition a PDF into members (streams) and, for content-like streams,
into fine-grained zones (comment, literal_string, hex_string, inline image dict/payload, syntax).
Also mark DEFLATE (zlib) locations:
  - Declared FlateDecode streams (validate header, inflate)
  - Embedded zlib headers inside raw member bytes (inflate attempt)
  - Raw-DEFATE "islands" (wbits=-15) inside members
  - The same, per-zone (when --dump-zones)

Usage:
  python3 pdf_partition.py file.pdf [--dump-zones] [--json out.json]
"""

import argparse
import json
import os
import re
import sys
import zlib
from typing import List, Tuple, Dict, Any, Optional

PDF_HEADER_RE = re.compile(rb"%PDF-\d\.\d")
OBJ_START_RE  = re.compile(rb"\b(\d+)\s+(\d+)\s+obj\b")
OBJ_END_RE    = re.compile(rb"\bendobj\b")
DICT_BACK_RE  = re.compile(rb"<<.*?>>", re.DOTALL)
FILTER_RE     = re.compile(rb"/Filter\s+(?P<val>(\[.*?\]|/\S+))", re.DOTALL)
NAME_RE       = re.compile(rb"/([A-Za-z0-9\-\+\.]+)")
DECODEPARMS_RE= re.compile(rb"/DecodeParms\s+(?P<val>(\[.*?\]|<<.*?>>))", re.DOTALL)

# ---------- tiny helpers ----------

def read_bytes(path: str, start: int, end_incl: int) -> bytes:
    if end_incl < start:
        return b""
    with open(path, "rb") as f:
        f.seek(start)
        return f.read(end_incl - start + 1)

def ascii_ratio(b: bytes) -> float:
    if not b:
        return 0.0
    return sum(1 for c in b if c in (9,10,13) or 32 <= c <= 126) / len(b)

def norm_filter_name(f: bytes) -> bytes:
    f = (f or b"").strip()
    m = re.match(rb"^([A-Za-z0-9\-\+\.]+)$", f)
    if m:
        return m.group(1)
    m = NAME_RE.match(b"/" + f)
    return m.group(1) if m else f

def parse_filter_names(val: bytes) -> List[bytes]:
    if not val:
        return []
    val = val.strip()
    if val.startswith(b"["):
        return [norm_filter_name(m.group(1)) for m in NAME_RE.finditer(val)]
    elif val.startswith(b"/"):
        m = NAME_RE.match(val)
        return [norm_filter_name(m.group(1))] if m else []
    return []

def zlib_header_ok(b: bytes) -> bool:
    if len(b) < 2:
        return False
    cmf, flg = b[0], b[1]
    if (cmf & 0x0F) != 8:   # CM = 8 (DEFLATE)
        return False
    if (cmf >> 4) > 7:      # CINFO <= 7 (32K window)
        return False
    return (((cmf << 8) | flg) % 31) == 0

def zlib_candidates(b: bytes, max_hits: int = 64) -> List[int]:
    hits = []
    i, L = 0, len(b)
    while i + 1 < L and len(hits) < max_hits:
        if b[i] == 0x78 and b[i+1] in (0x01, 0x5E, 0x9C, 0xDA):
            if (((0x78 << 8) | b[i+1]) % 31) == 0:
                hits.append(i)
                # step a little to avoid re-hitting same place
                i += 2
                continue
        i += 1
    return hits

def try_inflate_from(b: bytes, off: int) -> Tuple[bool, Optional[int], Optional[str]]:
    try:
        out = zlib.decompress(b[off:])
        return True, len(out), None
    except Exception as e:
        return False, None, f"{type(e).__name__}: {e}"

def find_raw_deflate_islands(b: bytes, max_tries: int = 16) -> List[Dict[str, Any]]:
    """
    Sweep for raw-DEFATE (no zlib wrapper). We try a handful of offsets.
    """
    L = len(b)
    if L < 64:
        return []
    # step roughly proportional to size, but bounded
    step = max(32, min(256, L // (max_tries * 4)))
    out: List[Dict[str, Any]] = []
    tried = 0
    j = 0
    while j < L - 32 and tried < max_tries:
        d = zlib.decompressobj(wbits=-15)
        try:
            chunk = d.decompress(b[j:j+65536]) + d.flush()
            if chunk:
                out.append({"rel_off": j, "out_len": len(chunk)})
        except Exception:
            pass
        tried += 1
        j += step
    return out

def looks_textish_stream_dict(d: bytes) -> bool:
    # heuristic: content/XMP/metadata-like
    return (b"/Type/Metadata" in d or b"/Subtype/XML" in d or
            (b"/Length" in d and b"/Subtype" not in d and b"/Type/XRef" not in d and b"/Type/ObjStm" not in d))

def is_contentish_raw(buf: bytes) -> bool:
    if not buf:
        return False
    # cheap: look for common operators and BT..ET ordering
    ops = [b"BT", b"ET", b"Tj", b"TJ", b"Tf", b"Td", b"Tm", b"Tr", b"Ts", b"Tw", b"Tc"]
    hits = sum(buf.count(op) for op in ops)
    if hits >= 2:
        # mild paren sanity
        bal, esc = 0, False
        for c in buf[:200000]:
            if esc:
                esc = False; continue
            if c == 0x5C: esc = True; continue
            if c == 0x28: bal += 1
            elif c == 0x29 and bal > 0: bal -= 1
        return bal < 32
    i_bt, i_et = buf.find(b"BT"), buf.find(b"ET")
    return (i_bt != -1 and i_et != -1 and i_bt < i_et)

# ---------- tokenizer for zones inside (decoded) content-like streams ----------

def tokenize_zones(buf: bytes) -> List[Dict[str, Any]]:
    """
    Return list of zones in a decoded (or raw-contentish) stream.
    Kinds: comment, literal_string, hex_string, inline_image_dict, inline_image_payload, syntax
    """
    zones: List[Dict[str, Any]] = []
    L = len(buf)
    i = 0
    in_comment = False
    in_lit = False; lit_depth = 0; lit_escape = False; lit_s = -1
    in_hex = False; hex_s = -1
    in_iid = False
    in_iip = False
    payload_s = None

    def is_delim(x: Optional[int]) -> bool:
        if x is None: return True
        return x in (0x00, 0x09, 0x0A, 0x0D, 0x20, 0x28, 0x29, 0x3C, 0x3E, 0x5B, 0x5D, 0x7B, 0x7D, 0x2F)

    def match_kw(i: int, kw: bytes) -> bool:
        k = len(kw)
        if i < 0 or i + k > L: return False
        prev = buf[i-1] if i > 0 else None
        nxt  = buf[i+k] if i+k < L else None
        return buf[i:i+k] == kw and is_delim(prev) and is_delim(nxt)

    # accumulate ASCII-constrained runs as we go
    syn_s = 0

    def flush_syntax(run_end_excl: int):
        nonlocal syn_s
        if run_end_excl > syn_s:
            zones.append({"kind": "syntax", "start": syn_s, "end": run_end_excl - 1})
        syn_s = run_end_excl

    while i < L:
        c = buf[i]
        nxt = buf[i+1] if i+1 < L else None

        if in_iip:
            # end payload at 'EI' boundary
            if match_kw(i, b"EI"):
                zones.append({"kind": "inline_image_payload", "start": payload_s if payload_s is not None else syn_s, "end": i-1})
                in_iip = False
                i += 2
                syn_s = i
                continue
            i += 1
            continue

        if in_comment:
            if c in (0x0A, 0x0D):
                zones.append({"kind": "comment", "start": syn_s, "end": i})
                in_comment = False
                i += 1
                syn_s = i
                continue
            i += 1
            continue

        if in_lit:
            if lit_escape: lit_escape = False; i += 1; continue
            if c == 0x5C: lit_escape = True; i += 1; continue
            if c == 0x28: lit_depth += 1; i += 1; continue
            if c == 0x29:
                lit_depth = max(0, lit_depth-1); i += 1
                if lit_depth == 0:
                    zones.append({"kind": "literal_string", "start": lit_s, "end": i-2})
                    syn_s = i
                    in_lit = False
                continue
            i += 1
            continue

        if in_hex:
            if c == 0x3E:  # '>'
                zones.append({"kind": "hex_string", "start": hex_s, "end": i-1})
                i += 1
                syn_s = i
                in_hex = False
                continue
            i += 1
            continue

        if in_iid:
            if match_kw(i, b"ID"):
                zones.append({"kind": "inline_image_dict", "start": syn_s, "end": i-1})
                in_iid = False
                in_iip = True
                i += 2
                if i < L and buf[i] in (0x20,0x0D,0x0A,0x09,0x0C,0x00):
                    i += 1
                payload_s = i
                syn_s = i
                continue
            i += 1
            continue

        # outside protected zones
        if c == 0x25:  # '%'
            flush_syntax(i)
            in_comment = True
            i += 1
            continue

        if c == 0x28:  # '('
            flush_syntax(i)
            in_lit = True; lit_depth = 1; lit_escape = False; lit_s = i+1
            i += 1
            continue

        if c == 0x3C:  # '<' or '<<'
            if nxt == 0x3C:
                i += 2
                continue
            flush_syntax(i)
            in_hex = True; hex_s = i+1
            i += 1
            continue

        if match_kw(i, b"BI"):
            flush_syntax(i)
            in_iid = True
            i += 2
            continue

        i += 1

    # tail syntax
    flush_syntax(L)
    return [z for z in zones if z["end"] >= z["start"]]

# ---------- stream scan ----------

class StreamRec:
    def __init__(self, dict_start: int, dict_end: int, data_start: int, data_end: int, dict_bytes: bytes):
        self.dict_start = dict_start
        self.dict_end = dict_end
        self.data_start = data_start
        self.data_end = data_end
        self.dict_bytes = dict_bytes
        # Extract /Filter names safely from the dictionary bytes
        if dict_bytes:
            _m = FILTER_RE.search(dict_bytes)
            self.filters = parse_filter_names(_m.group("val")) if _m else []
        else:
            self.filters = []
        self.declared_flate = any(norm_filter_name(f) == b"FlateDecode" for f in self.filters)

def scan_streams(path: str) -> List[StreamRec]:
    size = os.path.getsize(path)
    mm = read_bytes(path, 0, size - 1)  # read entire file into bytes to avoid mmap buffer issues
    if not PDF_HEADER_RE.search(mm[:64]):
        return []
    streams: List[StreamRec] = []
    start = 0
    while True:
        s_idx = mm.find(b"stream", start)
        if s_idx < 0:
            break
        # ignore "...endstream"
        if s_idx >= 3 and mm[s_idx-3:s_idx] == b"end":
            start = s_idx + 6; continue

        # find EOL after 'stream'
        scan_end = min(size, s_idx + 2048)
        cr = mm.find(b"\r", s_idx, scan_end)
        lf = mm.find(b"\n", s_idx, scan_end)
        if cr == -1 and lf == -1:
            start = s_idx + 6; continue
        if cr != -1 and lf != -1 and lf == cr + 1:
            data_start = lf + 1
        elif lf != -1 and (cr == -1 or lf < cr):
            data_start = lf + 1
        else:
            data_start = cr + 1

        e_idx = mm.find(b"endstream", data_start)
        if e_idx < 0:
            start = s_idx + 6; continue
        data_end = e_idx - 1
        while data_end >= data_start and mm[data_end] in (0x0A, 0x0D):
            data_end -= 1

        # look back up to 64K for dict
        look_back_start = max(0, s_idx - 65536)
        slice_back = mm[look_back_start:s_idx]
        m = None
        for match in DICT_BACK_RE.finditer(slice_back):
            m = match
        if m:
            dict_start = look_back_start + m.start()
            dict_end = look_back_start + m.end()
            dict_bytes = bytes(slice_back[m.start():m.end()])
        else:
            dict_start = dict_end = s_idx
            dict_bytes = b""

        streams.append(StreamRec(dict_start, dict_end, data_start, data_end, dict_bytes))
        start = e_idx + len(b"endstream")
    return streams

# ---------- main analysis ----------

def analyze(path: str, dump_zones: bool) -> Dict[str, Any]:
    size = os.path.getsize(path)
    streams = scan_streams(path)
    out: Dict[str, Any] = {"file_size": size, "members": []}

    for st in streams:
        rec: Dict[str, Any] = {
            "kind": "stream",
            "dict_range": [st.dict_start, st.dict_end],
            "data_range": [st.data_start, st.data_end],
            "filters": [f.decode("latin-1", "ignore") for f in st.filters],
            "declared_flate": bool(st.declared_flate),
            "declared_zlib_header_at0": None,
            "declared_inflate_ok": None,
            "declared_inflate_error": None,
            "declared_decoded_len": None,
            "embedded_zlib_headers": [],
            "raw_deflate_islands": [],
            "zones": [],
            "contentish": False,
        }

        raw = read_bytes(path, st.data_start, st.data_end)

        # Declared FlateDecode?
        if st.declared_flate:
            head = raw[:2]
            rec["declared_zlib_header_at0"] = bool(zlib_header_ok(head))
            try:
                dec = zlib.decompress(raw)
                rec["declared_inflate_ok"] = True
                rec["declared_decoded_len"] = len(dec)
            except Exception as e:
                rec["declared_inflate_ok"] = False
                rec["declared_inflate_error"] = f"{type(e).__name__}: {e}"
                dec = None
        else:
            dec = None

        # Embedded zlib headers inside RAW member
        hdr_offs = zlib_candidates(raw, max_hits=64)
        for rel in hdr_offs:
            ok, out_len, err = try_inflate_from(raw, rel)
            rec["embedded_zlib_headers"].append({
                "abs_off": st.data_start + rel,
                "rel_off": rel,
                "inflate_ok": bool(ok),
                "out_len": out_len,
                "error": err
            })

        # Raw-DEFATE islands (w/o wrapper)
        islands = find_raw_deflate_islands(raw, max_tries=16)
        for isl in islands:
            rec["raw_deflate_islands"].append({
                "abs_off": st.data_start + isl["rel_off"],
                "rel_off": isl["rel_off"],
                "out_len": isl["out_len"]
            })

        # Content-like? Use decoded if available; otherwise raw if it "looks contentish"
        content_bytes = dec if dec is not None else (raw if is_contentish_raw(raw) else None)
        rec["contentish"] = bool(content_bytes is not None)

        if dump_zones and content_bytes:
            zones = tokenize_zones(content_bytes)
            for z in zones:
                zrec = {
                    "kind": z["kind"],
                    "rel_start": z["start"],
                    "rel_end": z["end"],
                    "embedded_zlib_headers": [],
                    "raw_deflate_islands": [],
                }
                zbuf = content_bytes[z["start"]:z["end"]+1]
                # scan for zlib headers inside the zone
                zh = zlib_candidates(zbuf, max_hits=16)
                for r in zh:
                    ok, out_len, err = try_inflate_from(zbuf, r)
                    zrec["embedded_zlib_headers"].append({
                        "zone_rel_off": r,
                        "inflate_ok": bool(ok),
                        "out_len": out_len,
                        "error": err
                    })
                # raw-DEFATE islands inside zone
                z_islands = find_raw_deflate_islands(zbuf, max_tries=8)
                for isl in z_islands:
                    zrec["raw_deflate_islands"].append({
                        "zone_rel_off": isl["rel_off"],
                        "out_len": isl["out_len"]
                    })
                rec["zones"].append(zrec)

        out["members"].append(rec)

    return out

# ---------- pretty printing ----------

def pretty_print(report: Dict[str, Any], dump_zones: bool) -> None:
    print(f"# File size: {report['file_size']} bytes")
    for idx, m in enumerate(report["members"]):
        s0, s1 = m["data_range"]
        d0, d1 = m["dict_range"]
        print(f"\n== Member[{idx}] stream data=[{s0},{s1}] dict=[{d0},{d1}] filters={m['filters']}")
        if m["declared_flate"]:
            print(f"   - Declared FlateDecode: zlib_hdr@0={m['declared_zlib_header_at0']} "
                  f"inflated={m['declared_inflate_ok']} len={m['declared_decoded_len']} err={m['declared_inflate_error']}")
        if m["embedded_zlib_headers"]:
            print(f"   - Embedded zlib headers (in RAW):")
            for h in m["embedded_zlib_headers"][:20]:
                print(f"       * abs={h['abs_off']} rel={h['rel_off']} ok={h['inflate_ok']} out_len={h['out_len']} err={h['error']}")
            more = len(m["embedded_zlib_headers"]) - 20
            if more > 0: print(f"       ... (+{more} more)")
        if m["raw_deflate_islands"]:
            print(f"   - Raw-DEFLATE islands (in RAW):")
            for isl in m["raw_deflate_islands"][:20]:
                print(f"       * abs={isl['abs_off']} rel={isl['rel_off']} out_len={isl['out_len']}")
            more = len(m["raw_deflate_islands"]) - 20
            if more > 0: print(f"       ... (+{more} more)")
        print(f"   - contentish={m['contentish']}")
        if dump_zones and m["zones"]:
            print("   - zones:")
            for z in m["zones"][:50]:
                print(f"       [{z['kind']}] rel=[{z['rel_start']},{z['rel_end']}] "
                      f"zlib_hits={len(z['embedded_zlib_headers'])} raw_islands={len(z['raw_deflate_islands'])}")
            more = len(m["zones"]) - 50
            if more > 0: print(f"       ... (+{more} more)")

# ---------- cli ----------

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("pdf")
    ap.add_argument("--dump-zones", action="store_true", help="tokenize contentish streams and scan zones for deflate")
    ap.add_argument("--json", help="write full JSON report to this path")
    args = ap.parse_args()

    if not os.path.isfile(args.pdf):
        print(f"no such file: {args.pdf}", file=sys.stderr)
        sys.exit(2)

    rep = analyze(args.pdf, dump_zones=args.dump_zones)
    pretty_print(rep, dump_zones=args.dump_zones)

    if args.json:
        with open(args.json, "w") as f:
            json.dump(rep, f, indent=2)

if __name__ == "__main__":
    main()
