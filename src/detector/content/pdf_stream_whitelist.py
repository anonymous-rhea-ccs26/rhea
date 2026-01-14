#!/usr/bin/env python3
"""
pdf_stream_whitelist.py

Generate a whitelist (hash manifest) of PDF image/font stream payloads.

Policy / Contract assumptions (caller responsibility)
- PDFs are "clean": no incremental updates, no duplicated xref history retained.
- Tools in the pipeline MUST NOT recompress or rewrite image/font payload bytes.
- Any violation of these contracts can be treated as an attack.

What this script does
- Scans each input PDF and finds:
  (1) Image streams: stream dict contains /Subtype /Image
  (2) Font streams: objects referenced by /FontFile, /FontFile2, /FontFile3
- For each selected stream object, hashes the *raw stream payload bytes*
  (bytes between 'stream' and 'endstream', excluding the delimiter EOL
   immediately preceding 'endstream').
- Writes a JSON whitelist file.

Output
- A run directory under --output-path:
    run_YYYYmmdd-HHMMSS_mode-pdf_stream_whitelist/
      - config.json
      - pdf_stream_whitelist.json

Whitelist format (v1)
{
  "version": 1,
  "hash_alg": "sha256",
  "generated_at": "...",
  "entries": [
    {
      "pdf_path": "...",
      "pdf_sha256": "...",
      "file_size": 123,
      "streams": [
        {"obj": 12, "gen": 0, "kind": "image", "sha256": "...", "length": 4567},
        {"obj": 34, "gen": 0, "kind": "font",  "sha256": "...", "length": 8910}
      ]
    }
  ]
}
"""

from __future__ import annotations

import argparse
import json
import os
import re
import hashlib
from dataclasses import dataclass
from datetime import datetime
from typing import Dict, List, Optional, Tuple


# ----------------------------
# Helpers: run directory
# ----------------------------

def create_run_directory(output_root: str) -> str:
    os.makedirs(output_root, exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    base = f"run_{timestamp}_mode-pdf_stream_whitelist"
    run_dir = os.path.join(output_root, base)

    suff = 1
    unique = run_dir
    while os.path.exists(unique):
        unique = f"{run_dir}_{suff}"
        suff += 1
    os.makedirs(unique, exist_ok=False)
    return unique


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


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: str, chunk_size: int = 1024 * 1024) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while True:
            b = f.read(chunk_size)
            if not b:
                break
            h.update(b)
    return h.hexdigest()


# ----------------------------
# PDF scanning: objects + streams
# ----------------------------

OBJ_HDR_RE = re.compile(rb"(?m)^[ \t]*([0-9]+)[ \t]+([0-9]+)[ \t]+obj\b")
FONT_REF_RE = re.compile(rb"/FontFile(?:2|3)?[ \t\r\n]+([0-9]+)[ \t]+([0-9]+)[ \t]+R\b")
SUBTYPE_IMAGE_RE = re.compile(rb"/Subtype[ \t\r\n]+/Image\b")


@dataclass(frozen=True)
class StreamHit:
    obj: int
    gen: int
    kind: str          # "image" or "font"
    payload_sha256: str
    payload_len: int


def _find_stream_bounds(buf: bytes, start_search: int, end_limit: int) -> Optional[Tuple[int, int, int]]:
    """
    Find 'stream' ... 'endstream' within [start_search, end_limit).
    Returns (stream_kw_off, payload_start, payload_end_excl) or None.

    payload_end_excl excludes the delimiter EOL right before 'endstream'
    if it is a clean CR/LF/CRLF.
    """
    stream_kw = buf.find(b"stream", start_search, end_limit)
    if stream_kw < 0:
        return None

    # 'stream' must be followed by EOL (spec-ish). We'll accept spaces then EOL.
    i = stream_kw + len(b"stream")
    while i < end_limit and buf[i] in b" \t":
        i += 1

    # expect EOL
    if i >= end_limit:
        return None

    if buf[i:i+2] == b"\r\n":
        payload_start = i + 2
    elif buf[i:i+1] == b"\n":
        payload_start = i + 1
    elif buf[i:i+1] == b"\r":
        payload_start = i + 1
    else:
        # Not a well-formed stream delimiter. Still treat as no-stream.
        return None

    endstream_kw = buf.find(b"endstream", payload_start, end_limit)
    if endstream_kw < 0:
        return None

    payload_end = endstream_kw

    # Exclude the EOL immediately before endstream if present (typical writer behavior).
    if payload_end >= 2 and buf[payload_end-2:payload_end] == b"\r\n":
        payload_end -= 2
    elif payload_end >= 1 and buf[payload_end-1:payload_end] in (b"\n", b"\r"):
        payload_end -= 1

    if payload_end < payload_start:
        return None

    return (stream_kw, payload_start, payload_end)


def _extract_nearby_dict(buf: bytes, obj_start: int, stream_kw_off: int, max_back_window: int = 64 * 1024) -> bytes:
    """
    Best-effort extraction of the stream dictionary preceding 'stream'.
    We search backward from stream_kw_off to find the last '<<' and '>>' pair.
    This is intentionally simple and contract-oriented.
    """
    lo = max(obj_start, stream_kw_off - max_back_window)
    chunk = buf[lo:stream_kw_off]

    # find the last '<<' before stream
    dd = chunk.rfind(b"<<")
    if dd < 0:
        return b""
    dd_abs = lo + dd

    # find the first '>>' after that
    ee = buf.find(b">>", dd_abs, stream_kw_off)
    if ee < 0:
        return b""
    return buf[dd_abs:ee+2]


def scan_pdf_for_image_and_font_streams(buf: bytes) -> List[StreamHit]:
    """
    Returns StreamHit list. All hashing is sha256(raw_stream_payload).
    """
    # 1) collect font stream object numbers via /FontFile references
    font_obj_nums = set()
    for m in FONT_REF_RE.finditer(buf):
        obj = int(m.group(1))
        font_obj_nums.add(obj)

    hits: List[StreamHit] = []

    # 2) enumerate indirect objects; within each, look for a stream
    objs = list(OBJ_HDR_RE.finditer(buf))
    for idx, m in enumerate(objs):
        obj = int(m.group(1))
        gen = int(m.group(2))
        obj_start = m.start()

        obj_end = objs[idx + 1].start() if idx + 1 < len(objs) else len(buf)

        sb = _find_stream_bounds(buf, start_search=m.end(), end_limit=obj_end)
        if sb is None:
            continue

        stream_kw_off, payload_start, payload_end = sb
        dct = _extract_nearby_dict(buf, obj_start=obj_start, stream_kw_off=stream_kw_off)

        is_image = bool(SUBTYPE_IMAGE_RE.search(dct))
        is_font = (obj in font_obj_nums)

        if not is_image and not is_font:
            continue

        payload = buf[payload_start:payload_end]
        h = sha256_hex(payload)

        hits.append(
            StreamHit(
                obj=obj,
                gen=gen,
                kind=("image" if is_image else "font"),
                payload_sha256=h,
                payload_len=len(payload),
            )
        )

    return hits


# ----------------------------
# CLI
# ----------------------------

def parse_args(argv: Optional[List[str]] = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Generate a whitelist of PDF image/font stream payload hashes (sha256)."
    )
    p.add_argument("--input-path", required=True, help="PDF file or flat directory (no recursion).")
    p.add_argument("--output-path", required=True, help="Root output directory.")
    p.add_argument("--only-pdf-ext", action="store_true", default=True,
                   help="Process only .pdf extension files (default on).")
    p.add_argument("--allow-non-pdf-ext", dest="only_pdf_ext", action="store_false",
                   help="Also scan non-.pdf files (not recommended).")
    return p.parse_args(argv)


def main(argv: Optional[List[str]] = None) -> None:
    args = parse_args(argv)

    files = discover_files(args.input_path)
    if args.only_pdf_ext:
        files = [p for p in files if os.path.splitext(p)[1].lower() == ".pdf"]

    if not files:
        raise SystemExit("No input files to scan.")

    run_dir = create_run_directory(args.output_path)

    cfg_path = os.path.join(run_dir, "config.json")
    with open(cfg_path, "w", encoding="utf-8") as f:
        json.dump(
            {
                "input_path": os.path.abspath(args.input_path),
                "mode": "pdf_stream_whitelist",
                "timestamp": datetime.now().isoformat(),
                "only_pdf_ext": bool(args.only_pdf_ext),
                "hash_alg": "sha256",
                "contract": {
                    "no_incremental_updates": True,
                    "no_recompression_or_optimization": True,
                    "payload_hashing_is_raw_stream_bytes": True,
                    "stream_types": ["image", "font"],
                },
            },
            f,
            indent=2,
        )

    out_path = os.path.join(run_dir, "pdf_stream_whitelist.json")
    out_obj = {
        "version": 1,
        "hash_alg": "sha256",
        "generated_at": datetime.now().isoformat(),
        "entries": [],
    }

    for path in files:
        st = os.stat(path)
        with open(path, "rb") as fp:
            buf = fp.read()

        pdf_hash = sha256_hex(buf)
        hits = scan_pdf_for_image_and_font_streams(buf)

        out_obj["entries"].append(
            {
                "pdf_path": os.path.abspath(path),
                "pdf_sha256": pdf_hash,
                "file_size": int(st.st_size),
                "streams": [
                    {
                        "obj": h.obj,
                        "gen": h.gen,
                        "kind": h.kind,
                        "sha256": h.payload_sha256,
                        "length": h.payload_len,
                    }
                    for h in hits
                ],
            }
        )

    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(out_obj, f, indent=2)

    print(f"Whitelist generation complete. Written to: {out_path}")


if __name__ == "__main__":
    main()
