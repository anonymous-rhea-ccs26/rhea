#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
inspect_pdf_tokens.py — deterministic inspection of PDF literals/hex strings
around a byte range, with TEXT vs CIPHERTEXT verdicts (no chi², no fragment probe).

Usage:
  python3 inspect_pdf_tokens.py <pdf_path> --start 22528 --end 23039 [--radius 16384]

Notes:
- We scan a context window around the provided range and report only tokens
  that overlap [start,end].
- Literal strings are decoded per PDF rules (escapes, octal, line continuations).
- For hex strings <...> we ignore dict '<< >>' and only treat single-angle blocks as hex.
- Verdicts follow deterministic rules discussed in the thread.
"""

import argparse
import os
import re
import zlib
import sys

# ---------- regexes ----------
LIT_RE  = re.compile(rb"\((?:\\.|[^\\\)])*\)", re.DOTALL)
HEX_RE  = re.compile(rb"<[0-9A-Fa-f\s]*?>", re.DOTALL)   # single-angle only (avoid dict '<< >>')
DICT_RE = re.compile(rb"<<.*?>>", re.DOTALL)

# ---------- helpers ----------
def read_ctx(path, start, end, radius=16384, cap=65536):
    fsize = os.path.getsize(path)
    a = max(0, start - radius)
    b = min(fsize - 1, end + radius) if fsize > 0 else 0
    if b < a:
        a, b = 0, min(fsize - 1, cap - 1)
    length = min(cap, b - a + 1)
    with open(path, "rb") as f:
        f.seek(a)
        return f.read(length), a

def ascii_printable_ratio(b: bytes) -> float:
    if not b: return 1.0
    printable = sum(1 for x in b if x in (9,10,13) or 32 <= x <= 126)
    return printable / len(b)

def highbit_ratio(b: bytes) -> float:
    if not b: return 0.0
    return sum(1 for x in b if x >= 0x80) / len(b)

def longest_ascii_run(b: bytes) -> int:
    best = cur = 0
    for x in b:
        if x in (9,10,13) or 32 <= x <= 126:
            cur += 1
            if cur > best: best = cur
        else:
            cur = 0
    return best

def zlib_compress_ratio(sample: bytes) -> float:
    if not sample: return 0.0
    s = sample[:2048]  # cheap, stable signal
    try:
        comp = zlib.compress(s, 6)
        return (len(comp) / len(s)) if s else 0.0
    except Exception:
        return 1.0

def try_decode_utf16_maybe(b: bytes):
    # return (decoded_utf8_bytes|None)
    if len(b) >= 2 and b[:2] in (b"\xFE\xFF", b"\xFF\xFE"):
        try:
            return b.decode("utf-16").encode("utf-8")
        except Exception:
            return None
    # light heuristic: many zeros in even or odd positions → maybe UTF-16BE/LE without BOM
    if len(b) >= 8:
        even_zeros = sum(1 for i in range(0, len(b), 2) if b[i] == 0) / (len(b)//2 or 1)
        odd_zeros  = sum(1 for i in range(1, len(b), 2) if b[i] == 0) / (len(b)//2 or 1)
        try:
            if even_zeros > 0.25:  # likely BE
                return b.decode("utf-16-be").encode("utf-8")
            if odd_zeros  > 0.25:  # likely LE
                return b.decode("utf-16-le").encode("utf-8")
        except Exception:
            return None
    return None

def decode_pdf_literal_string(body: bytes) -> bytes:
    """
    Decode PDF literal string body (without outer parentheses):
      - handle escapes, octal, line continuations
      - return raw bytes (no character-set re-encoding)
    """
    out = bytearray()
    i = 0; L = len(body)
    esc = False
    depth = 0  # we’re already inside a literal; nested '(' increments depth, ')' decrements
    while i < L:
        c = body[i]; i += 1
        if not esc and c == 0x5C:  # '\'
            if i >= L: break
            e = body[i]; i += 1
            if e in b"nrtbf()\\":    # common escapes
                table = {ord('n'):10, ord('r'):13, ord('t'):9, ord('b'):8, ord('f'):12,
                         ord('('):0x28, ord(')'):0x29, ord('\\'):0x5C}
                out.append(table[e])
            elif 0x30 <= e <= 0x37:  # octal \ddd
                val = e - 0x30
                for _ in range(2):
                    if i < L and 0x30 <= body[i] <= 0x37:
                        val = (val << 3) + (body[i] - 0x30); i += 1
                    else:
                        break
                out.append(val & 0xFF)
            elif e in (0x0D, 0x0A):  # line continuation
                # optional LF after CR
                if e == 0x0D and i < L and body[i] == 0x0A:
                    i += 1
                # no byte appended
            else:
                out.append(e)
            continue

        # not an escape
        if c == 0x28:  # '('
            depth += 1
            out.append(c)
        elif c == 0x29:  # ')'
            # inner ')' as data if we’re in nested context
            if depth > 0:
                depth -= 1
                out.append(c)
            else:
                # this would be the closing paren of the outer literal, but we never receive it here
                out.append(c)
        else:
            out.append(c)
    return bytes(out)

def decode_hex_string(inner: bytes) -> bytes | None:
    s = re.sub(rb"\s+", b"", inner)
    if len(s) == 0: return b""
    if len(s) % 2 == 1: s += b"0"
    try:
        return bytes.fromhex(s.decode("ascii"))
    except Exception:
        return None

def utf8_ok(b: bytes) -> bool:
    try:
        b.decode("utf-8", "strict")
        return True
    except Exception:
        return False

def classify_token(raw_payload: bytes, textish_expected: bool) -> tuple[str, dict]:
    """
    Returns (verdict, metrics) with verdict in {"TEXT","CIPHERTEXT"}.
    Deterministic, no chi²/fragments.
    """
    metrics = {}
    # 0) Fast path: if it cleanly decodes as UTF-8 and is printable enough, call it TEXT.
    utf8 = utf8_ok(raw_payload)
    pr   = ascii_printable_ratio(raw_payload if utf8 else b"")
    if utf8 and pr >= 0.60:
        metrics.update(dict(utf8_ok=True, printable=pr))
        return "TEXT", metrics

    # Text-ish streams: UTF-8 is REQUIRED
    if textish_expected:
        metrics.update(dict(utf8_ok=utf8, printable=pr))
        return "TEXT", metrics if (utf8 and pr >= 0.60) else ("CIPHERTEXT", metrics)

    # Generic literals/hex (non-textish expected)
    hb = highbit_ratio(raw_payload)
    lr = longest_ascii_run(raw_payload)
    cr = zlib_compress_ratio(raw_payload)
    L  = len(raw_payload)
    metrics.update(dict(utf8_ok=utf8, length=L, printable=ascii_printable_ratio(raw_payload),
                        highbit=hb, longest_ascii_run=lr, zlib_cr=cr))

    # Deterministic fused rules, tuned to catch your FN:
    # A) High-bit heavy AND low printable → ciphertext
    if hb >= 0.30 and metrics["printable"] < 0.60:
        return "CIPHERTEXT", metrics
    # B) Long payload with binary-ish features → ciphertext
    if (L >= 96) and (cr >= 0.97 or (hb >= 0.25 and lr < 24)):
        return "CIPHERTEXT", metrics
    # C) Not UTF-8, somewhat binary distribution and not very printable
    if (not utf8) and (hb >= 0.20) and (metrics["printable"] < 0.75):
        return "CIPHERTEXT", metrics

    return "TEXT", metrics

def overlaps(a0,a1,b0,b1): return not (a1 < b0 or b1 < a0)

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("pdf_path")
    ap.add_argument("--start", type=int, required=True)
    ap.add_argument("--end",   type=int, required=True)
    ap.add_argument("--radius", type=int, default=16384)
    ap.add_argument("--textish", action="store_true",
                    help="Treat tokens as text-ish expected (UTF-8 required).")
    args = ap.parse_args()

    data, base = read_ctx(args.pdf_path, args.start, args.end, radius=args.radius)
    rel_s = max(0, args.start - base)
    rel_e = min(len(data) - 1, args.end - base)

    print(f"# Inspecting tokens in {args.pdf_path} around [{args.start},{args.end}] "
          f"(read_base={base}, size={len(data)})\n")

    caught_any = False

    # ---- Literal strings ----
    print("## Literal strings (…) overlapping")
    lit_hits = 0
    for m in LIT_RE.finditer(data):
        a, b = m.start(), m.end() - 1
        if not overlaps(rel_s, rel_e, a, b): continue
        inner = m.group(0)[1:-1]  # without outer parens
        raw   = decode_pdf_literal_string(inner)

        # try UTF-16 if identifiable; otherwise raw stays as-is
        maybe_utf16 = try_decode_utf16_maybe(raw)
        payload_for_text = maybe_utf16 if (maybe_utf16 is not None) else raw

        verdict, metrics = classify_token(payload_for_text, textish_expected=args.textish)
        if verdict == "CIPHERTEXT": caught_any = True

        pr = metrics.get("printable")
        # preview as Latin-1 to avoid decode errors in terminal
        preview = raw[:96].decode("latin-1", "replace")
        span_abs = (base + a, base + b)
        md = " ".join(f"{k}={v:.3f}" if isinstance(v,float) else f"{k}={v}"
                      for k,v in metrics.items())
        print(f"- {span_abs} len={len(raw)} verdict={verdict} {md} preview='{preview}'")
        lit_hits += 1
    if lit_hits == 0:
        print("- (none overlapping)")

    # ---- Hex strings ----
    print("\n## Hex strings <…> overlapping")
    hex_hits = 0
    # Avoid dicts `<< >>` by skipping any match that is exactly '<<...>>'
    for m in HEX_RE.finditer(data):
        # If this hex is part of a dict '<< >>', skip
        s, e = m.start(), m.end()
        # A crude guard: if there’s a second '<' right at s+1, it's probably '<<'
        if s+1 < len(data) and data[s:s+2] == b"<<":
            continue
        a, b = s, e - 1
        if not overlaps(rel_s, rel_e, a, b): continue

        inner = m.group(0)[1:-1]
        raw = decode_hex_string(inner)
        if raw is None:
            print(f"- {(base+a, base+b)} undecodable HEX (ignored for verdict)")
            continue

        maybe_utf16 = try_decode_utf16_maybe(raw)
        payload_for_text = maybe_utf16 if (maybe_utf16 is not None) else raw

        verdict, metrics = classify_token(payload_for_text, textish_expected=args.textish)
        if verdict == "CIPHERTEXT": caught_any = True

        pr = metrics.get("printable")
        preview = raw[:96].decode("latin-1", "replace")
        md = " ".join(f"{k}={v:.3f}" if isinstance(v,float) else f"{k}={v}"
                      for k,v in metrics.items())
        print(f"- {(base+a, base+b)} len={len(raw)} verdict={verdict} {md} preview='{preview}'")
        hex_hits += 1
    if hex_hits == 0:
        print("- (none overlapping)")

    # ---- Summary ----
    print("\n## Summary")
    if caught_any:
        print("This region WOULD BE CAUGHT as ciphertext by the deterministic rules.")
    else:
        print("This region would NOT be flagged by the deterministic rules.")

if __name__ == "__main__":
    sys.exit(main())
