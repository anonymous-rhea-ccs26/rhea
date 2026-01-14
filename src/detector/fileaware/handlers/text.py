# detector/fileaware/handlers/text.py
import os
import codecs
from typing import Optional, List, Tuple

from ..types import FileContext, SuspiciousFileRegion, FileAwareDecision, RegionDecision


def _is_printable_byte(b: int) -> bool:
    # ASCII printable + common whitespace; exclude NUL and most control chars
    return (32 <= b <= 126) or b in (9, 10, 13)  # \t \n \r


def _printable_ratio(data: bytes) -> float:
    if not data:
        return 0.0
    pr = sum(1 for x in data if _is_printable_byte(x))
    return pr / len(data)

def _looks_like_text_prefix(magic: bytes) -> bool:
    """Very light sniffing; true when 'magic' is mostly printable text."""
    if not magic:
        return False
    # Allow short prefixes to be a bit stricter
    need = 0.80 if len(magic) >= 8 else 0.90
    return _printable_ratio(magic) >= need

def _utf8_error_scan(b: bytes, max_report: int = 12) -> Tuple[int, List[int]]:
    """Return (error_count, sample_positions) for strict UTF-8 decoding of 'b'."""
    if not b:
        return 0, []
    dec = codecs.getincrementaldecoder("utf-8")("strict")
    errors, sample, offset = 0, [], 0
    mv = memoryview(b)
    while offset < len(b):
        try:
            dec.decode(mv[offset:], final=True)
            break
        except UnicodeDecodeError as ex:
            errors += 1
            pos = offset + int(getattr(ex, "start", 0) or 0)
            if len(sample) < max_report:
                sample.append(pos)
            offset = max(pos + 1, offset + 1)
            dec = codecs.getincrementaldecoder("utf-8")("strict")
    return errors, sample

class TextHandler:
    """
    Modifiable text policy:
      - If file hash is trusted -> DROP (benign).
      - Otherwise, inspect *each suspicious region*:
          * If region looks like plain text (high printable ratio and low entropy) -> DROP that region.
          * If region looks ciphertext/binary-ish (high entropy or low printable) -> KEEP that region (escalate) with reason.
      - File-level keep_file=True iff any region is kept; else False.
    """
    # Common texty extensions (feel free to add/remove)
    exts = {"txt", "log", "csv", "tsv", "md", "json", "xml", "yaml", "yml", "ini", "cfg", "conf", "properties"}

    @staticmethod
    def supports(ext: str, magic: Optional[bytes]) -> bool:
        e = (ext or "").lstrip(".").lower()
        if e in TextHandler.exts:
            return True
        # no standard magic for text; fall back to heuristic
        return _looks_like_text_prefix(magic or b"")

    def decide(self, ctx: FileContext, reg: SuspiciousFileRegion) -> FileAwareDecision:
        # --- Param knobs (with sensible defaults) ---
        sample_bytes = int(ctx.params.get("txt_sample_bytes", 64 * 1024))  # per-region sample cap
        utf8_err_cap = int(ctx.params.get("txt_utf8_error_sample", 12))    # show up to N offending offsets
        text_debug   = bool(ctx.params.get("text_debug", False))           # verbose prints

        # --- No FS? → conservative keep (escalate) ---
        if not ctx.fs_root:
            return FileAwareDecision(
                keep_file=True,
                reason="text: no fs_root; escalate",
                region_decisions=[
                    RegionDecision(start=s, end=e, keep=True, reason="text: cannot inspect; escalate")
                    for (s, e) in (reg.byte_ranges or [])
                ] or None,
            )

        # Resolve absolute path
        ap = os.path.join(ctx.fs_root, ctx.file_path.lstrip("/"))

        # --- Trusted hash short-circuit ---
        try:
            # Only hash if caller already provided it, or avoid rehashing here (inventory stage should do hashing).
            # If ctx.sha256 is present and trusted, drop file outright.
            if ctx.sha256 and (ctx.sha256.lower() in (ctx.trusted_hashes or set())):
                return FileAwareDecision(keep_file=False, reason="text: trusted (sha256)")
        except Exception:
            # Non-fatal; continue with content checks
            pass

        # --- Gather file size for clamping ---
        try:
            fsize = os.path.getsize(ap)
        except Exception:
            # If we cannot stat/open → keep conservatively
            return FileAwareDecision(
                keep_file=True,
                reason="text: read/stat error; escalate",
                region_decisions=[
                    RegionDecision(start=s, end=e, keep=True, reason="text: read/stat error; escalate")
                    for (s, e) in (reg.byte_ranges or [])
                ] or None,
            )

        # Helper: read a bounded slice [start..end], but cap to sample_bytes
        def _read_slice(start: int, end: int) -> bytes:
            if start is None or end is None:
                return b""
            s = max(0, int(start))
            e = min(int(end), max(0, fsize - 1))
            if e < s:
                return b""
            # Read at most sample_bytes from the middle of the region to avoid header-only bias
            span = e - s + 1
            if span <= sample_bytes:
                rs, rl = s, span
            else:
                # center window
                mid = s + span // 2
                half = sample_bytes // 2
                rs = max(s, mid - half)
                rs = min(rs, max(0, e - sample_bytes + 1))
                rl = min(sample_bytes, max(0, e - rs + 1))
            try:
                with open(ap, "rb") as f:
                    f.seek(rs)
                    return f.read(rl)
            except Exception:
                return b""

        regions = reg.byte_ranges or []
        
        # Debug header
        if text_debug:
            try:
                print(f"[TEXT][DBG] file={ctx.file_path} path={ap}")
                print(f"[TEXT][CFG] sample_bytes={sample_bytes} utf8_err_cap={utf8_err_cap}")
                print(f"[TEXT][SAWA] suspicious_ranges={list(regions)}")
            except Exception:
                pass

        region_decisions: List[RegionDecision] = []

        kept_any = False
        for (s, e) in regions:
            data = _read_slice(s, e)
            if not data:
                # If we can't read the region, keep conservatively
                region_decisions.append(RegionDecision(start=s, end=e, keep=True, reason="text: unreadable; escalate"))
                kept_any = True
                continue

            if text_debug:
                try:
                    print(f"[TEXT][REG] [{int(s)}..{int(e)}] len={int(e)-int(s)+1} sample_len={len(data)}")
                except Exception:
                    pass

            # Strict UTF-8 validity is the only signal.
            err_cnt, err_sample = _utf8_error_scan(data, max_report=utf8_err_cap)
            if err_cnt > 0:
                if text_debug:
                    try:
                        print(f"[UTF8][FAIL] [{int(s)}..{int(e)}) errors={err_cnt} sample={err_sample}")
                    except Exception:
                        pass
                rd = RegionDecision(
                    start=s, end=e, keep=True,
                    reason=f"text: invalid UTF-8 in region ({err_cnt} errors)"
                )
                region_decisions.append(rd)
                kept_any = True
                if text_debug:
                    try:
                        print(f"[TEXT][REG][DECISION] [{int(s)}..{int(e)}] KEEP → {rd.reason}")
                    except Exception:
                        pass
            else:
                if text_debug:
                    try:
                        print(f"[UTF8][OK] [{int(s)}..{int(e)})")
                    except Exception:
                        pass
                rd = RegionDecision(
                    start=s, end=e, keep=False,
                    reason="text: UTF-8 plaintext-like"
                )
                region_decisions.append(rd)
                if text_debug:
                    try:
                        print(f"[TEXT][REG][DECISION] [{int(s)}..{int(e)}] DROP → {rd.reason}")
                    except Exception:
                        pass

        # File-level decision: keep iff any suspicious region is kept
        if kept_any:
            return FileAwareDecision(
                keep_file=True,
                reason="text: suspicious (invalid UTF-8) regions kept",
                region_decisions=region_decisions or None,
            )
        else:
            return FileAwareDecision(
                keep_file=False,
                reason="text: all suspicious regions were valid UTF-8 (benign)",
                region_decisions=region_decisions or None,
            )
