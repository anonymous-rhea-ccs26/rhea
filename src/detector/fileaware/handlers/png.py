# detector/fileaware/handlers/png.py
import os
import hashlib
from typing import Optional, List, Tuple
from ..types import FileContext, SuspiciousFileRegion, FileAwareDecision, RegionDecision


_PNG_SIG = b"\x89PNG\r\n\x1a\n"


def _looks_like_png(magic: bytes) -> bool:
    """
    Minimal PNG signature check.
    Valid PNG files start with the 8-byte signature:
    89 50 4E 47 0D 0A 1A 0A
    """
    return bool(magic) and magic.startswith(_PNG_SIG)


def _bounded_stream_hash(path: str, limit_bytes: int) -> Tuple[Optional[str], int]:
    try:
        h = hashlib.sha256()
        total = 0
        with open(path, "rb") as f:
            while total < limit_bytes:
                chunk = f.read(min(1024 * 1024, limit_bytes - total))
                if not chunk:
                    break
                h.update(chunk)
                total += len(chunk)
        return h.hexdigest().lower(), total
    except Exception:
        return None, 0


class PNGHandler:
    """
    Media policy (hardly-modifiable):
      - If file hash is trusted -> DROP (benign).
      - Otherwise, escalate: KEEP the file and mark ALL suspicious regions as kept.
      - We only do a light signature check; no full PNG parsing/decoding.
    """
    exts = {"png"}

    @staticmethod
    def supports(ext: str, magic: Optional[bytes]) -> bool:
        e = (ext or "").lstrip(".").lower()
        return (e in PNGHandler.exts) or _looks_like_png(magic or b"")

    def decide(self, ctx: FileContext, reg: SuspiciousFileRegion) -> FileAwareDecision:
        if not ctx.fs_root:
            # No FS access → conservative keep (escalate)
            return FileAwareDecision(
                keep_file=True,
                reason="png: no fs_root; escalate",
                region_decisions=[
                    RegionDecision(start=s, end=e, keep=True, reason="png: media (hardly-modifiable); escalate")
                    for (s, e) in (reg.byte_ranges or [])
                ] or None,
            )

        ap = os.path.join(ctx.fs_root, ctx.file_path.lstrip("/"))

        # 1) Early trust override
        budget = int(ctx.params.get("decompress_budget_bytes", 32 * 1024 * 1024))
        h, _ = _bounded_stream_hash(ap, budget)
        if h and (h in ctx.trusted_hashes):
            return FileAwareDecision(keep_file=False, reason="png: trusted (sha256)")

        # 2) Light signature check (no structural parsing)
        try:
            with open(ap, "rb") as f:
                magic = f.read(8)
        except Exception:
            magic = b""

        sig_ok = _looks_like_png(magic)
        reason = "png: untrusted" if sig_ok else "png: untrusted; metadata encrypted"

        # 3) Escalate all incoming suspicious regions
        region_out: List[RegionDecision] = [
            RegionDecision(start=s, end=e, keep=True, reason="png: untrusted")
            for (s, e) in (reg.byte_ranges or [])
        ] or None

        return FileAwareDecision(keep_file=True, reason=reason, region_decisions=region_out)
