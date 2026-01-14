# detector/fileaware/handlers/jpeg.py
import os
import hashlib
from typing import Optional, List, Tuple
from ..types import FileContext, SuspiciousFileRegion, FileAwareDecision, RegionDecision


def _looks_like_jpeg(magic: bytes) -> bool:
    """
    Minimal JPEG signature check.
    - SOI marker: 0xFF 0xD8 at the start.
    Optionally many JPEGs will have APP0 'JFIF\\0' or APP1 'Exif\\0\\0' soon after,
    but we keep it simple and only require SOI.
    """
    return bool(magic) and len(magic) >= 2 and magic[0] == 0xFF and magic[1] == 0xD8


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


class JPEGHandler:
    """
    Media policy (hardly-modifiable):
      - If file hash is trusted -> DROP (benign).
      - Otherwise, escalate: KEEP the file and mark ALL suspicious regions as kept.
      - We only do a light SOI signature check; no full JPEG parsing/decoding.
    """
    exts = {"jpg", "jpeg", "jpe"}

    @staticmethod
    def supports(ext: str, magic: Optional[bytes]) -> bool:
        e = (ext or "").lstrip(".").lower()
        return (e in JPEGHandler.exts) or _looks_like_jpeg(magic or b"")

    def decide(self, ctx: FileContext, reg: SuspiciousFileRegion) -> FileAwareDecision:
        if not ctx.fs_root:
            # No FS access → conservative keep (escalate)
            return FileAwareDecision(
                keep_file=True,
                reason="jpeg: no fs_root; escalate",
                region_decisions=[
                    RegionDecision(start=s, end=e, keep=True, reason="jpeg: media (hardly-modifiable); escalate")
                    for (s, e) in (reg.byte_ranges or [])
                ] or None,
            )

        ap = os.path.join(ctx.fs_root, ctx.file_path.lstrip("/"))

        # 1) Early trust override
        budget = int(ctx.params.get("decompress_budget_bytes", 32 * 1024 * 1024))
        h, _ = _bounded_stream_hash(ap, budget)
        if h and (h in ctx.trusted_hashes):
            return FileAwareDecision(keep_file=False, reason="jpeg: trusted (sha256)")

        # 2) Light signature check (SOI)
        try:
            with open(ap, "rb") as f:
                magic = f.read(8)
        except Exception:
            magic = b""

        sig_ok = _looks_like_jpeg(magic)
        reason = "jpeg: untrusted" if sig_ok else "jpeg: untrusted; metadata encrypted"

        # 3) Escalate all incoming suspicious regions
        region_out: List[RegionDecision] = [
            RegionDecision(start=s, end=e, keep=True, reason="jpeg: untrusted")
            for (s, e) in (reg.byte_ranges or [])
        ] or None

        return FileAwareDecision(keep_file=True, reason=reason, region_decisions=region_out)
