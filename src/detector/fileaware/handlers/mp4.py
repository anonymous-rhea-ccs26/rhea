# detector/fileaware/handlers/mp4.py
import os
import hashlib
from typing import Optional, List, Tuple
from ..types import FileContext, SuspiciousFileRegion, FileAwareDecision, RegionDecision


def _looks_like_mp4(magic: bytes) -> bool:
    """
    Very light ISO Base Media File (MP4/M4V/M4A/MOV) check:
    - Typical layout: [4-byte size][b'ftyp'][major_brand...]
    - We only need to see 'ftyp' at offset 4 to call it "likely MP4".
    """
    if not magic or len(magic) < 8:
        return False
    return magic[4:8] == b"ftyp"


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


class MP4Handler:
    """
    Media policy (hardly-modifiable):
      - If file hash is trusted -> DROP (benign).
      - Otherwise, escalate: KEEP the file and mark ALL suspicious regions as kept.
      - We do a minimal signature check (ftyp at offset 4); no parsing/decoding.
    """
    exts = {"mp4", "m4v", "m4a", "mov"}

    @staticmethod
    def supports(ext: str, magic: Optional[bytes]) -> bool:
        e = (ext or "").lstrip(".").lower()
        return (e in MP4Handler.exts) or _looks_like_mp4(magic or b"")

    def decide(self, ctx: FileContext, reg: SuspiciousFileRegion) -> FileAwareDecision:
        if not ctx.fs_root:
            # No FS access → conservative keep (escalate)
            return FileAwareDecision(
                keep_file=True,
                reason="mp4: no fs_root; escalate",
                region_decisions=[
                    RegionDecision(start=s, end=e, keep=True, reason="mp4: media (hardly-modifiable); escalate")
                    for (s, e) in (reg.byte_ranges or [])
                ] or None,
            )

        ap = os.path.join(ctx.fs_root, ctx.file_path.strip("/"))

        # 1) Early trust override (rare due to earlier filtering, but safe)
        budget = int(ctx.params.get("decompress_budget_bytes", 32 * 1024 * 1024))
        h, _ = _bounded_stream_hash(ap, budget)
        if h and (h in ctx.trusted_hashes):
            return FileAwareDecision(keep_file=False, reason="mp4: trusted (sha256)")

        # 2) Light signature check for better audit reason (no structural parsing)
        try:
            with open(ap, "rb") as f:
                magic = f.read(12)  # enough to see size+ftyp
        except Exception:
            magic = b""

        sig_ok = _looks_like_mp4(magic)
        reason = "mp4: untrusted" if sig_ok else "mp4: untrusted; metadata encrypted"

        # 3) Escalate all incoming suspicious regions
        region_out: List[RegionDecision] = [
            RegionDecision(start=s, end=e, keep=True, reason="mp4: untrusted")
            for (s, e) in (reg.byte_ranges or [])
        ] or None

        return FileAwareDecision(keep_file=True, reason=reason, region_decisions=region_out)
