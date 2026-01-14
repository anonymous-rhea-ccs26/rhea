# detector/fileaware/handlers/mp3.py
import os
import hashlib
from typing import Optional, List, Tuple
from ..types import FileContext, SuspiciousFileRegion, FileAwareDecision, RegionDecision


def _looks_like_mp3(magic: bytes) -> bool:
    if not magic:
        return False
    if magic.startswith(b"ID3"):
        return True  # ID3v2
    # 0xFFE sync (11 ones) + next 3 bits non-zero
    return (len(magic) >= 2) and (magic[0] == 0xFF) and ((magic[1] & 0xE0) == 0xE0)


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


class MP3Handler:
    """
    Media policy (hardly-modifiable):
      - If file hash is trusted -> DROP (benign).
      - Otherwise, escalate: KEEP the file and mark ALL suspicious regions as kept.
      - We still check the magic so the reason string is informative, but we do not
        attempt frame/ID3 parsing or decoding — by design for simplicity & safety.
    """
    exts = {"mp3"}

    @staticmethod
    def supports(ext: str, magic: Optional[bytes]) -> bool:
        e = (ext or "").lstrip(".").lower()
        return (e in MP3Handler.exts) or _looks_like_mp3(magic or b"")

    def decide(self, ctx: FileContext, reg: SuspiciousFileRegion) -> FileAwareDecision:
        if not ctx.fs_root:
            # No FS access → conservative keep (escalate)
            return FileAwareDecision(
                keep_file=True,
                reason="mp3: no fs_root; escalate",
                region_decisions=[
                    RegionDecision(start=s, end=e, keep=True, reason="mp3: media (hardly-modifiable); escalate")
                    for (s, e) in (reg.byte_ranges or [])
                ] or None,
            )

        ap = os.path.join(ctx.fs_root, ctx.file_path.lstrip("/"))

        # 1) Early trust override (should be rare since you filter earlier, but safe)
        budget = int(ctx.params.get("decompress_budget_bytes", 32 * 1024 * 1024))
        h, _ = _bounded_stream_hash(ap, budget)
        if h and (h in ctx.trusted_hashes):
            return FileAwareDecision(keep_file=False, reason="mp3: trusted (sha256)")

        # 2) Light signature check for better audit reason (no structural parsing)
        try:
            with open(ap, "rb") as f:
                magic = f.read(4)
        except Exception:
            magic = b""

        sig_ok = _looks_like_mp3(magic)
        reason = "mp3: untrusted"
        if not sig_ok:
            reason = "mp3: untrusted; metadata encrypted"

        # 3) Escalate all incoming suspicious regions
        region_out: List[RegionDecision] = [
            RegionDecision(start=s, end=e, keep=True, reason="mp3: untrusted")
            for (s, e) in (reg.byte_ranges or [])
        ] or None

        return FileAwareDecision(keep_file=True, reason=reason, region_decisions=region_out)
