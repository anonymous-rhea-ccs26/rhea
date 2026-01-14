# detector/fileaware/types.py
from __future__ import annotations
from dataclasses import dataclass
from typing import List, Optional, Tuple, Dict, Any, Set

@dataclass
class FileContext:
    file_path: str
    fs_root: Optional[str]
    sha256: Optional[str]
    size_bytes: Optional[int]
    trusted_hashes: Set[str]
    params: Dict[str, Any]

@dataclass
class SuspiciousFileRegion:
    # Inclusive byte ranges (start, end_inclusive)
    byte_ranges: List[Tuple[int, int]]
    chi2_summary: Optional[Dict[str, Any]] = None

@dataclass
class RegionDecision:
    start: int
    end: int          # inclusive
    keep: bool        # keep this region as suspicious?
    reason: str = ""
    score: Optional[float] = None  # optional diagnostic (e.g., chi²)

@dataclass
class FileAwareDecision:
    # File-level summary (legacy-compatible)
    keep_file: bool
    reason: str = ""
    # Fine-grained region decisions (optional)
    region_decisions: Optional[List[RegionDecision]] = None

    # Back-compat accessor
    @property
    def keep(self) -> bool:
        return self.keep_file
