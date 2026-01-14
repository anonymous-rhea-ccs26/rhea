from typing import List, Optional, Union, Any

from typing import List, Union, Any, Optional

class BlockExtent:
    """
    Represents a group of contiguous logical blocks (an extent).
    """
    def __init__(self, extent_id, extent_size, extent_block_count, block_ids):
        self.extent_id = extent_id  # int: unique extent index
        self.extent_size = extent_size  # int: total extent size in bytes
        self.extent_block_count = extent_block_count  # int: number of blocks in this extent
        self.block_ids = block_ids  # list[int]: block IDs in this extent

    def __repr__(self):
        return f"<BlockExtent id={self.extent_id} blocks={self.block_ids}>"

    def to_dict(self):
        return {
            "extent_id": self.extent_id,
            "extent_size": self.extent_size,
            "extent_block_count": self.extent_block_count,
            "block_ids": self.block_ids,
        }

class AggregBlock:
    """
    Aggregates block data for a (possibly contiguous) run of blocks within an extent.
    Stores the block IDs of the blocks included in this aggregation.
    """
    def __init__(self, aggreg_block_id, extent_id, aggreg_data, block_ids):
        self.aggreg_block_id = aggreg_block_id  # str or int: unique aggregation ID
        self.extent_id = extent_id              # int: parent extent
        self.aggreg_data = aggreg_data          # list[int] or bytes: concatenated bytes
        self.block_ids = block_ids              # list[int]: block IDs in order for this AggregBlock

    def __repr__(self):
        return (f"<AggregBlock id={self.aggreg_block_id} extent={self.extent_id} "
                f"size={len(self.aggreg_data)} blocks={self.block_ids}>")

class DeltaBlock:
    """
    Represents a forward-difference (delta) region within an AggregBlock.
    Contains mapping information to underlying block IDs and offsets.
    """
    def __init__(
        self,
        delta_block_id: int,
        delta_block_size: int,
        aggreg_block_id: Union[str, int],
        f_diff: Union[bytes, List[int]],
        block_ids: Optional[List[Union[str, int]]] = None,
        start_offset: Optional[int] = None,
        end_offset: Optional[int] = None,
    ):
        self.delta_block_id = delta_block_id
        self.delta_block_size = delta_block_size
        self.aggreg_block_id = aggreg_block_id
        self.f_diff = f_diff  # bytes or list[int]
        self.block_ids = block_ids or []
        self.start_offset = start_offset  # offset within first block
        self.end_offset = end_offset      # offset within last block

    def __repr__(self):
        return (f"<DeltaBlock id={self.delta_block_id} size={self.delta_block_size} "
                f"agg_id={self.aggreg_block_id} blocks={self.block_ids} "
                f"start_off={self.start_offset} end_off={self.end_offset}>")

    def to_dict(self) -> dict:
        return {
            "delta_block_id": self.delta_block_id,
            "delta_block_size": self.delta_block_size,
            "aggreg_block_id": self.aggreg_block_id,
            "f_diff": list(self.f_diff) if isinstance(self.f_diff, bytes) else self.f_diff,
            "block_ids": self.block_ids,
            "start_offset": self.start_offset,
            "end_offset": self.end_offset,
        }

    @staticmethod
    def from_dict(d: dict) -> 'DeltaBlock':
        f_diff = d["f_diff"]
        if isinstance(f_diff, list):
            f_diff = bytes(f_diff)
        return DeltaBlock(
            delta_block_id=d["delta_block_id"],
            delta_block_size=d["delta_block_size"],
            aggreg_block_id=d["aggreg_block_id"],
            f_diff=f_diff,
            block_ids=d.get("block_ids"),
            start_offset=d.get("start_offset"),
            end_offset=d.get("end_offset"),
        )

    def __eq__(self, other: Any) -> bool:
        if not isinstance(other, DeltaBlock):
            return False
        return self.to_dict() == other.to_dict()


class DeltaExtent:
    """
    Represents a delta extent: a group of blocks (extent) and the delta blocks detected within.
    """
    def __init__(
        self,
        extent_id: int,
        delta_blocks: List[DeltaBlock]
    ):
        self.extent_id = extent_id        # int: logical extent index
        self.delta_blocks = delta_blocks  # list of DeltaBlock objects

    def __repr__(self):
        return (f"<DeltaExtent id={self.extent_id} "
                f"n_deltas={len(self.delta_blocks)}>")

    def to_dict(self) -> dict:
        return {
            "extent_id": self.extent_id,
            "delta_blocks": [db.to_dict() for db in self.delta_blocks]
        }

    @staticmethod
    def from_dict(d: dict) -> 'DeltaExtent':
        return DeltaExtent(
            extent_id=d["extent_id"],
            delta_blocks=[DeltaBlock.from_dict(db) for db in d["delta_blocks"]]
        )

    def __eq__(self, other: Any) -> bool:
        if not isinstance(other, DeltaExtent):
            return False
        return self.to_dict() == other.to_dict()

from typing import List, Any, Optional, Union

class SuspiciousRegion:
    def __init__(
        self,
        extent_id: int,
        delta_block_id: int,
        block_ids: List[Union[int, str]],
        start_offset: int,               # offset within first block (bytes)
        end_offset: int,                 # offset within last block (bytes)
        *,                                # keyword-only from here
        # indices within db.block_ids
        block_idx_start: Optional[int] = None,
        block_idx_end: Optional[int] = None,
        # absolute device block IDs (LBAs)
        lba_start_block: Optional[int] = None,
        lba_end_block: Optional[int] = None,
        # absolute device byte offsets
        byte_start: Optional[int] = None,
        byte_end_inclusive: Optional[int] = None,
        # diagnostics
        chi2_min: Optional[float] = None,
        chi2_max: Optional[float] = None,
        chi2_var: Optional[float] = None,
        chi2_final: Optional[float] = None,
    ):
        self.extent_id = extent_id
        self.delta_block_id = delta_block_id
        self.block_ids = block_ids
        self.start_offset = start_offset
        self.end_offset = end_offset

        self.block_idx_start = block_idx_start
        self.block_idx_end = block_idx_end
        self.lba_start_block = lba_start_block
        self.lba_end_block = lba_end_block
        self.byte_start = byte_start
        self.byte_end_inclusive = byte_end_inclusive

        self.chi2_min = chi2_min
        self.chi2_max = chi2_max
        self.chi2_var = chi2_var
        self.chi2_final = chi2_final

    def __str__(self):
        parts = [
            f"Extent {self.extent_id}",
            f"DeltaBlock {self.delta_block_id}",
            f"Blocks {self.block_ids}",
            f"BlockOffsets [{self.start_offset}->{self.end_offset}]",
        ]
        if self.lba_start_block is not None and self.lba_end_block is not None:
            parts.append(f"LBA [{self.lba_start_block} - {self.lba_end_block}]")
        if self.byte_start is not None and self.byte_end_inclusive is not None:
            parts.append(f"bytes [{self.byte_start} - {self.byte_end_inclusive}]")
        if self.chi2_min is not None:   parts.append(f"chi2_min={self.chi2_min:.3f}")
        if self.chi2_max is not None:   parts.append(f"chi2_max={self.chi2_max:.3f}")
        if self.chi2_var is not None:   parts.append(f"chi2_var={self.chi2_var:.3f}")
        if self.chi2_final is not None: parts.append(f"chi2_final={self.chi2_final:.3f}")
        return ", ".join(parts)

    def to_dict(self) -> dict:
        return {
            "extent_id": self.extent_id,
            "delta_block_id": self.delta_block_id,
            "block_ids": self.block_ids,
            "start_offset": self.start_offset,
            "end_offset": self.end_offset,
            "block_idx_start": self.block_idx_start,
            "block_idx_end": self.block_idx_end,
            "lba_start_block": self.lba_start_block,
            "lba_end_block": self.lba_end_block,
            "byte_start": self.byte_start,
            "byte_end_inclusive": self.byte_end_inclusive,
            "chi2_min": self.chi2_min,
            "chi2_max": self.chi2_max,
            "chi2_var": self.chi2_var,
            "chi2_final": self.chi2_final,
        }

    @staticmethod
    def from_dict(d: dict) -> 'SuspiciousRegion':
        # back-compat: accept old keys 'window_start'/'window_end' as LBAs if needed
        lba_start = d.get("lba_start_block", d.get("window_start"))
        lba_end   = d.get("lba_end_block", d.get("window_end"))
        return SuspiciousRegion(
            extent_id=d["extent_id"],
            delta_block_id=d["delta_block_id"],
            block_ids=d["block_ids"],
            start_offset=d["start_offset"],
            end_offset=d["end_offset"],
            block_idx_start=d.get("block_idx_start"),
            block_idx_end=d.get("block_idx_end"),
            lba_start_block=lba_start,
            lba_end_block=lba_end,
            byte_start=d.get("byte_start"),
            byte_end_inclusive=d.get("byte_end_inclusive"),
            chi2_min=d.get("chi2_min"),
            chi2_max=d.get("chi2_max"),
            chi2_var=d.get("chi2_var"),
            chi2_final=d.get("chi2_final"),
        )
