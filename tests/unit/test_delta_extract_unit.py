# tests/unit/test_delta_extract_unit.py

import unittest
import tempfile
import os
import json
import base64

from detector.delta_extract import (
    extract_block_extents,
    extract_aggreg_blocks,
    extract_delta_extents,
    write_delta_extents_csv,
)

from detector.delta_types import (
    BlockExtent,
    AggregBlock,
    DeltaBlock,
    DeltaExtent,
)


class TestDeltaExtract(unittest.TestCase):
    # --- extract_block_extents ---
    def test_extract_block_extents_basic(self):
        """Test grouping block IDs into extents."""
        block_ids = [0, 1, 2, 8, 9, 10]
        extents = extract_block_extents(block_ids, extent_size=4096, block_size=512)
        self.assertEqual(len(extents), 2)
        self.assertListEqual(extents[0].block_ids, [0, 1, 2])
        self.assertListEqual(extents[1].block_ids, [8, 9, 10])

    def test_extract_block_extents_empty(self):
        """Test with empty block_id list."""
        extents = extract_block_extents([], extent_size=4096, block_size=512)
        self.assertEqual(len(extents), 0)

    def test_extract_block_extents_non_sequential(self):
        """Test grouping with non-sequential block IDs."""
        block_ids = [0, 5, 8, 16]
        extents = extract_block_extents(block_ids, extent_size=4096, block_size=512)
        self.assertTrue(all(isinstance(e, BlockExtent) for e in extents))
        # Check that each input block ID is somewhere in extents' block_ids
        flat = [bid for e in extents for bid in e.block_ids]
        for bid in block_ids:
            self.assertIn(bid, flat)

    # --- extract_aggreg_blocks ---
    def test_extract_aggreg_blocks_basic(self):
        """Test AggregBlock creation for contiguous and non-contiguous blocks."""
        extent = BlockExtent(0, 4096, 8, [0, 1, 2, 4, 5])
        # Contiguous runs: [0,1,2], [4,5]
        by_blocks = {0: [0]*512, 1: [1]*512, 2: [2]*512, 4: [4]*512, 5: [5]*512}
        take_blocks = {0: [0]*512, 1: [1]*512, 2: [2]*512, 4: [4]*512, 5: [5]*512}
        agg_old, agg_new = extract_aggreg_blocks(extent, by_blocks, take_blocks, block_size=512)
        self.assertEqual(len(agg_old), 2)
        self.assertEqual(len(agg_new), 2)
        # First AggregBlock should include blocks [0,1,2]
        self.assertListEqual(agg_old[0].block_ids, [0,1,2])
        self.assertListEqual(agg_new[0].block_ids, [0,1,2])
        # Second AggregBlock should include blocks [4,5]
        self.assertListEqual(agg_old[1].block_ids, [4,5])

    def test_extract_aggreg_blocks_empty_extent(self):
        """Test extract_aggreg_blocks with no block_ids."""
        extent = BlockExtent(0, 4096, 8, [])
        by_blocks = {}
        take_blocks = {}
        agg_old, agg_new = extract_aggreg_blocks(extent, by_blocks, take_blocks, block_size=512)
        self.assertEqual(agg_old, [])
        self.assertEqual(agg_new, [])

    # --- extract_delta_extents ---
    def test_delta_no_change(self):
        """No changed blocks yields zero delta blocks."""
        extent = BlockExtent(0, 4096, 8, [0, 1])
        by_blocks = {0: [5]*512, 1: [6]*512}
        take_blocks = {0: [5]*512, 1: [6]*512}
        delta_extents = extract_delta_extents([extent], by_blocks, take_blocks)
        self.assertEqual(len(delta_extents[0].delta_blocks), 0)

    def test_delta_single_block_change(self):
        """Changing one block yields a single delta block."""
        extent = BlockExtent(0, 4096, 8, [0, 1])
        by_blocks = {0: [1]*512, 1: [2]*512}
        take_blocks = {0: [1]*512, 1: [3]*512}
        delta_extents = extract_delta_extents([extent], by_blocks, take_blocks, block_size=512)
        self.assertTrue(any(all(b == 3 for b in db.f_diff) and db.delta_block_size == 512 for db in delta_extents[0].delta_blocks))

    def test_delta_all_blocks_changed(self):
        """All blocks changed yields a single delta block with full extent size."""
        extent = BlockExtent(0, 4096, 8, [0, 1])
        by_blocks = {0: [1]*512, 1: [2]*512}
        take_blocks = {0: [3]*512, 1: [4]*512}
        delta_extents = extract_delta_extents([extent], by_blocks, take_blocks, block_size=512)
        self.assertEqual(len(delta_extents[0].delta_blocks), 1)
        self.assertEqual(delta_extents[0].delta_blocks[0].delta_block_size, 1024)

    def test_delta_missing_by_blocks(self):
        """If by_blocks is missing, should default to zeros."""
        extent = BlockExtent(0, 4096, 8, [0])
        by_blocks = {}
        take_blocks = {0: [5]*512}
        delta_extents = extract_delta_extents([extent], by_blocks, take_blocks)
        found = any(db.delta_block_size == 512 and all(b == 5 for b in db.f_diff) for db in delta_extents[0].delta_blocks)
        self.assertTrue(found)

    def test_delta_missing_take_blocks(self):
        """If take_blocks is missing, should default to zeros."""
        extent = BlockExtent(0, 4096, 8, [0])
        by_blocks = {0: [3]*512}
        take_blocks = {}
        delta_extents = extract_delta_extents([extent], by_blocks, take_blocks)
        found = any(db.delta_block_size == 512 and all(b == 0 for b in db.f_diff) for db in delta_extents[0].delta_blocks)
        self.assertTrue(found)

    def test_delta_with_gaps(self):
        """Test min_gap_length parameter splits delta blocks."""
        extent = BlockExtent(0, 4096, 8, [0])
        by_blocks = {0: [2]*512}
        take = [2]*512
        # Change bytes 0-9 and 20-29, leave gap of 10 (exceeds min_gap_length=5)
        for i in range(0, 10):
            take[i] = 9
        for i in range(20, 30):
            take[i] = 8
        take_blocks = {0: take}
        delta_extents = extract_delta_extents([extent], by_blocks, take_blocks, min_gap_length=5)
        self.assertGreaterEqual(len(delta_extents[0].delta_blocks), 2)

    def test_delta_multiple_extents(self):
        """Multiple extents: change only in second extent."""
        extent1 = BlockExtent(0, 4096, 8, [0, 1])
        extent2 = BlockExtent(1, 4096, 8, [8, 9])
        by_blocks = {0: [1]*512, 1: [2]*512, 8: [3]*512, 9: [4]*512}
        take_blocks = {0: [1]*512, 1: [2]*512, 8: [9]*512, 9: [4]*512}
        delta_extents = extract_delta_extents([extent1, extent2], by_blocks, take_blocks)
        # Change detected in extent2 only
        self.assertEqual(len(delta_extents), 2)
        self.assertEqual(len(delta_extents[0].delta_blocks), 0)
        self.assertTrue(any(all(b == 9 for b in db.f_diff) for db in delta_extents[1].delta_blocks))

    # --- write_delta_extents_csv ---
    def test_write_delta_extents_csv(self):
        """Test writing delta extents to CSV and re-parsing fields."""
        extent = BlockExtent(0, 4096, 8, [0, 1])
        by_blocks = {0: [10]*512, 1: [20]*512}
        take_blocks = {0: [11]*512, 1: [21]*512}
        delta_extents = extract_delta_extents([extent], by_blocks, take_blocks, block_size=512)
        with tempfile.TemporaryDirectory() as tmpdir:
            csv_path = os.path.join(tmpdir, "out.csv")
            write_delta_extents_csv(delta_extents, csv_path)
            self.assertTrue(os.path.exists(csv_path))
            # Read back the file, verify structure
            with open(csv_path, "r") as f:
                lines = f.readlines()
            self.assertGreater(len(lines), 1)  # header + at least one row
            # Parse a data row
            header = lines[0].strip().split(";")
            row = lines[1].strip().split(";")
            data = dict(zip(header, row))
            # Verify f_diff can be decoded from base64 and has expected length
            f_diff_bytes = base64.b64decode(data["f_diff"])
            self.assertTrue(len(f_diff_bytes) > 0)
            block_ids = json.loads(data["block_ids"])
            self.assertTrue(isinstance(block_ids, list))
            self.assertIn(int(data["extent_id"]), [0,1])

    # --- New: Test edge-cases for extract_delta_extents ---
    def test_extract_delta_extents_empty_inputs(self):
        """Empty inputs should produce empty output."""
        res = extract_delta_extents([], {}, {})
        self.assertEqual(res, [])
        extent = BlockExtent(0, 4096, 8, [])
        res2 = extract_delta_extents([extent], {}, {})
        self.assertEqual(len(res2), 1)
        self.assertEqual(len(res2[0].delta_blocks), 0)

    def test_extract_delta_extents_partial_missing_blocks(self):
        """Test behavior when some blocks are missing from by_blocks/take_blocks."""
        extent = BlockExtent(0, 4096, 8, [0, 1, 2])
        by_blocks = {0: [1]*512}  # 1,2 missing
        take_blocks = {2: [3]*512}  # 0,1 missing
        res = extract_delta_extents([extent], by_blocks, take_blocks)
        # Should default missing to zeros and detect changes accordingly
        delta_blocks = [db for de in res for db in de.delta_blocks]
        self.assertTrue(any(db for db in delta_blocks if db.delta_block_size == 512))

if __name__ == "__main__":
    unittest.main()
