"""
test_ntfs_b2fm.py

Unit tests for ntfs_b2fm.py: block-to-file mapping using interval trees.

This test suite uses **mock file extents** (not a real image!) and verifies:
  - Overlap handling for blocks and file extents
  - Fragmented files, deduplication, and empty inputs
  - That mapping logic always returns the correct set of file(s) for each query

Run:
    python test_ntfs_b2fm.py
"""

import os
import sys
import unittest

from detector.ntfs_b2fm import (
    build_interval_tree,
    map_blocks_to_files,
)

class TestNtfsBlockToFileMapping(unittest.TestCase):
    def setUp(self):
        print("\n[Setup] Creating mock file extents and interval tree for testing block-to-file mapping.")
        # Mock extents for files (including fragmented and overlapping cases)
        # Format: (start_block, end_block, file_id, file_path)
        self.file_extents = [
            (10, 14, 1, "/fileA.txt"),
            (20, 22, 2, "/fileB.txt"),
            (30, 35, 3, "/fileC.txt"),
            (12, 17, 4, "/fileD.txt"),     # overlaps fileA
            (100, 102, 5, "/fileE.txt"),   # fileE: fragmented
            (200, 202, 5, "/fileE.txt"),
            (300, 301, 5, "/fileE.txt"),
            (400, 401, 6, "/fileF.txt"),
            (500, 505, 7, "/fileG.txt"),
            (1000, 1002, 8, "/fileH.txt"),
            (1500, 1504, 8, "/fileH.txt"),
        ]
        self.tree = build_interval_tree(self.file_extents)

    def test_single_block_overlap(self):
        """Block 12 overlaps both fileA and fileD (overlap logic test)."""
        suspicious_blocks = [12]
        files = map_blocks_to_files(suspicious_blocks, self.tree)
        expected = {(1, "/fileA.txt"), (4, "/fileD.txt")}
        self.assertEqual(files, expected)

    def test_multiple_blocks(self):
        """Test mapping multiple blocks, including fragmented and overlapping files."""
        suspicious_blocks = [13, 32, 201, 301]
        files = map_blocks_to_files(suspicious_blocks, self.tree)
        expected = {(1, "/fileA.txt"), (4, "/fileD.txt"), (3, "/fileC.txt"), (5, "/fileE.txt")}
        self.assertEqual(files, expected)

    def test_block_not_found(self):
        """Block 99 does not map to any file."""
        suspicious_blocks = [99]
        files = map_blocks_to_files(suspicious_blocks, self.tree)
        self.assertEqual(files, set())

    def test_deduplication(self):
        """Multiple/repeated and overlapping blocks still yield deduplicated file set."""
        suspicious_blocks = [13, 13, 30, 200, 200]
        files = map_blocks_to_files(suspicious_blocks, self.tree)
        expected = {(1, "/fileA.txt"), (4, "/fileD.txt"), (3, "/fileC.txt"), (5, "/fileE.txt")}
        self.assertEqual(files, expected)

    def test_empty_query(self):
        """Empty suspicious block list returns empty result."""
        suspicious_blocks = []
        files = map_blocks_to_files(suspicious_blocks, self.tree)
        self.assertEqual(files, set())

    def test_fragmented_file(self):
        """Mapping blocks in all extents of a fragmented fileE."""
        suspicious_blocks = [100, 200, 301]
        files = map_blocks_to_files(suspicious_blocks, self.tree)
        expected = {(5, "/fileE.txt")}
        self.assertEqual(files, expected)

    def test_fragmented_multiple_files(self):
        """Mapping blocks in fragmented fileE and fileH (across multiple extents)."""
        suspicious_blocks = [100, 200, 301, 1001, 1501]
        files = map_blocks_to_files(suspicious_blocks, self.tree)
        expected = {(5, "/fileE.txt"), (8, "/fileH.txt")}
        self.assertEqual(files, expected)

    def test_all_extents_hit(self):
        """Blocks that hit all extents of fileH."""
        suspicious_blocks = [1000, 1001, 1500, 1502]
        files = map_blocks_to_files(suspicious_blocks, self.tree)
        expected = {(8, "/fileH.txt")}
        self.assertEqual(files, expected)

    def test_multiple_files_same_block(self):
        """Block 12 overlaps fileA and fileD (repeat)."""
        suspicious_blocks = [12]
        files = map_blocks_to_files(suspicious_blocks, self.tree)
        expected = {(1, "/fileA.txt"), (4, "/fileD.txt")}
        self.assertEqual(files, expected)

    def test_fileE_first_extent(self):
        """Block 100 in fileE's first extent only."""
        suspicious_blocks = [100]
        files = map_blocks_to_files(suspicious_blocks, self.tree)
        expected = {(5, "/fileE.txt")}
        self.assertEqual(files, expected)

    def test_large_query_set(self):
        """Large query set should hit all files."""
        suspicious_blocks = [10, 12, 14, 20, 30, 101, 201, 301, 400, 502, 1503]
        files = map_blocks_to_files(suspicious_blocks, self.tree)
        expected = {
            (1, "/fileA.txt"), (2, "/fileB.txt"), (3, "/fileC.txt"), (4, "/fileD.txt"),
            (5, "/fileE.txt"), (6, "/fileF.txt"), (7, "/fileG.txt"), (8, "/fileH.txt")
        }
        self.assertEqual(files, expected)

if __name__ == "__main__":
    print("==== Starting ntfs_b2fm mapping unit tests ====")
    unittest.main(verbosity=2)
    print("==== All ntfs_b2fm tests completed. ====")
