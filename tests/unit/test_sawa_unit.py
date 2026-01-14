# Rhea/tests/unit/test_sawa_unit.py

import unittest
import numpy as np

# Import from your actual implementation
from detector.sawa import chi2_entropy, sliding_adaptive_window_analysis
from detector.delta_types import DeltaBlock, SuspiciousRegion

class TestSawaUnit(unittest.TestCase):
    def test_chi2_entropy_all_zero(self):
        data = [0] * 16
        score = chi2_entropy(data)
        self.assertIsInstance(score, float)
        self.assertGreater(score, 0.0)

    def test_chi2_entropy_uniform(self):
        data = list(range(256))  # uniform
        score = chi2_entropy(data)
        self.assertAlmostEqual(score, 0, delta=100)  # Should be close to 0 (high entropy)

    def test_sliding_adaptive_window_analysis_finds_suspicious(self):
        # Mock DeltaBlock: block_ids=[10,11], diff=[0]*512 (low entropy)
        block_ids = [10, 11]
        # A region of constant values (low entropy, suspicious)
        f_diff = [0] * 512 + [255] * 512
        db = DeltaBlock(
            delta_block_id=0,
            delta_block_size=len(f_diff),
            aggreg_block_id=42,
            f_diff=f_diff,
            block_ids=block_ids,
            start_offset=0,
            end_offset=1023
        )

        # Print out actual chi2 for the first window
        #print("chi2(zeros):", chi2_entropy([0]*64))
        #print("chi2(zeros+255):", chi2_entropy([0]*32 + [255]*32))
        
        suspicious = sliding_adaptive_window_analysis(
            [db],
            width=64, stride=32, chi2_threshold=10000, block_size=512
        )

        # We expect at least one suspicious region
        self.assertTrue(any(isinstance(s, SuspiciousRegion) for s in suspicious))

    def test_sliding_adaptive_window_analysis_no_false_positive(self):
        # Mock DeltaBlock: block_ids=[20,21], diff=range(1024) (high entropy)
        block_ids = [20, 21]
        f_diff = list(range(256)) * 4  # Length 1024, high entropy
        db = DeltaBlock(
            delta_block_id=1,
            delta_block_size=len(f_diff),
            aggreg_block_id=43,
            f_diff=f_diff,
            block_ids=block_ids,
            start_offset=0,
            end_offset=1023
        )

        suspicious = sliding_adaptive_window_analysis(
            [db],
            width=64, stride=32, chi2_threshold=10, block_size=512  # very strict
        )

        # We expect no suspicious region with low chi2_threshold
        self.assertEqual(len(suspicious), 0)

if __name__ == "__main__":
    unittest.main()
