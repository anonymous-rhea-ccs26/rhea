import os
import sys
import tempfile
import shutil
import pandas as pd
import numpy as np
import pytest
from unittest.mock import patch, MagicMock

@pytest.fixture
def temp_outdir():
    tmpdir = tempfile.mkdtemp()
    yield tmpdir
    shutil.rmtree(tmpdir)

@pytest.fixture
def mock_database_class():
    with patch('preprocessor.database.Database') as MockDB:
        instance = MockDB.return_value
        # Provide sane defaults
        instance.item_by_epoch.return_value = []
        instance.item_bitmap.return_value = []
        yield MockDB

def import_preprocess_module():
    # Remove cached preprocess module to reload fresh with patch
    if 'preprocessor.preprocess' in sys.modules:
        del sys.modules['preprocessor.preprocess']
    # Import freshly
    import preprocessor.preprocess as preprocess
    return preprocess

def test_save_epoch_handles_empty_data(temp_outdir, mock_database_class):
    preprocess = None
    # Setup mock return values before import
    mock_database_class.return_value.item_by_epoch.return_value = []
    mock_database_class.return_value.item_bitmap.return_value = []

    # Import preprocess after patching
    preprocess = import_preprocess_module()

    # Reset cached instance so get_db uses mocked Database
    preprocess._db_instance = None

    # Confirm mock is used
    db_instance = preprocess.get_db()
    assert db_instance is mock_database_class.return_value

    preprocess.save_epoch(temp_outdir, epoch=2, debug=True, profile=True)

    parquet_file = os.path.join(temp_outdir, "mutation_2.parquet")
    bitmap_file = os.path.join(temp_outdir, "bitmap_2.bin")

    assert os.path.exists(parquet_file)
    assert os.path.exists(bitmap_file)

    df = pd.read_parquet(parquet_file)
    assert df.shape[0] == 0

def test_save_epoch_writes_files(temp_outdir, mock_database_class):
    # Setup mock with example data
    block_ids = [2, 4, 7]
    items = [{"key": f"foo:{bid}", "value": MagicMock(value=[bid] * 8)} for bid in block_ids]
    mock_database_class.return_value.item_by_epoch.return_value = items

    bitmap_length = max(block_ids) + 1
    bitmap = [0] * bitmap_length
    for bid in block_ids:
        bitmap[bid] = 1
    mock_database_class.return_value.item_bitmap.return_value = bitmap

    preprocess = import_preprocess_module()
    preprocess._db_instance = None

    db_instance = preprocess.get_db()
    assert db_instance is mock_database_class.return_value

    preprocess.save_epoch(temp_outdir, epoch=1, debug=True, profile=True)

    parquet_file = os.path.join(temp_outdir, "mutation_1.parquet")
    bitmap_file = os.path.join(temp_outdir, "bitmap_1.bin")

    assert os.path.exists(parquet_file)
    assert os.path.exists(bitmap_file)

    df = pd.read_parquet(parquet_file)
    assert set(df["id"]) == set(block_ids)

    bitmap_bytes = np.unpackbits(np.frombuffer(open(bitmap_file, "rb").read(), dtype=np.uint8))
    assert np.array_equal(bitmap_bytes[:len(bitmap)], np.array(bitmap))

def test_save_epoch_debug_and_profile(temp_outdir, mock_database_class):
    block_ids = [1, 2]
    items = [{"key": f"foo:{bid}", "value": MagicMock(value=[bid] * 4)} for bid in block_ids]
    mock_database_class.return_value.item_by_epoch.return_value = items

    bitmap_length = max(block_ids) + 1
    bitmap = [0] * bitmap_length
    for bid in block_ids:
        bitmap[bid] = 1
    mock_database_class.return_value.item_bitmap.return_value = bitmap

    preprocess = import_preprocess_module()
    preprocess._db_instance = None

    preprocess.save_epoch(temp_outdir, epoch=3, debug=True, profile=True)

    parquet_file = os.path.join(temp_outdir, "mutation_3.parquet")
    bitmap_file = os.path.join(temp_outdir, "bitmap_3.bin")

    assert os.path.exists(parquet_file)
    assert os.path.exists(bitmap_file)
