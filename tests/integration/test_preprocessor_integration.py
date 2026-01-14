import warnings
warnings.filterwarnings("ignore", category=DeprecationWarning)


import os
import sys
import tempfile
import shutil
import boto3
import pytest
import random
import string
import numpy as np
import pandas as pd
from boto3.dynamodb.types import Binary
import array

from preprocessor import preprocess

import subprocess
import time
import pytest

DYNAMODB_LOCAL_PORT = "8000"
CONTAINER_NAME = "pytest-dynamodb-local"

# --- Helpers for unique names ---

def is_dynamodb_local_running():
    try:
        subprocess.check_output([
            "docker", "inspect", "-f", "{{.State.Running}}", CONTAINER_NAME
        ])
        return True
    except subprocess.CalledProcessError:
        return False

def random_table_name(prefix="test"):
    return f"{prefix}_{''.join(random.choices(string.ascii_lowercase + string.digits, k=8))}"

def wait_until_table_active(table, timeout=10):
    import time
    start = time.time()
    while True:
        table.load()
        if table.table_status == 'ACTIVE':
            return
        if time.time() - start > timeout:
            raise TimeoutError(f"Table {table.name} did not become ACTIVE within {timeout} seconds.")
        time.sleep(0.2)
        
# --- Fixtures ---

@pytest.fixture(scope="session", autouse=True)
def ensure_dynamodb_local():
    # Start DynamoDB Local in Docker if not running
    if not is_dynamodb_local_running():
        print("[pytest] Starting DynamoDB Local in Docker...")
        subprocess.check_call([
            "docker", "run", "-d", "--rm",
            "--name", CONTAINER_NAME,
            "-p", f"{DYNAMODB_LOCAL_PORT}:8000",
            "amazon/dynamodb-local"
        ])
        # Give DynamoDB Local a few seconds to start up
        time.sleep(3)
    else:
        print("[pytest] DynamoDB Local already running.")

    yield

    # Teardown: Stop the container
    print("[pytest] Stopping DynamoDB Local Docker container...")
    subprocess.call(["docker", "stop", CONTAINER_NAME])

@pytest.fixture(scope="module")
def dynamodb_resource():
    resource = boto3.resource(
        "dynamodb",
        endpoint_url="http://localhost:8000",
        region_name="us-west-2",
        aws_access_key_id="dummy",
        aws_secret_access_key="dummy"
    )
    yield resource

@pytest.fixture
def unique_tables(dynamodb_resource):
    # Unique database prefix for this test
    database_name = random_table_name("testdb")
    bitmap_table_name = f"{database_name}-cloudEpochBitmapsTable"
    block_table_name = f"{database_name}-cloudBlockSnapshotStoreTable"

    # Create the tables
    print(f"[integration test] Creating {bitmap_table_name}")
    bitmap_table = dynamodb_resource.create_table(
        TableName=bitmap_table_name,
        KeySchema=[{"AttributeName": "key", "KeyType": "HASH"}],
        AttributeDefinitions=[{"AttributeName": "key", "AttributeType": "S"}],
        ProvisionedThroughput={"ReadCapacityUnits": 1, "WriteCapacityUnits": 1}
    )
    print(f"[integration test] Creating {block_table_name}")
    block_table = dynamodb_resource.create_table(
        TableName=block_table_name,
        KeySchema=[{"AttributeName": "key", "KeyType": "HASH"}],
        AttributeDefinitions=[{"AttributeName": "key", "AttributeType": "S"}],
        ProvisionedThroughput={"ReadCapacityUnits": 1, "WriteCapacityUnits": 1}
    )
    bitmap_table.wait_until_exists()
    block_table.wait_until_exists()
    wait_until_table_active(bitmap_table)
    wait_until_table_active(block_table)

    print("Tables after creation:", list(dynamodb_resource.tables.all()))

    yield (bitmap_table, block_table, database_name)
    bitmap_table.delete()
    block_table.delete()

@pytest.fixture
def temp_outdir():
    d = tempfile.mkdtemp()
    yield d
    shutil.rmtree(d)

# --- DynamoDB seeding ---

def seed_bitmap_table(bitmap_table, epoch, block_ids):
    # For simplicity, let's use 16 bits (2 bytes)
    bitmap_bits = np.zeros(16, dtype=np.uint8)
    for b in block_ids:
        if b < 16:
            bitmap_bits[b] = 1
    bitmap_bytes = np.packbits(bitmap_bits, bitorder='big')
    bitmap_table.put_item(Item={
        "key": f"{epoch}-bitmap",
        "value": bytes(bitmap_bytes)
    })

def seed_block_table(block_table, epoch, block_ids, block_len=8):
    for b in block_ids:
        arr = array.array('B', [b] * block_len)
        block_table.put_item(Item={
            "key": f"{epoch}:{b}",
            "value": arr.tobytes()
        })

# --- Integration Test ---

def test_preprocessor_save_epoch_integration(unique_tables, temp_outdir, dynamodb_resource):
    bitmap_table, block_table, database_name = unique_tables
    epoch = 1
    block_ids = [2, 4, 7]

    # 1. Seed DynamoDB tables (using dynamodb_resource!)
    seed_bitmap_table(bitmap_table, epoch, block_ids)
    seed_block_table(block_table, epoch, block_ids, block_len=8)

    # 2. Import preprocessor and patch the db instance to use this database and resource
    #sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../../src/preprocessor")))
    #import preprocess

    # *** Key Fix: Use the SAME resource and client for both the Database and the test ***
    preprocess._db_instance = preprocess.Database(
        database=database_name,
        endpoint_url="http://localhost:8000"  # Same endpoint!
    )
    # Patch the internal resource/client to the exact ones used in seeding
    preprocess._db_instance.resource = dynamodb_resource
    preprocess._db_instance.client = dynamodb_resource.meta.client

    print("Existing tables:", preprocess._db_instance.list_tables())

    # 3. Run preprocessor (writes parquet/bitmap outputs)
    preprocess.save_epoch(temp_outdir, epoch=epoch, debug=True, profile=True)

    # 4. Check output
    parquet_file = os.path.join(temp_outdir, f"mutation_{epoch}.parquet")
    bitmap_file = os.path.join(temp_outdir, f"bitmap_{epoch}.bin")
    assert os.path.exists(parquet_file)
    assert os.path.exists(bitmap_file)

    df = pd.read_parquet(parquet_file)

    # -- 1. Bitmap correctness --
    with open(bitmap_file, "rb") as f:
        bitmap_bytes = f.read()
    bitmap_bits = np.unpackbits(np.frombuffer(bitmap_bytes, dtype=np.uint8), bitorder='big')
    # Check all block_ids we seeded are set to 1
    for bid in block_ids:
        assert bitmap_bits[bid] == 1, f"Block ID {bid} bit not set in bitmap!"
    # Check bits outside seeded IDs are zero
    for i in range(len(bitmap_bits)):
        if i not in block_ids:
            assert bitmap_bits[i] == 0, f"Unexpected bit set at offset {i} in bitmap!"

    # -- 2. Parquet file has only the block_ids we seeded --
    df_block_ids = set(df["id"])
    assert df_block_ids == set(block_ids), f"Unexpected block IDs in parquet: {df_block_ids} != {set(block_ids)}"

    # -- 3. Block content correctness --
    block_len = 8
    expected_block_map = {bid: bytes([bid] * block_len) for bid in block_ids}
    for _, row in df.iterrows():
        bid = row["id"]
        block = row["block"]

        # Convert block to bytes for all expected input types
        if isinstance(block, bytes):
            bblock = block
        elif isinstance(block, bytearray):
            bblock = bytes(block)
        elif isinstance(block, list):
            bblock = bytes(block)
        elif hasattr(block, "tolist"):  # catches numpy arrays
            bblock = bytes(block.tolist())
        else:
            raise TypeError(f"Unexpected type for block: {type(block)}")

        assert bblock == expected_block_map[bid], f"Block data for ID {bid} does not match: {bblock} != {expected_block_map[bid]}"

    print("All bitmap, block ID, and block content checks passed.")

    print("Integration test succeeded!")
