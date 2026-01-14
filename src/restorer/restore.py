import os
import numpy as np
import pandas as pd
import time
from datetime import datetime

def restore_device_snapshot_core(epoch, size, img_path, directory=".", debug=False, profile=False, overwrite=True):
    """
    Core logic: Restores the device image by replaying block mutations up to the given epoch.
    If overwrite is True, existing img_path will be replaced.
    """
    def profmsg(msg, t1, t0):
        if profile:
            print(f"[Profile][Restorer] {msg}: {(t1 - t0) * 1000:.2f} ms")

    t_start = time.perf_counter() if profile else None

    block_size = 512  # Adjust as needed

    # (Re-)Create device image as zeros if needed
    if os.path.exists(img_path):
        if overwrite:
            if debug:
                print(f"[Restorer][DEBUG] Device image already exists. Removing: {img_path}")
            os.remove(img_path)
        else:
            raise FileExistsError(f"File {img_path} already exists and overwrite=False.")
    if debug:
        print(f"[Restorer][DEBUG] Creating device image: {img_path} (size: {size} bytes)")
    with open(img_path, "wb") as f:
        f.seek(size - 1)
        f.write(b"\x00")
    if debug:
        print(f"[Restorer][DEBUG] Device image creation done.")

    t0 = time.perf_counter() if profile else None

    latest_block = dict()  # block_id: (epoch, block_data)
    # REVERSE: from latest to earliest
    if debug:
        print(f"[Restorer][DEBUG] Scanning epochs in reverse: {epoch} → 1")
    for e in range(epoch, 0, -1):
        parquet_path = os.path.join(directory, f"mutation_{e}.parquet")
        bitmap_path = os.path.join(directory, f"bitmap_{e}.bin")
        if not os.path.exists(parquet_path):
            msg = f"[Restorer][ERROR] Missing mutation snapshot: {parquet_path} (required for epoch {e})"
            print(msg)
            assert False, msg
        if not os.path.exists(bitmap_path):
            msg = f"[Restorer][ERROR] Missing bitmap file: {bitmap_path} (required for epoch {e})"
            print(msg)
            assert False, msg
        if debug:
            print(f"[Restorer][DEBUG] Loading epoch {e}: {parquet_path}, {bitmap_path}")
        # Load bitmap
        with open(bitmap_path, "rb") as f:
            packed = np.frombuffer(f.read(), dtype=np.uint8)
            bitmap = np.unpackbits(packed)
        if debug:
            print(f"[Restorer][DEBUG] Bitmap length: {len(bitmap)} (epoch {e})")
        # Load mutated block snapshots
        df = pd.read_parquet(parquet_path)
        id_to_block = {row.id: row.block for row in df.itertuples()}
        for idx, bit in enumerate(bitmap):
            if bit and idx in id_to_block and idx not in latest_block:
                latest_block[idx] = (e, id_to_block[idx])
                if debug and len(latest_block) <= 5:
                    print(f"[Restorer][DEBUG] Block {idx} from epoch {e} mapped for restore.")
        if debug:
            print(f"[Restorer][DEBUG] Finished epoch {e}. Latest block count: {len(latest_block)}")

    t1 = time.perf_counter() if profile else None
    profmsg("Block mapping (latest snapshot index build)", t1, t0)

    print(f"[Restorer] Total blocks to restore: {len(latest_block)}")

    # Write the latest known snapshot for each block id
    t2 = time.perf_counter() if profile else None
    with open(img_path, "r+b") as f:
        sorted_blocks = sorted(latest_block.keys())
        run = []
        last = None
        for bid in sorted_blocks + [None]:
            if run and (bid is None or bid != last + 1):
                # Write contiguous run efficiently
                start = run[0]
                blocks = [latest_block[i][1] for i in run]
                if debug:
                    print(f"[Restorer][DEBUG] Writing blocks {start} to {run[-1]} (count: {len(blocks)})")
                f.seek(start * block_size)
                f.write(bytes(np.array(blocks, dtype=np.uint8).flatten()))
                run = []
            if bid is not None:
                run.append(bid)
                last = bid

    t3 = time.perf_counter() if profile else None
    profmsg("Block writing (image restoration)", t3, t2)

    if debug:
        print(f"[Restorer][DEBUG] Device image restore complete: {img_path}")
    if profile:
        total_elapsed = (t3 - t_start) * 1000 if t_start is not None else None
        print(f"[Profile][Restorer] Total restore_device_snapshot_image_file time: {total_elapsed:.2f} ms")


def pre_restore_device_snapshot(epoch, size, directory=".", debug=False, profile=False):
    """
    Preprocessing restoration: always overwrites 'device_{epoch}.img'.
    """
    img_path = os.path.join(directory, f"device_{epoch}.img")
    restore_device_snapshot_core(
        epoch=epoch,
        size=size,
        img_path=img_path,
        directory=directory,
        debug=debug,
        profile=profile,
        overwrite=True
    )


def post_restore_device_snapshot(epoch, size, directory=".", debug=False, profile=False):
    """
    Postprocessing restoration: creates 'device_recovered_{epoch}_{timestamp}.img', never overwrites.
    """
    timestamp = datetime.utcnow().strftime("%Y%m%dT%H%M%S")
    img_path = os.path.join(directory, f"device_recovered_{epoch}_{timestamp}.img")
    restore_device_snapshot_core(
        epoch=epoch,
        size=size,
        img_path=img_path,
        directory=directory,
        debug=debug,
        profile=profile,
        overwrite=False
    )
