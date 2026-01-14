# Rhea

Cloud-based **Privilege-Evasive Ransomware Defense Mechanism**.

Rhea is a research prototype that provides a snapshot-based defense pipeline against ransomware attacks. It preprocesses block-level mutations, detects ransomware-like encryption patterns, and restores valid device snapshots for analysis and recovery.  


---

## 📦 Installation & Build

Clone the repository and set up a Python virtual environment:

```bash
git clone https://github.com/<your-org>/rhea.git
cd rhea
python3 -m venv .venv
source .venv/bin/activate
pip install -e .
```

This will:

* Install dependencies defined in `pyproject.toml`
* Register console scripts such as `rhea-preprocess`, `rhea-detect`, etc.

---

## Workflow

1. Setup Rocky ("refer to README of Rocky")
2. Run workload ("refer to README of PERSim")
3. Preprocessing (See below)
4. Detecting (See below)

---

## 🚀 Running the Preprocessor (Incremental 1..N)

The **preprocessor** is the first step of the pipeline. It fetches block-mutation data, saves Parquet mutation snapshots and bitmaps **for epochs `1..N`**, and restores the latest device snapshot **as of `N`**.

It now runs **incrementally by default**: for each epoch `e ∈ [1..N]`, it **skips** work if both `mutation_e.parquet` and `bitmap_e.bin` already exist in the output directory. Use `--force-overwrite` to rebuild everything.

### Required Arguments

* `--output` → output directory for snapshots and bitmaps  
* `--device-size` → size of the device image (in bytes)  
* `--end-epoch` → ending epoch (inclusive) for this run  
  *(Legacy: `--epoch` is still accepted and treated as `--end-epoch`.)*

### Optional Arguments

* `--skip-restore` → do not reconstruct the device image after writing snapshots  
* `--force-overwrite` → rebuild snapshots for **all** epochs `1..end` (ignore any existing files)  
* `--debug` → enable debug mode (extra logging, assertions)  
* `--profile` → enable fine-grained timing measurements  

### What It Produces

In the `--output` directory:

* `mutation_<epoch>.parquet` → snapshot of mutated blocks for each epoch in **1..end**  
* `bitmap_<epoch>.bin` → dirty bitmap (packed bits) for each epoch in **1..end**  
* `device_<end-epoch>.img` → reconstructed device image **as of** `end-epoch` (unless `--skip-restore`)  

> **Note:** Empty epochs are still written as empty Parquet files to keep downstream stages stable.

### Example Runs

What I am using:
```bash
rhea-preprocess --epoch 4 --output attack_out --device-size 1073741824 --debug --profile```


**1) Incremental run to epoch 168 (skip already present epochs):**
```bash
rhea-preprocess \
  --end-epoch 168 \
  --output out \
  --device-size 2147483648 \
  --profile
```

**2) Force full rebuild 1..168:**
```bash
rhea-preprocess \
  --end-epoch 168 \
  --output out \
  --device-size 2147483648 \
  --force-overwrite
```

**3) Produce only snapshots (no device restore):**
```bash
rhea-preprocess \
  --end-epoch 168 \
  --output out \
  --device-size 2147483648 \
  --skip-restore
```

### Sample Output (abridged)

```text
[Preprocessor] Processing epochs 1..168 (inclusive)
[Preprocessor] Output dir: out
[Preprocessor] Profiling mode enabled.
[materialize][skip] epoch 1 (both outputs already present)
[materialize][skip] epoch 2 (both outputs already present)
[save_epoch] Mutation snapshot saved to out/mutation_167.parquet (rows=...)
[save_epoch] Dirty bitmap saved to out/bitmap_167.bin (bytes=...)
[Profile] save_epoch total (epoch 167): 139.882 ms
[save_epoch] Mutation snapshot saved to out/mutation_168.parquet (rows=...)
[save_epoch] Dirty bitmap saved to out/bitmap_168.bin (bytes=...)
[Profile] save_epoch total (epoch 168): 145.221 ms
[Profile] restore_device_snapshot_image_file: 244.876 ms
[Preprocessor] Done. Total time taken: 692.115 ms
```

---

## 🔎 Running the Detector

The **detector** analyzes snapshots from two epochs, extracts deltas, runs SAWA entropy analysis, and maps suspicious blocks back to files.

Because the preprocessor materializes **all epochs from 1..N incrementally**, the detector can analyze **any sub-window** `[start_epoch..end_epoch]` using the Parquet snapshots already present. If your detector uses the device image at `end_epoch` to read post-change bytes, ensure `device_<end>.img` exists (preprocessor creates it unless `--skip-restore`).

### Required Arguments

* `--start-epoch` → starting epoch for analysis window  
* `--end-epoch` → ending epoch for analysis window  
* `--snapshot-path` → path to preprocessor output (must contain `mutation_<epoch>.parquet` for the window; include `device_<end>.img` if your detector reads end-bytes)  
* `--output-path` → directory to store suspicious block/file mappings

### Optional Arguments

* `--whitelist-path` → path to whitelist SQLite DB (default: `<output-path>/whitelist.sqlite`)  
* `--extent-size` → extent size in bytes (default: 4096)  
* `--block-size` → block size in bytes (default: 512)  
* `--min-gap-length` → minimum gap length for delta extraction (default: 16)  
* `--width` → initial SAWA window width (default: 16)  
* `--stride` → SAWA window stride (default: 4)  
* `--chi2-threshold` → chi-squared threshold for SAWA (default: 350)  
* `--debug` / `--profile` → enable debug or profiling modes

### Example Run

IMPORTANT: Remeber you must mount the correct device_<epoch>.img to attack_out/tmp before running detection (rhea-detect)

For 2_2, I ran
```bash
time rhea-detect   --start-epoch 2 --end-epoch 2   --snapshot-path attack_out --output-path attack_out/detect --extent-size 4096 --block-size 512   --min-gap-length 16 --width 16 --stride 8   --chi2-threshold 350 --min-expansio
ns 3 --max-chi2-var 3000 --trusted-manifest input/trusted_manifest_media.csv --end-mount-root attack_out/tmp --out-formats 'csv' --audit-formats 'csv' --block-debug --block-debug-outdir block_debug_2_2 &> detect.log                     
```

For 3_3, I ran
```bash
time rhea-detect   --start-epoch 3 --end-epoch 3   --snapshot-path attack_out --output-path attack_out/detect   --extent-size 4096 --block-size 512   --min-gap-length 16 --width 16 --stride 8   -
-chi2-threshold 350 --min-expansions 3 --max-chi2-var 3000 --trusted-manifest input/trusted_manifest_media.csv --end-mount-root attack_out/tmp --out-formats 'csv' --audit-formats 'csv' --block-debug --block-debug-audit ../persim/work/cl
one-20250906-204448/audits/audit_20250906-204502.ndjson --block-debug-path-match basename --block-debug-outdir block_debug_3_3 &> detect.log
```

For 4_4, I ran
```bash
time rhea-detect   --start-epoch 4 --end-epoch 4   --snapshot-path attack_out --output-path attack_out/detect   --extent-size 4096 --block-size 512   --min-gap-length 16 --width 16 --stride 8   -
-chi2-threshold 350 --min-expansions 3 --max-chi2-var 3000 --trusted-manifest input/trusted_manifest_media.csv --end-mount-root attack_out/tmp --out-formats 'csv' --audit-formats 'csv' --block-debug --block-debug-audit ../persim/work/clone-20250917-111716/audits/audit_20250917-111850.ndjson --block-debug-path-match basename --block-debug-outdir block_debug_4_4 &> detect.log
```

To get eval result, I ran
```bash
rhea-postprocess --gt-base ./block_debug_4_4 --rhea-dir ./attack_out/detect/suspicious_block_mappings_4_4_csv --out-dir ./eval_out --device-image attack_out/device_4.img &> eval_4_4_out/eval.log
```

```bash
# Analyze epochs 120..168 using snapshots in ./out
rhea-detect \
  --start-epoch 120 \
  --end-epoch 168 \
  --snapshot-path out \
  --output-path out/detect \
  --extent-size 4096 \
  --block-size 512 \
  --min-gap-length 16 \
  --width 16 \
  --stride 4 \
  --chi2-threshold 350 \
  --profile
```

This will produce in `out/detect/`:

* `suspicious_block_mappings_120_168.parquet` → structured suspicious block→file mappings  
* `suspicious_block_mappings_120_168_csv/` → equivalent CSV files (Spark part files)

---

## 🔄 Example End-to-End Workflow

```bash
# Step 1. Preprocess mutation snapshots incrementally to epoch 168 (1..168)
rhea-preprocess --end-epoch 168 --output out --device-size 2147483648

# Step 2. Detect suspicious encryption patterns on a chosen window
rhea-detect --start-epoch 150 --end-epoch 168 --snapshot-path out --output-path out/detect

# Step 3. Postprocess detection results into a summary report
rhea-postproc --input out/detect --report reports/summary.json

# (Optional) Restore or re-restore a specific epoch image later
rhea-restore --epoch 160 --input out --output restored_160.img
```

---

## 🗂 Project Layout

```
rhea/
├── configs/         # Example configuration files
├── sample_data/     # Sample input data for testing
├── src/             # Source code
│   ├── preprocessor/
│   ├── detector/
│   ├── postprocessor/
│   ├── restorer/
│   └── utils/
├── tests/           # Unit tests
├── pyproject.toml   # Project metadata & dependencies
└── README.md        # This file
```

---

## 🧪 Development

Run the test suite with:

```bash
pytest
```

Install developer dependencies via:

```bash
pip install -e ".[dev]"
```

---

## Verify

Run the Python script, verify_detection_vs_manifest.py :

```bash
python src/utils/verify_detection_vs_manifest.py --suspicious attack_out/detect/suspicious_regions_3_3_csv/part-00000-b2764f2f-da34-451c-b39c-fdd187ba2e67-c000.csv --blockmap attack_out/detect/suspicious_block_mappings_3_3_csv/part-00000-4267dfc7-1e55-42e4-9c01-a7a1b2754b6b-c000.csv --manifest ../persim/work/clone-20250906-204448/manifests/manifest_20250906-204502.json --epoch 3 --file-prefix /cloned- --default-prefix-bytes 4096 --path-match basename --out-dir out_verify
```

---

## 📄 License

Rhea is released under the **MIT License**. See [LICENSE](LICENSE) for details.

---

## ✨ Acknowledgments

Anonymized Authors.
