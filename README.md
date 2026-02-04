I. Artifacts
1. Rhea source code
2. PERSim source code
3. Dataset (Sample only because all datasets are too large to host on a github repository)
4. Ransomware Samples (source link and hash identifiers only)
* NOTE: Please refer to the draft for the OS and VirtualBox versions we tested with.

II. To reproduce 6.1
1. Rhea is built on top of the open source project, Rocky, available at https://github.com/Kaelus/Rocky.
   Build it and set it up.
2. Build and set up PERSim for fast, skip-step, animagus attack patterns.
   2-1. fast
        ./setup-clone-attack.sh --input-root /home/cslab/project/rhea/sample_data --output-root /home/cslab/project/persim/tmp --pattern fast --bytes 4096 --cipher aes-ctr
   2-2. skip-step
   	./setup-clone-attack.sh --input-root /home/cslab/project/rhea/sample_data --output-root /home/cslab/project/persim/tmp --pattern skipstep --bytes 4096 --skip 4096 --cipher aes-ctr
   2-3. animagus
   	./setup-clone-attack.sh --input-root /home/cslab/project/rhea/sample_data --output-root /home/cslab/project/persim/tmp --pattern animagus --animagus-frac 25 --cipher aes-ctr
3. Run PERSim to clone and encrypt original files by running run.sh created after setup script above in step 2.
   e.g., /home/cslab/project/persim/work/clone-20251022-074921/run.sh
4. Flush all changes from the Rhea frontend to the Rhea backend (refer to Rocky's README)
5. Run the Rhea's preprocessor
   e.g., rhea-preprocess --epoch 3 --output attack_out --device-size 1073741824 --debug --profile
6. Run the Rhea's detector
   6-1. Mount the correct device_<epoch>.img to attack_out/tmp before running detection
   6-2a. Run for detection results
   	 e.g., rhea-detect --start-epoch 3 --end-epoch 3 --snapshot-path attack_out --output-path attack_out/detect --extent-size 4096 --block-size 512 --min-gap-length 16 --width 16 --stride 8 --chi2-threshold 350 --min-expansions 0 --max-chi2-var 3000 --trusted-manifest input/trusted_manifest_media.csv --end-mount-root attack_out/tmp --out-formats 'csv' --audit-formats 'csv' --block-debug --block-debug-audit ../persim/work/clone-20251004-063849/audits/audit_20251004-063924.ndjson --block-debug-path-match basename --block-debug-outdir block_debug_3_3
   6-2b. Run for performance profiling
   	 e.g., rhea-detect --start-epoch 3 --end-epoch 3 --snapshot-path attack_out --output-path attack_out/detect --extent-size 4096 --block-size 512 --min-gap-length 16 --width 16 --stride 8 --chi2-threshold 350 --min-expansions 0 --max-chi2-var 3000 --trusted-manifest input/trusted_manifest_media.csv --end-mount-root attack_out/tmp --out-formats 'csv' --audit-formats 'parquet' --profile &> detect.log
7. Run the Rhea's postprocessor
   e.g., rhea-postprocess --gt-base ./block_debug_3_3 --rhea-dir ./attack_out/detect/suspicious_block_mappings_3_3_csv --out-dir ./eval_out --device-image attack_out/device_3.img &> eval_3_3_out/eval.log

III. To reproduce 6.2
1. Prepare a directory to keep only a single file format.
   e.g., For the text file format:
   	 /home/cslab/project/rhea/txt_only_data
2. Build and set up PERSim for skip-step with different bytes parameters.
   e.g., To encrypt 64 bytes at a time:
   	 ./setup-clone-attack.sh --input-root /home/cslab/project/rhea/txt_only_data --output-root /home/cslab/project/persim/tmp --pattern skipstep --bytes 64 --skip 128 --cipher aes-ctr
3. Run PERSim to clone and encrypt original files by running run.sh created after the setup above.
4. Run Shannon-based detector
   4-1. For the text file format:
   	python content_detector.py --input-path /home/cslab/project/rhea/txt_only_data --output-path /tmp/rhea_runs --mode entropy --entropy-threshold 7.5
   4-2. For the zip file format:
   	python content_detector.py --input-path /home/cslab/project/rhea/zip_only_data --output-path /tmp/rhea_runs --mode entropy --entropy-threshold 7.9675
   4-3. For the docx file format:
  	python content_detector.py --input-path /home/cslab/project/rhea/docx_only_data --output-path /tmp/rhea_runs --mode entropy --entropy-threshold 7.9681
   4-4. For the pdf file format:
  	python content_detector.py --input-path /home/cslab/project/rhea/pdf_only_data --output-path /tmp/rhea_runs --mode entropy --entropy-threshold 7.9662
5. Run Chi2-based detector
   5-1. For the text file format:
    	python content_detector.py --input-path /home/cslab/project/rhea/txt_only_data --output-path /tmp/rhea_runs --mode chi2 --chi2-threshold 10000
   5-2. For the zip file format:
      	python content_detector.py --input-path /home/cslab/project/rhea/zip_only_data --output-path /tmp/rhea_runs --mode chi2 --chi2-threshold 180.6249
   5-3. For the docx file format:
      	python content_detector.py --input-path /home/cslab/project/rhea/docx_only_data --output-path /tmp/rhea_runs --mode chi2 --chi2-threshold 180.6249
   5-4. For the pdf file format:
      	python content_detector.py --input-path /home/cslab/project/rhea/pdf_only_data --output-path /tmp/rhea_runs --mode chi2 --chi2-threshold 190.2499
6. Run FAV-based detector
   6-1. For the text file format:
   	python3 txt_fav.py --input-path /home/cslab/project/rhea/txt_only_data --output-path /tmp/rhea_runs
   6-2. For the zip file format:
      	python3 zip_fav.py --input-path /home/cslab/project/rhea/zip_only_data --output-path /tmp/rhea_runs	
   6-3. For the docx file format:
      	python3 zip_fav.py --input-path /home/cslab/project/rhea/docx_only_data --output-path /tmp/rhea_runs	
   6-4. For the pdf file format:
   	6-4-1. First create the whitelist:
   	       python3 pdf_stream_whitelist.py --input-path /home/cslab/project/rhea/pdf_only_data --output-path /tmp/rhea_runs
	6-4-2. Run the fav with the whitelist:
	       python3 pdf_fav.py --input-path /home/cslab/project/rhea/pdf_only_data --output-path /tmp/rhea_runs --whitelist-dir /tmp/rhea_runs --whitelist-file pdf_stream_whitelist.json

IV. To reproduce 6.3
1. Get the ransomware sample on the public repositories, referring to samples.txt contains hashsum of each ransomware variant, ransomware family label, and the source, either MaruaderMap or MalwareBazaar.
2. Mount ransomware attacks in a VM as described in the draft and get the encrypted files on the host
3. Run the FAV-based detector as described in the step 6 of III above.

