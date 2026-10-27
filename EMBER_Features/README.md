# EMBER_Features

Generates **EMBER2024-compatible features** (thrember, EMBER feature version 3, 2,568-dim vector) for the VERA ransomware binaries.
Because the format is identical to EMBER2024's, VERA Active/Latent samples can be combined with EMBER2024 benign (or other) data,
or EMBER2024-trained models (e.g. its LightGBM benchmarks) can be tested directly on VERA ransomware.

Pinned: [EMBER2024](https://github.com/FutureComputing4AI/EMBER2024) commit `0ef753e81d98bf209f71b03cd331dfc190b5b54d`.

## Setup
Keep the venv on a local Linux filesystem (venvs can break on FUSE/NTFS mounts). Needs Python >= 3.10.
```bash
python3 -m venv ~/.venvs/vera-ember
~/.venvs/vera-ember/bin/pip install -r EMBER_Features/requirements.txt
```
Note: `signify` must be 0.7.1 (newer versions break thrember). On hosts with OpenSSL 3.0.x the script
auto-points `oscrypto` at the system `libcrypto.so.1.1` (needed by signify); install `libssl1.1` if it is missing.

## Run
```bash
# from the repo root; full dataset (resumable - just re-run the same command)
# VERA=<folder where you extracted the full Zenodo release>
~/.venvs/vera-ember/bin/python -I EMBER_Features/extract_ember_features.py extract \
  --binaries-dir "$VERA/Binary Files/VERA-Active" \
  --binaries-dir "$VERA/Binary Files/VERA-Latent" \
  --labels-dir Labels --out-dir EMBER_Features/output --workers 8 --vectorize
# vectorize only (re-create X_vera.dat from raw_features.jsonl)
~/.venvs/vera-ember/bin/python -I EMBER_Features/extract_ember_features.py vectorize --out-dir EMBER_Features/output
```
Other flags: `--limit N` (per folder, for tests), `--timeout 120` (per file, seconds), `--retry-failed`.
Partition name = folder name minus `VERA-` (Active, Latent). Each file's SHA256 is its filename (`.bin` stripped).

## Outputs (`--out-dir`)
| File | Content |
|---|---|
| `raw_features.jsonl` | One JSON object per file, as produced by `thrember.PEFeatureExtractor.raw_features` (`sha256`, `general`, `histogram`, `byteentropy`, `strings`, `header`, `section`, `imports`, `exports`, `datadirectories`, `richheader`, `authenticode`, `pefilewarnings`), readable by EMBER tooling. Extra fields: `vera_sha256`, `vera_partition`, `vera_family` (Final_Family; Active only, else null), `vera_label_source` (null if the labels file has no `Label_Source`). EMBER's own label fields (`label`, `family`, ...) are **not** written - EMBER's metadata is not available for VERA. |
| `X_vera.dat` | float32 memmap, shape `(N, 2568)`, row order = `index.csv`. Made with EMBER's `process_raw_features` (same as `thrember.vectorize`). Read: `np.memmap(p, dtype=np.float32, mode="r").reshape(-1, 2568)` |
| `index.csv` | `row,sha256,partition,family,label_source,is_pe` |
| `failures.csv` | `sha256,partition,error_type,error_message` for files that failed or timed out |
| `run_info.json` | thrember commit, feature version, vector dim, counts per partition (ok / non-PE / failed), timing of the last run |

Note: `thrember.read_vectorized_features` / `create_vectorized_features` expect EMBER's `X_<subset>.dat` + `y_<subset>.dat`
naming and label fields, so load `X_vera.dat` directly; labels (partition/family) come from `index.csv`.
Latent/Active are not EMBER "malicious/benign" labels; define your own `y` from `index.csv`.

## Non-PE files
EMBER2024 handles non-PE input natively: pefile parsing fails quietly and only the general, byte-histogram, byte-entropy and string
features are populated (`general.is_pe = 0`; the PE-specific blocks are empty/zero in the vector). So scripts, MSI/OLE, LNK, ELF, DEX
and blobs are **kept**, flagged via `is_pe` in `index.csv`, and counted under `non_pe_per_partition` in `run_info.json`.
Only genuine errors (e.g. empty file, timeout, worker crash) go to `failures.csv`.

## Runtime and safety
- Full run (38,285 files, ~45 GB, 8 workers): 23 min (~0.04 s/file), with 0 failures and 318 non-PE files kept.
  Output is ~704 MB: `raw_features.jsonl` 341 MB and `X_vera.dat` 393 MB.
- Per-file timeout uses `SIGALRM` in the worker; a crashed worker is recorded as `WorkerCrash` and the pool is rebuilt.
- **The binaries are live ransomware.** The tool only reads bytes (`open(..., "rb")`) for static parsing; nothing is executed, copied,
  moved or modified. Run with `python -I`, keep scripts outside the binary folders, and do not open the files with OS handlers.
