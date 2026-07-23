# VERA: Validated Execution-based Ransomware Analysis

**A dual-validated, behaviorally-verified repository of 15,000+ raw Windows ransomware binaries.**

[![DOI](https://img.shields.io/badge/DOI-10.5281%2Fzenodo.17904705-blue)](https://doi.org/10.5281/zenodo.17904705)
[![License](https://img.shields.io/badge/License-SEE%20BELOW-lightgrey)](#license)
[![Paper](https://img.shields.io/badge/Paper-IEEE%20ICCCN-orange)](#citation)

---

> ## ⚠️ Safety Notice: This Repository Contains Live Malware
>
> Every file under `Binary Files/` is a **functional, unmodified ransomware sample**. Executing, extracting, or mishandling these binaries can encrypt data, disable recovery mechanisms, and spread across a network.
>
> **Do not run any sample outside an isolated, disposable, network-restricted analysis environment.** These files are provided strictly for defensive security research, malware analysis, and machine-learning study. See [Responsible Handling](#responsible-handling) before you download anything.

---

## Table of Contents

- [Overview](#overview)
- [What Is in This GitHub Repository](#what-is-in-this-github-repository)
- [Full Dataset on Zenodo](#full-dataset-on-zenodo)
- [Repository Structure](#repository-structure)
- [Dataset Composition](#dataset-composition)
- [How VERA Was Built](#how-vera-was-built)
- [Family Labels](#family-labels)
- [File and Artifact Reference](#file-and-artifact-reference)
- [Getting Started](#getting-started)
- [Responsible Handling](#responsible-handling)
- [Reproducing the Paper](#reproducing-the-paper)
- [Citation](#citation)
- [License](#license)
- [Ethical Use and Disclaimer](#ethical-use-and-disclaimer)
- [Authors and Contact](#authors-and-contact)
- [Acknowledgements](#acknowledgements)

---

## Overview

Reliable ransomware detection research is held back by a shortage of high-quality, reproducible data. Public repositories often carry label noise, where generic malware, benign files, or corrupted binaries are misclassified as ransomware, and they rarely confirm that a sample actually does anything when executed.

**VERA (Validated Execution-based Ransomware Analysis)** addresses this with a two-stage validation pipeline. Every candidate is filtered through multi-vendor static consensus and then verified by dynamic execution in a sandbox. Samples are separated into two clearly defined partitions:

- **VERA-Active:** samples that satisfy static consensus **and** exhibit at least one high-confidence ransomware behavior during execution, such as volume shadow copy deletion, high-entropy file writes, or ransom note generation.
- **VERA-Latent:** samples that satisfy the same static consensus but stay behaviorally silent within the execution window, for reasons such as defunct infrastructure, delayed triggers, or environment-specific execution checks.

This separation lets researchers study behavioral viability, delayed-trigger behavior, and the limits of static-only labeling, rather than blindly mixing active and dormant binaries.

The dataset ships with raw binaries, full sandbox execution logs, pre-extracted features, unified family labels, and the validation and analysis code, so results can be reproduced end to end.

---

## What Is in This GitHub Repository

This GitHub repository is a **lightweight sample** intended for researchers who just read the paper and want to inspect the data structure, labels, and code quickly, without downloading tens of gigabytes.

It contains:

- A representative subset of roughly **1,000 binary files** drawn from the `VERA-Active` and `VERA-Latent` partitions.
- The complete **label files** for the full dataset.
- The full **analysis and validation code** (notebooks and scripts).
- The **VirusTotal report analysis** artifacts.

It does **not** contain the complete set of binaries or the complete set of per-sample CAPE execution logs. The full corpus lives on Zenodo (see below).

> The label CSVs in this repo describe the **entire** dataset, not only the sampled binaries. A given hash listed in the labels may therefore not have its binary present here. Use the Zenodo archive when you need the full set.

---

## Full Dataset on Zenodo

The complete VERA dataset, including all raw binaries, all CAPE Sandbox JSON execution reports, and all metadata, is archived at:

**https://doi.org/10.5281/zenodo.17904705**

Please cite the Zenodo record and the paper when you use the data (see [Citation](#citation)).

---

## Repository Structure

```text
VERA Dataset/
├── Analysis/
│   └── VirusTotal Reports/          # Aggregated VirusTotal detection reports and analysis
│
├── Binary Files/                    # Raw ransomware binaries (SAMPLE SUBSET in this repo)
│   ├── VERA-Active/                 # Behaviorally verified, actively malicious samples
│   └── VERA-Latent/                 # Statically confirmed but behaviorally silent samples
│
├── Code/
│   ├── Family_Classification/       # Dual-stage family labeling pipeline
│   ├── RWvsMW For Dataset paper.ipynb        # Ransomware vs. general malware benchmark
│   ├── VirusTotal Report Generation.ipynb    # Static consensus report generation
│   ├── RansomwareVerification.ipynb          # Dynamic behavioral validation logic
│   └── feature_dataset_true.csv              # Pre-extracted feature set
│
└── Labels/
    ├── vera_labels.csv              # Behavioral status per sample (Active / Latent)
    ├── Family_Consensus_Labels.csv # Stage I consensus family labels
    └── Final_Family_Labels.csv     # Final unified family label per sample
```

---

## Dataset Composition

| Category                        | Count  | Released |
| ------------------------------- | ------ | -------- |
| Candidate samples collected     | 44,678 | Pool     |
| **VERA-Active**                 | 15,448 | Yes      |
| **VERA-Latent**                 | 22,837 | Yes      |
| Excluded (failed execution)     | 6,293  | No       |

Samples were collected from VX Underground, VirusShare, MalwareBazaar, and Malshare, spanning **2019 to 2024**. Failed-execution samples (crashes, immediate termination, or empty logs) are excluded from the release. Note that latent samples are **not** benign; they are ransomware-labeled binaries whose malicious behavior could not be dynamically confirmed under the analysis conditions.

---

## How VERA Was Built

VERA uses a multi-stage construction pipeline designed to remove low-quality noise and confirm behavioral fidelity.

**Step 1: Sample collection.**
Candidate binaries were gathered from four widely used malware repositories.

**Step 2: Dual verification.**

- *Static consensus (VirusTotal).* A sample passes static verification only if at least **four distinct antivirus vendors** independently flag it as ransomware. This threshold reduces the impact of noisy or overly generic single-engine detections.
- *Dynamic execution (CAPE Sandbox).* Every sample is executed for **3 minutes** in a sandbox configured to imitate a realistic user environment and resist common virtualization-evasion checks. Raw execution logs are captured for validation.

**Step 3: Behavioral validation.**
A deterministic classifier, adapted from the ransomware behavioral taxonomy of Hou et al., scans the execution logs for indicators across three lifecycle stages:

1. **System profiling and staging:** cryptographic API queries, recovery-tool enumeration, and network discovery commands.
2. **Recovery inhibition and encryption:** volume shadow copy deletion via `vssadmin` or `wmic`, high-entropy write bursts, and event-log clearing.
3. **Extortion and propagation:** data egress tooling, SMB or WSDAPI connections, and ransom note generation.

A sample is labeled **Active** if it produces at least one high-confidence indicator, such as backup deletion, multi-file high-entropy writes, or ransom note creation. Otherwise it is labeled **Latent**.

---

## Family Labels

Family labels are produced by a **dual-stage labeling pipeline**.

**Stage I: Consensus.**
Three independent labeling tools are run on each sample: **AVClass**, **Euphony**, and **ClarAVy**. When at least two of the three agree on the same family name, the sample joins the **Consensus Set**. The rest form the **Contested Set**.

| Set            | Count  | Percentage |
| -------------- | ------ | ---------- |
| Consensus Set  | 12,864 | 83.27%     |
| Contested Set  | 2,584  | 16.73%     |
| **Total**      | 15,448 | 100.00%    |

**Stage II: Propagation.**
The Consensus Set is treated as trusted training data for an **XGBoost** classifier, using combined static and behavioral features. The model then assigns a single family label to every sample in the Contested Set. The finalized labeling covers **15,448 samples across 671 unique ransomware families**.

### Top 20 families by sample count

| Family        | Count | Percent | Family         | Count | Percent |
| ------------- | ----- | ------- | -------------- | ----- | ------- |
| gimemo        | 1,605 | 10.39%  | wannacry       | 416   | 2.69%   |
| timer         | 808   | 5.23%   | hexzone        | 414   | 2.68%   |
| revil         | 650   | 4.21%   | globeimposter  | 406   | 2.63%   |
| fullscreen    | 629   | 4.07%   | 7ev3n          | 342   | 2.21%   |
| locky         | 610   | 3.95%   | shade          | 339   | 2.19%   |
| cerber        | 585   | 3.79%   | gandcrab       | 334   | 2.16%   |
| zedopoo       | 571   | 3.70%   | hmlocker       | 309   | 2.00%   |
| pornostser    | 528   | 3.42%   | drolnux        | 276   | 1.79%   |
| fakeinstaller | 498   | 3.22%   | birdele        | 265   | 1.72%   |
| xorist        | 453   | 2.93%   | zard           | 253   | 1.64%   |

The top 20 families account for 10,291 samples (66.62%), with the remaining 33.38% spread across a long tail of less frequent families.

---

## File and Artifact Reference

### Labels

| File                          | Description                                                                 |
| ----------------------------- | --------------------------------------------------------------------------- |
| `vera_labels.csv`             | Behavioral status per sample (Active or Latent), keyed by SHA256 hash.      |
| `Family_Consensus_Labels.csv` | Stage I family labels, limited to Consensus Set samples.                    |
| `Final_Family_Labels.csv`     | Final unified family label per sample after Stage II propagation.           |

### Code

| File                                   | Description                                                              |
| -------------------------------------- | ------------------------------------------------------------------------ |
| `VirusTotal Report Generation.ipynb`   | Retrieves and aggregates VirusTotal reports for static consensus.        |
| `RansomwareVerification.ipynb`         | Parses CAPE logs and applies the behavioral validation logic.            |
| `RWvsMW For Dataset paper.ipynb`       | Ransomware vs. general malware benchmark (VERA-Active vs. BODMAS).        |
| `Family_Classification/`               | Stage I consensus and Stage II model-based label propagation.            |
| `feature_dataset_true.csv`             | Pre-extracted feature set used across the analysis notebooks.            |

### Features

For every sample, the full Zenodo release provides the raw binary, the complete CAPE Sandbox JSON report, and a pre-processed feature set covering API call traces, file system operations, registry modifications, network activity, and process behavior. All feature extraction is deterministic and derived only from released artifacts, so results can be regenerated without proprietary tools or manual annotation.

---

## Getting Started

1. Read [Responsible Handling](#responsible-handling) first.
2. Clone the repository.

   ```bash
   git clone https://github.com/garvit-agarwal-purdue/VERA-Dataset.git
   cd "VERA Dataset"
   ```

3. Explore the labels and features without touching any binary.

   ```python
   import pandas as pd

   status = pd.read_csv("Labels/vera_labels.csv")
   families = pd.read_csv("Labels/Final_Family_Labels.csv")

   print(status["status"].value_counts())      # adjust column name to match the file
   print(families["family"].value_counts().head(20))
   ```

4. To work with binaries, move them into an isolated analysis VM **before** extracting or executing anything.

> The column names in the snippet above are illustrative. Open each CSV header first to confirm the exact field names.

---

## Responsible Handling

These samples are live. Treat them accordingly.

- **Isolation.** Analyze only inside a dedicated virtual machine with host isolation. Never handle samples on a primary workstation or a machine with access to production or personal data.
- **No network.** Disable networking, or route through a controlled, monitored analysis network. Some samples attempt to reach command-and-control infrastructure or spread laterally.
- **Snapshots.** Take a clean VM snapshot before execution and revert after every run.
- **No shared storage.** Keep samples off shared drives, cloud sync folders, and backup targets.
- **Archive password.** If the binaries are distributed inside password-protected archives, the archive password is `<CONFIRM_PASSWORD>`. The malware research community commonly uses `infected` for this purpose. Confirm the value used in your release before publishing.
- **Legal duty.** You are responsible for complying with all applicable laws, your institution's policies, and the terms under which the source repositories distribute these samples.

---

## Reproducing the Paper

The notebooks under `Code/` reproduce the core results:

- **Behavioral validation:** `RansomwareVerification.ipynb` classifies each sample as Active or Latent from its CAPE log.
- **Family labeling:** `Family_Classification/` builds the Stage I consensus and trains the Stage II XGBoost propagation model.
- **Distinctiveness benchmark:** `RWvsMW For Dataset paper.ipynb` reproduces the binary classification of VERA-Active against the BODMAS general-malware dataset, where standard classifiers reach near-perfect separation. As noted in the paper, this benchmark is a label-purity sanity check rather than a deployment claim.

To run the full pipeline, download the complete binaries and CAPE reports from the Zenodo record and point the notebook paths at your local copy.

---

## Citation

If you use VERA in your work, please cite both the paper and the dataset.

**Paper:**

```bibtex
@inproceedings{agarwal2026vera,
  title     = {VERA: A Dual-Validated, Behaviorally-Verified Repository of 15,000+ Raw Windows Ransomware Binaries},
  author    = {Agarwal, Garvit and Vasanth, Nithish and Cho, Seunghyun and Alomayri, Yousef Mohammed Y. and Pumphrey, Noah D. and Li, Feng and Xie, Yucheng and Zou, Xukai},
  booktitle = {IEEE International Conference on Computer Communications and Networks (ICCCN)},
  year      = {<YEAR>},
  pages     = {<PAGES>},
  publisher = {IEEE}
}
```

**Dataset:**

```bibtex
@dataset{agarwal2026vera_dataset,
  title     = {VERA: Validated Execution-based Ransomware Analysis Dataset},
  author    = {Agarwal, Garvit and Vasanth, Nithish and Cho, Seunghyun and Alomayri, Yousef Mohammed Y. and Pumphrey, Noah D. and Li, Feng and Xie, Yucheng and Zou, Xukai},
  year      = {<YEAR>},
  publisher = {Zenodo},
  doi       = {10.5281/zenodo.17904705},
  url       = {https://doi.org/10.5281/zenodo.17904705}
}
```

---

## License

The code and the data may carry different licenses. Please confirm and state them explicitly before publishing, for example:

- **Code:** `<CODE_LICENSE, e.g. MIT>`
- **Data and labels:** `<DATA_LICENSE, e.g. CC BY 4.0 or a research-only license>`
- **Binaries:** subject to the terms of the originating repositories (VX Underground, VirusShare, MalwareBazaar, Malshare) and intended for defensive research use only.

Replace these placeholders with your final choices and add the corresponding `LICENSE` file to the repository.

---

## Ethical Use and Disclaimer

VERA is released to support defensive security research, malware analysis, and machine-learning study. By downloading any part of this repository you agree to use it only for lawful, ethical, defensive purposes.

The authors and their institutions provide these materials "as is," without warranty of any kind, and accept no liability for any damage, data loss, or misuse arising from the download, handling, or execution of these samples. Do not use this dataset to develop, deploy, or distribute malicious software.

---

## Authors and Contact

- Garvit Agarwal, Nithish Vasanth, Seunghyun Cho, Yousef Mohammed Y. Alomayri, Noah D. Pumphrey, Feng Li, Purdue University
- Yucheng Xie, Yeshiva University
- Xukai Zou, Indiana University Indianapolis

For questions about the dataset, contact `agarw347@purdue.edu`.

---

## Acknowledgements

We thank VX Underground, VirusShare, MalwareBazaar, and Malshare for sample access, VirusTotal for the academic API used in static consensus, and the CAPE Sandbox project for the dynamic analysis environment.
