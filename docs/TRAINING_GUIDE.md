# StealthTap Model Training Guide

This is the practical companion to `MODEL_CONTRACT.md`. Use `train_model_template.py` for all four families — the training/evaluation/export pipeline is already built and verified end-to-end; you only edit the CONFIG block and `row_to_flow()` per dataset.

## The pipeline has been verified end-to-end (not just written — actually run)

I ran this exact template against a 30k-domain subsample of real DGA data before handing it off, to catch bugs before you hit them. It found and fixed two real issues:

1. `skl2onnx` needs the ONNX-ML domain opset specified separately from the general opset (`target_opset={"": 17, "ai.onnx.ml": 3}`, not a plain int) — already fixed in the template.
2. I confirmed the exact ONNX output tensor shapes for both XGBoost and Isolation Forest against real exported artifacts, and verified `model_server.py`'s extraction logic reads them correctly. This was previously an open, untested assumption — it no longer is.

**Real results from that smoke-test run** (held-out test set, not training data):

| Model | Precision | Recall | F1 | ROC-AUC |
|---|---|---|---|---|
| XGBoost | 0.92 | 0.84 | 0.87 | 0.95 |
| Isolation Forest | 0.79 | 0.17 | 0.28 | 0.74 |

**Read this honestly, don't hide it:** Isolation Forest alone is much weaker than XGBoost here. That's expected, not a bug — it was trained only on benign lexical patterns and isn't trying to beat a supervised model on the exact same distribution it saw in training. Its actual job is catching DGA structures neither model has seen before. If a jury asks about that gap, this is a defensible, honest answer: "the anomaly detector trades recall on known patterns for the ability to flag novel ones the supervised model was never trained on — that's the point of running both."

This smoke-test model (`dns_xgboost_v1.onnx` + `dns_isolation_forest_v1.onnx` + `MANIFEST.json`, included in this handoff) is **not your submission model** — it's trained on a 30k subsample for speed, not the full 675k-row dataset. Drop it into `models/` now to test the FastAPI `/score/dns` endpoint immediately while your real training runs; retrain on the full dataset locally for your actual numbers.

## Where to get real, labeled data per family

| Family | Source | Notes |
|---|---|---|
| `dns` | [chrmor/DGA_domains_dataset](https://github.com/chrmor/DGA_domains_dataset) | 675k domains, 25 DGA families + Alexa benign. Cite: Cucchiarelli et al. 2021, *Expert Systems with Applications*, DOI 10.1016/j.eswa.2020.114551 |
| `flow` | [CICIDS2017/2018 (UNB CIC)](https://www.unb.ca/cic/datasets/ids-2017.html) | The standard IT benchmark, already referenced in your own README. Column names vary by CSV release — check the actual header before editing `row_to_flow()`. |
| `modbus` | [CIC Modbus 2023 (UNB)](https://www.unb.ca/cic/datasets/modbus-2023.html) | Recent, comprehensive, attack types explicitly mapped to MITRE ATT&CK for ICS — lines up directly with your MITRE requirement. Backup: LeMay et al.'s SCADA dataset (USENIX CSET'16), widely cited. |
| `tls` | **No strong public option found.** | JA4 is newer than JA3; public labeled malicious-fingerprint sets haven't caught up. Recommended: self-generate with your own traffic harness — known C2 emulator traffic for malicious examples, ordinary browser/app captures for benign. You control ground truth completely this way, which scraped fingerprint lists usually can't guarantee. |

## How to adapt the template per family

Only two functions need editing — everything else (split, training, evaluation, ONNX export, MANIFEST.json) is shared and already tested:

```python
FAMILY = "flow"  # change this
DATASET_CSV = "path/to/your/downloaded/dataset.csv"

def row_to_flow(row):
    # map YOUR dataset's actual column names into the flow-dict shape
    # feature_extraction.py expects for this family
    ...

def is_malicious(row):
    # how to read YOUR dataset's label column
    ...
```

Run it: `python3 train_model_template.py`. It'll print both models' held-out metrics, then write `models/{family}_xgboost_v1.onnx`, `models/{family}_isolation_forest_v1.onnx`, and update `models/MANIFEST.json`.

## Evaluation discipline (repeat this from MODEL_CONTRACT.md, it matters)

The template gives you a standard 70/15/15 split. For your real submission, also run the **family-holdout** variant for `dns` (train on 20 malware families, test only on 5 never seen — the pattern from the original `train_dga_model.py`) and a **temporal holdout** for `flow`/`modbus`/`tls` (train on one time slice, test on later traffic). Report both the standard and holdout numbers in your documentation — the holdout number is the one that actually answers "does this generalize," which is what a jury question about robustness is really asking.
