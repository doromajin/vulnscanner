# recall/

Ground-truth corpus for continuous accuracy measurement.

## Structure

| Directory | Purpose | Expected outcome |
|---|---|---|
| `positive/` | Deliberately vulnerable code | All EXPECTED findings detected with correct severity |
| `negative/` | Safe / sanitized code | Zero active findings (any finding = false positive) |
| `real_fp/` | Historical false positives now fixed | Zero active findings (any finding = regression) |

## Running

```bash
python recall_check.py            # full benchmark
python recall_check.py --verbose  # also print all active findings
```

## Metrics

| Metric | Definition |
|---|---|
| **Recall** | TP / (TP + FN) — fraction of vulnerable cases detected |
| **Precision** | TP / (TP + FP) — fraction of detections that are correct |
| **Specificity** | TN / (TN + FP) — fraction of safe cases left clean |
| **F1** | 2 × Precision × Recall / (Precision + Recall) |

Units: positive cases are EXPECTED entries (per rule); negative/real_fp cases are files (per file).

## Adding cases

- **New vulnerability pattern** → add to `positive/<lang>/`; register in `recall_check.py` EXPECTED list
- **New safe pattern** → add to `negative/<lang>/`; no registration needed (any finding = failure)
- **Confirmed FP now fixed** → add to `real_fp/<lang>/` with a comment citing the commit and source
