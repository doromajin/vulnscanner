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

## real_world/

Ground truth taken from real projects, pinned by commit (needs the clones, so it is not part of CI).

| File | Content |
|---|---|
| `real_world/oss_labels.json` | Every non-INFO finding on a few OSS repos with a verdict: `TP`, `FP`, `HARDENING` (low risk by design), `DEP_ADVISORY`, `UNTRIAGED` (not looked at yet) |
| `real_world/disclosed.json` | Human-confirmed, vendor-reported bugs and whether the scanner is expected to find them |
| `real_world/check_real_world.py` | Scans each pinned commit and compares; exit 1 on a finding without a label (`NEW`), a lost TP (`LOST`) or a disclosed bug no longer found (`MISS`) |

```bash
python recall/real_world/check_real_world.py                # all available repos (VULNSCANNER_REPOS or --repos)
python recall/real_world/check_real_world.py --only kimai   # one repo / one disclosed case
python recall/real_world/check_real_world.py --init <repo>  # skeleton labels for a new repo
```

Rules for labels: only label what was read in the code (`UNTRIAGED` is honest, a guess is not); a rule change that
removes an `FP`/`HARDENING` finding is an improvement (`gone`), one that removes a `TP` is a regression.
The checker checks the commit out with a private index instead of `git archive`, because `export-ignore` in a
project's `.gitattributes` silently drops directories such as `assets/`.
