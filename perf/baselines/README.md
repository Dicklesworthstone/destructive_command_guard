# Performance Baselines

This directory stores JSON artifacts produced by `scripts/perf_baseline.py`.

Guidelines:
- Use stable filenames (date or tag) so diffs are easy to review.
- Do not overwrite existing baselines; add new files when re-measuring.
- Record the command line and environment in the baseline JSON itself.

Example:
```
./scripts/perf_baseline.py --bin ./target/release/dcg --output perf/baselines/2026-01-10.json
```
