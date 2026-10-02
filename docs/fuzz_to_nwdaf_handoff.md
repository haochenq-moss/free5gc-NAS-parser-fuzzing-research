# Fuzz-to-NWDAF Evidence Handoff

## Purpose and Current Status

This guide connects the implemented offline NAS parser fuzzing workflow in this repository to the input-testing and NWDAF-style analytics records in the separate `nwdaf-research` repository. It defines an evidence handoff, not an automatic live replay or mitigation feature.

The lab currently fuzzes `message.ParseGMM` and `message.ParseGSM` through Go/AFL++ parser harnesses. Those runs do not start free5GC network functions or create SBI/PFCP traffic. The NWDAF repository has `fuzz-run-v1` provenance, input/outcome/run-label records, run-level Linux/SBI/PFCP feature evaluation, and a fixed read-only NRF discovery helper. It does not currently have a NAS PDU injection/replay adapter. In particular, the NRF GET helper is not a NAS replay path and must not be used to imply one.

## Evidence Flow

```text
ordinary or LLM seed
  -> bounded offline NAS parser fuzz run
  -> candidate path/crash/coverage observation
  -> deterministic parser reproduction and oracle
  -> human bug review
  -> [future: explicitly approved NAS replay adapter in isolated free5GC lab]
  -> NWDAF-format run bundle + Linux/SBI/PFCP observations
  -> held-out input_test-vs-normal telemetry analysis
  -> analyst decision
  -> [separate authorization/rollback gate before any mitigation]
```

Every transition adds evidence; none promotes a lower-level observation into a higher-level claim automatically.

## Stable Handoff Identity

Use the same stable `input_id` for one exact byte sequence across both repositories and verify its SHA-256 at every copy. Link records with:

- The NWDAF campaign directory (campaign identity).
- `input_id` (the case identifier).
- `input_sha256` / `input.sha256` (the byte-level identity check).
- `free5gc_commit` (the target source revision).

The lab's fuzz-run record should use the existing `fuzz-run-v1` contract implemented in `nwdaf-research/schemas/fuzz-run.schema.json` and `src/nwdaf_research/input_testing/fuzz_provenance.py`. Store that record as a sidecar in the campaign evidence bundle and keep its `campaignId`, `inputId`, input hash, fuzz engine, harness/configuration hashes, execution, coverage, reproduction, bug review, and security review intact. Do not collapse these separate states into one `status` field.

When an authorized replay is eventually available, create the NWDAF input-case record from the same `input_id`, hash, corpus-relative path, component, input source, and pinned commit. Add the replay's own `TestOutcome` with its own run ID and time window; do not reuse the offline fuzz execution time as the network replay window. Add exactly one run label per NWDAF run and split complete runs, not individual events, between train and held-out partitions.

## Review and Promotion Gates

1. **Fuzz observation:** preserve the exact bytes, input hash, tool/configuration versions, resource limits, parser, engine, and raw output. Parser rejection is a normal outcome; a new edge is coverage evidence only.
2. **Reproduction:** minimize only in a copied, campaign-owned corpus. Replay deterministically against the pinned parser build with an explicit oracle. If the behavior cannot be reproduced, record that and stop promotion.
3. **Bug/security review:** a human decides whether reproduced behavior is a parser bug or expected leniency. A vulnerability claim additionally needs a human security review and evidence references; a crash or LLM explanation alone is insufficient.
4. **Network replay:** blocked until a separately reviewed adapter can deliver only the selected bounded NAS input to a private testbed, enforce synthetic identities and resource limits, record exact start/end timestamps, and reset state. Do not replay arbitrary AFL queue contents or fuzz a live/public core.
5. **NWDAF analysis:** compare labeled `input_test` and `normal` runs using telemetry that was actually observed. Keep missing SBI/PFCP sources unavailable rather than filling them with synthetic rows. Treat small or imbalanced campaigns as exploratory; detection of an input-test label is not vulnerability detection.
6. **Response:** no automatic mitigation follows from fuzz, replay, or classifier output. Any future response requires a separate authorization decision, bounded allow-listed action, audit record, and verified rollback.

## Campaign Layout Recommendation

Keep parser fuzz evidence and network replay evidence together under a new NWDAF input-testing campaign, without changing historical raw datasets:

```text
<campaign>/
  corpus/ordinary/<input_id>.bin
  corpus/llm/<input_id>.bin
  fuzz_provenance/<input_id>.json
  input_cases.jsonl
  outcomes.jsonl
  run_labels.jsonl
  runs/<run_id>/
  evaluation.json
  manifest.json
```

`outcomes.jsonl`, `runs/`, and `evaluation.json` are produced only for actual authorized replay/evaluation. Until the NAS replay adapter exists, the valid deliverable is the offline fuzz/provenance/reproduction review bundle; it must not be described as network-level telemetry evidence.

## Related Implementation

- This repository: `harness/nas_parser/`, `harness/nas_seed_compiler/`, `scripts/afl_seed_comparison.py`, and `data/raw/nas_seed_suite_20261002/seeds.json`.
- NWDAF repository: `schemas/fuzz-run.schema.json`, `src/nwdaf_research/input_testing/fuzz_provenance.py`, `src/nwdaf_research/input_testing/records.py`, and `docs/fuzz_to_nwdaf_stage1.md`.