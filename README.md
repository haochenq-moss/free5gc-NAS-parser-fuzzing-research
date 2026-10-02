# free5GC Security Lab

This repository contains defensive research tooling for isolated free5GC experiments. The current implemented workflow centers on the free5GC 5G NAS (GMM/GSM) parser: curated seeds, a bounded Go file-input harness, structured seed generation, AFL++ QEMU comparisons, and coverage-feedback experiments.

The broader NRF registration-poisoning, AI detection, automated mitigation, and NTN topics remain a research plan. They are not claims of implemented functionality or evaluated results in this repository today. See the [implementation status and research boundaries](docs/ARCHITECTURE.md) and [research plan](docs/RESEARCH_PLAN.md).

## Start Here

- [Documentation index](docs/README.md): guides grouped by purpose.
- [AFL++ Go NAS parser guide](docs/afl_go_parser.md): target behavior and QEMU setup.
- [Multi-model seed study](docs/afl_multimodel_study.md): paired design, commands, and interpretation limits.
- [Architecture and implementation status](docs/ARCHITECTURE.md): what exists versus what is planned.
- [Research plan](docs/RESEARCH_PLAN.md): proposed future phases and exit evidence.
- [Curated NAS seed suite](data/raw/nas_seed_suite_20261002/seeds.json): 16 GMM/GSM seed records and categories.

## Local Setup

The Python package supports Python 3.9 and later. Install the local package and run its offline checks:

```bash
python3 -m venv .venv
. .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -e .
python -m free5gc_security_lab doctor
python -m unittest discover -s tests -v
```

To bootstrap a separate upstream free5GC checkout, pin an explicit tag or commit:

```bash
python -m free5gc_security_lab bootstrap --ref <free5gc-tag-or-commit>
```

Bootstrap refuses to overwrite `vendor/free5gc`. Review upstream setup scripts before running them: they may require elevated privileges, host networking changes, or internet access. The wrapper at `vendor/quick-setup.sh` runs the upstream setup from the expected checkout directory.

The NAS parser fuzzing experiments need additional tools: Go and the matching free5GC Go module, AFL++ built with QEMU mode, and (for LLM seed generation) a local Ollama server with the selected models. Full matrices should run on the configured Slurm cluster rather than a shared login node; the experiment guide describes the commands and output layout.

## Repository Map

| Path | Contents |
| --- | --- |
| `src/free5gc_security_lab/` | Small Python CLI for prerequisite checks and pinned checkout bootstrap |
| `harness/nas_parser/` | File-input Go adapter invoking free5GC `ParseGMM` or `ParseGSM` |
| `harness/nas_seed_compiler/` | Structured NAS seed builder, dissector, and targeted IE mutation helper |
| `scripts/` | Seed export/validation, AFL++ campaign orchestration, and Slurm wrapper |
| `data/raw/` | Curated synthetic NAS seed specifications |
| `data/results/` | Local experiment outputs; ignored by Git by default |
| `configs/` | Lab configuration and explicit safety settings |
| `patches/` | Reproducible patch for the upstream Go fuzz target |
| `docs/` | Implementation scope, experiment methods, setup, and limitations |
| `tests/` | Python unit and offline workflow tests |
| `vendor/free5gc/` | Local upstream checkout created by bootstrap; ignored by Git |

## Safety and Research Boundaries

Use only a private, isolated lab and synthetic subscriber/network identifiers. The Go NAS fuzz harness reads a file capped at 4096 bytes and invokes a parser; it does not start a core network or send traffic. Do not connect test stimuli to production cores, public networks, or real subscribers.

Fuzzing campaigns, generated model seeds, binaries, and run outputs are local research artifacts. `data/results/` and the upstream checkout are ignored by default and are not automatically included in a publication or GitHub release. Preserve campaign manifests, seeds, tool versions, and reports separately when documenting a result. Crash reporting may be limited by the cluster core-dump handler; a zero-crash run is not evidence that the parser is defect-free.

## Before Public Release

- Choose and add a project license. No `LICENSE` is present, so public visibility alone does not grant reuse permission.
- Add citation metadata (`CITATION.cff`) and an archival release DOI when one is available.
- Verify that the upstream free5GC revision, vendored setup wrapper, patches, seeds, and generated artifacts may be redistributed under their respective terms.
- Decide which campaign manifests, corpora, coverage results, crash artifacts, and logs are part of the paper's evidence package. They are ignored by Git and will not appear in a normal clone.
- Pin toolchain and dependency versions, and verify every quantitative paper claim against a preserved run manifest and raw result artifact.
- Re-run the offline tests from a clean environment; keep live, Slurm, and privileged workflows separate from routine CI.