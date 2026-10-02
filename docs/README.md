# Documentation Index

## Implemented NAS Fuzzing Workflow

- [AFL++ Go NAS parser guide](afl_go_parser.md): Go parser adapter, AFL++ QEMU requirements, and basic run setup.
- [Multi-model seed study](afl_multimodel_study.md): paired comparison design, seed preparation, Slurm execution, and interpretation caveats.
- [Fuzz-to-NWDAF evidence handoff](fuzz_to_nwdaf_handoff.md): record linkage, review gates, and the missing live NAS replay adapter boundary.
- Curated seed input: [`data/raw/nas_seed_suite_20261002/seeds.json`](../data/raw/nas_seed_suite_20261002/seeds.json).

## Project Scope and Roadmap

- [Architecture and implementation status](ARCHITECTURE.md): implemented parser-fuzzing components and unimplemented architecture concepts.
- [Research plan](RESEARCH_PLAN.md): proposed NRF, detection, mitigation, NTN, and resilience work with exit evidence.

## Paper and Reproducibility

The current experimental evidence in this checkout concerns NAS parser seed generation and AFL++ fuzzing. Do not present the future phases in the research plan as implemented or evaluated results. Keep experiment run directories, seeds, toolchain versions, and reports linked to the exact campaign manifest when making a claim. Verify redistribution rights for any generated artifact before publishing it.

The project does not yet include a `LICENSE` or `CITATION.cff`; choose and confirm these before making the repository public. The upstream checkout created under `vendor/free5gc` is ignored and should be treated as a separate dependency with its own license and patch attribution requirements.

Use the [README publication checklist](../README.md#before-public-release) before pushing a public release or citing a result from a campaign directory.