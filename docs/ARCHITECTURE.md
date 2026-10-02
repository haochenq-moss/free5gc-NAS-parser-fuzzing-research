# Architecture and Current Scope

## Implemented in This Repository

The current executable implementation is a research harness around the free5GC Go NAS parser, plus a small Python prerequisite/bootstrap CLI:

- `harness/nas_parser/main.go` reads a file of at most 4096 bytes and invokes `message.ParseGMM` or `message.ParseGSM`.
- `harness/nas_seed_compiler/main.go` builds structured Registration Request and PDU Session Establishment Request seeds with the free5GC NAS package, dissects parse outcomes, and supports targeted IE replacement.
- `scripts/afl_seed_comparison.py` prepares ordinary and LLM-derived seed corpora, runs matched AFL++ QEMU campaigns, records repeatability/coverage data, generates coverage-gap variants, and validates candidate coverage before merge.
- `scripts/export_nas_seed_corpus.py` validates and exports the curated seed specifications into separate GMM/GSM corpora.
- `src/free5gc_security_lab/` checks local prerequisites and bootstraps an explicitly pinned upstream free5GC checkout.

The Go harness is a parser-only target. It does not instantiate free5GC network functions, send SBI traffic, implement a detector, or apply mitigations.

## Conceptual Target Architecture

The diagram below describes a possible future research system, not the current implementation:

```text
free5GC (isolated lab)
        |
        v
SBI event adapter --> normalized event log --> detector --> policy engine --> mitigation adapter
        |                                      |             |
        +---------- baseline/replay -----------+             +--> audit log

scenario adapter: terrestrial | NTN/orbital data center
```

The proposed project architecture is organized around stable event contracts:

- **Observation**: an SBI or NRF event with source, target, operation, service identity, endpoint, timestamp, and correlation ID.
- **Detection**: a finding with rule/model ID, score, explanation, and evidence references.
- **Mitigation**: an idempotent action with policy decision, target, result, and rollback reference.

NRF registration poisoning, SBI event adapters, detection, policy enforcement, mitigation, rollback, and terrestrial/NTN comparison remain planned work. The phase-specific exit evidence is in [RESEARCH_PLAN.md](RESEARCH_PLAN.md). Do not treat the conceptual diagram or the plan as evidence that these capabilities currently exist.
