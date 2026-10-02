# Research Plan

## Phase 1: free5GC testbed

- Pin a free5GC tag or commit under `vendor/free5gc`.
- Capture Go, kernel, container, and host-network prerequisites.
- Keep all PLMN, SUPI, and SBI endpoints synthetic.
- Add a repeatable baseline health check before security experiments.

**Exit evidence:** pinned source revision, documented runtime versions, successful registration and SBI baseline traces in an isolated environment.

## Phase 2: NRF registration poisoning

Define the threat model before implementation. The experiment should use a synthetic rogue NRF registration or conflicting service-registration state, with an explicit oracle for expected NRF discovery behavior. Capture request identity, timestamps, service name, priority, endpoint, and response outcome. The harness must support reset to a known-good state and must never target an external network.

**Exit evidence:** a reproducible lab-only trace showing the poisoned state, affected discovery result, reset procedure, and root-cause analysis.

## Phase 3: AI anomaly/threat detector

Start with an interpretable baseline: schema validation, identity/endpoint allowlists, rate and freshness checks, and statistical deviation from normal registration behavior. Compare that baseline with a learned detector only after collecting labeled benign and attack traces. Preserve explanations and confidence with every detection.

**Exit evidence:** held-out evaluation with precision, recall, false-positive rate, and detection latency.

## Phase 4: Automated mitigation

Use policy-gated actions: quarantine a registration, revoke its discovery eligibility, restore the last known-good registry snapshot, and alert an operator. Every action must be idempotent, auditable, reversible, and bounded by a dry-run mode.

**Exit evidence:** mitigation reduces poisoned discovery without disrupting valid registrations, with measured rollback behavior.

## Phase 5: NTN/orbital data-center scenario

Add a scenario adapter rather than coupling orbital assumptions into the detector. Model variable RTT, link outages, delayed telemetry, service relocation, and regional/orbital authority changes. Keep the same event contract so terrestrial and NTN traces are comparable.

**Exit evidence:** detector and mitigation behavior under controlled delay, partition, and handover conditions.

## Phase 6: resilience evaluation

Report time to detect, time to mitigate, service availability, valid-registration disruption, false positives, recovery time, and behavior during telemetry loss. Evaluate multiple seeds and scenario severities, and publish raw traces plus configuration alongside aggregate results.

**Exit evidence:** reproducible evaluation report with limitations and explicit residual risks.
