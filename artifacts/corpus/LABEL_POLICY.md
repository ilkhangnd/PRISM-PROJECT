# Phase 0 label policy - NSS 2026

## Decision

The submission experiment will use **contract-derived weak labels** for its
function graphs. It will not describe the current labels as function-level
ground truth.

The strictly source-span-mapped SolidiFI subset is not suitable for the
five-class experiment: it contains 2,580 retained graphs, with only two
Reentrancy and two Front-running examples. Those counts come from
`artifacts/nss2026/solidifi_span_audit.json` and are retained as an audit, not
as the training corpus.

## Consequences for the final paper

- Describe the labels as contract-derived weak supervision.
- State the label source by dataset: SmartBugs contract mapping; SolidiFI
  contract mapping with available BugLog injection spans; LISA finding-text
  keyword mapping.
- Do not claim localization accuracy or that every function graph contains the
  labeled vulnerability.
- Report the source-span audit as a limitation: unmatched spans and unrelated
  functions can introduce label noise.
- Use the frozen random and lineage-disjoint splits produced from the corpus
  manifest. Do not reuse historical split files as the experimental protocol.

## Deduplication policy

Structural hashes of the 32-dimensional graph features are kept for audit only.
They create false clone candidates because different source functions can have
the same coarse graph representation and even different labels. A sample is
unique by its source dataset, source contract, and function graph record. The
lineage-disjoint split prevents SolidiFI variants sharing a `buggy_N` origin,
LISA functions from the same finding entry, and functions from the same
imported source contract from crossing partitions.
