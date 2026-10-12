# Architecture

`re_core` contains request validation, report adapters, redaction, canonicalization, fingerprints, merge/diff and export. Its public C++ header has no JSON dependency. The implementation uses pinned, vendored nlohmann/json and official portable BLAKE3 C sources.

`re_capi` owns all memory allocated for C responses. The C ABI carries only pointers, byte lengths and status codes; exceptions are contained within the library. C# and Python bindings copy results and free both buffers in `finally` blocks. Calls have no mutable shared engine state.

`rudy-evidence` is a narrow filesystem/stdin reader around the same core. It constructs request envelopes without reparsing source JSON, so duplicate source keys are rejected by the core rather than silently overwritten by a convenience parser. It does not write output files, launch programs or access the network.

The processing order is bounded parsing → source digest → source redaction → adapter extraction → output redaction → canonical finding validation → deduplication → summary → integrity digest. Validation rebuilds the bundle rather than trusting supplied fingerprints or counts. Baseline comparison is offline and does not change any finding status.

Consumers should separate trusted SDK deployment from untrusted uploaded reports. In a service, use a fixed SDK binary/library selected by the operator, bound request size, isolate parsing if necessary, enforce timeouts externally and keep project/host namespaces stable. Never accept a library path or arbitrary executable path from a report.
