# Contributing

Start with a reproducible issue, synthetic report and expected behavior. Preserve compatibility with the versioned identity/hash contract. Do not silently guess missing identity fields, downgrade unknown severity, truncate findings or label absence as remediation.

Run the CMake build, CTest, vendor hash verification, C#/Python binding checks and installed C/C++ consumers. Add a meaningful regression fixture for changed behavior. New adapters need a primary upstream schema reference, positive input and malformed/ambiguous identity cases. Avoid live secrets and private customer evidence.

Changes to vendored dependencies must retain license files, source version/commit and updated file hashes. Runtime network access, telemetry and mandatory cloud accounts do not belong in the core. Document unsupported cases and measured performance honestly.
