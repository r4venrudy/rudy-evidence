# Third party code

Vendored, unchanged upstream files allow offline builds. Hashes are in `vendor/manifest.json`.

- nlohmann/json 3.12.0: `vendor/nlohmann/json.hpp`, MIT. Source: https://github.com/nlohmann/json/releases/tag/v3.12.0
- Official BLAKE3 C implementation 1.8.2, commit `df610ddc3b93841ffc59a87e3da659a15910eb46`: `vendor/blake3`. Licensed under Apache 2.0 or CC0; all upstream license files are retained. Source: https://github.com/BLAKE3-team/BLAKE3/tree/1.8.2/c

This release selects the portable C implementation; SIMD acceleration is disabled.
