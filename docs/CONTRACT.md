# Evidence contract v1

All APIs take one UTF-8 JSON request and return one JSON response. `process` performs no I/O. C++ errors throw `rudy::evidence::Error`; the C API returns a status with library-owned output/error buffers. Invalid field diagnostics do not echo input values. Caller-supplied C pointers and byte lengths must be valid for reading/writing.

## Operations

| operation | Required fields | Response |
| --- | --- | --- |
| normalize | `format`, `scope`, `document` | Canonical bundle |
| normalize-lines | `format`, `scope`, `text` | Canonical bundle; Nuclei or Sentinel NDJSON |
| validate | `document` | `valid`, finding count, bundle digest; rejects invalid input |
| merge | `documents` (1–128 bundles) | Canonical bundle |
| diff | `baseline`, `document` | Added/absent/changed arrays, unchanged fingerprints, both digests |
| sarif | `document` | SARIF 2.1.0 subset |
| redact | `document` | Sanitized document, replacement count and policy |
| digest | `text` (up to 64 KiB) | BLAKE3-256 of UTF-8 text, prefixed `blake3:` |

Native normalization input is `{ "findings": [...] }`. Each finding requires `producer`, `rule_id`, `title`, `severity` and `asset`. It inherits request `scope` unless it explicitly supplies one. `asset` contains exactly `kind` and `id`; kinds are `url`, `host`, `file`, `package`, `process`, `other`. Optional fields: `location` (path, positive 32-bit line/column), `evidence`, `identifiers`, `fingerprint`. Unknown finding fields are rejected. Severity: info, low, medium, high, critical. Case is normalized; unknown severities fail the whole request.

Evidence/identifier lists become sorted unique strings. Canonical fields are always present. Findings are sorted by fingerprint. Identity is the BLAKE3-256 hash of the compact JSON array:

```text
["rudy-finding/v1", scope, producer, rule_id, asset, location]
```

No Unicode normalization, URL canonicalization, path case folding or cross-scanner identity inference occurs. Redaction precedes identity calculation. Distinct secrets that redact to the same asset ID can therefore collapse; choose non-secret stable asset identifiers. Producer/rule IDs should be stable across versions. Scopes are user-controlled namespaces, not trust assertions.

The bundle contains exactly `schema`, `findings`, `sources`, `summary`, `redaction`, `integrity`. Schema is `rudy-evidence/v1`. Sources have format, scope and digest; they are sorted and deduplicated. Summary includes total and severity counts. Integrity is `{"algorithm":"blake3-256","digest":"blake3:..."}`.

**Canonical encoding is specific to v1**: nlohmann/json 3.12.0 `dump()` with default compact UTF-8 encoding and lexicographically sorted object keys. Canonical fields contain strings, nonnegative integers, arrays and objects. Do not substitute RFC 8785/JCS or a language's arbitrary JSON serialization. The integrity digest hashes the canonical bundle without its `integrity` field. Validation reconstructs all canonical fields, fingerprints and summary, checks redaction consistency and rejects tampering or unknown bundle fields.

For JSON adapters, the source digest hashes the parsed source's compact default JSON encoding **before redaction**, not the file's original bytes. For NDJSON, it hashes the exact supplied UTF-8 text. Source digests are opaque correlation hints; they can reveal equality or enable guessing low-entropy source content. They cannot recover or authenticate the original file.

Merge selects the highest severity for exact identities, lexicographically smallest title, and union of evidence/identifiers. Identical input bundles are counted once. Replacement counts sum across distinct input bundle digests; they count redaction operations, not unique secrets. Merge is deterministic and commutative, and merging an identical bundle with itself is idempotent. The library rejects limit overflow rather than truncating findings.

Diff compares fingerprints and full canonical finding contents. Missing findings are **absent**. They may reflect incomplete scanning, scope changes or suppressed output. Diff makes no assertion about scan completeness, remediation or exploitability.

## Limits

Requests and responses: 16 MiB each, including the request envelope. JSON depth: 32. Parser events: 500,000. Keys: 256 bytes. Canonical finding fields/list items: 64 KiB per string. Findings: 10,000 input records per normalization or across distinct merged bundles, before deduplication. Evidence and identifiers: 128 unique entries each (up to 256 supplied entries to permit merging). Sources: 128. NDJSON: 10,000 nonblank records. Exceeding any applicable limit rejects the whole operation.

These are resource bounds, not a hard wall-clock/memory guarantee. Applications handling hostile uploads should additionally isolate the process and enforce their own deadlines and memory quotas. The API does not retain input after a call, but does not securely erase allocator memory.

## Builtin redaction v1

Case-insensitive exact keys: password, passwd, secret, client_secret, api_key, apikey, token, access_token, refresh_token, authorization, proxy-authorization, cookie, set-cookie, private_key. Non-null values are replaced wholesale.

Text patterns: Bearer/Basic credentials separated by a space; GitHub token prefixes ghp_, gho_, ghu_, ghs_, ghr_, github_pat_; password/passwd/secret/api_key/apikey/token/access_token/client_secret followed by `=` or `:`; URL userinfo before `@`. Whitespace and common punctuation terminate recognized text values. Matches become `[REDACTED]`; repeated processing is idempotent for these markers.

This is deliberately a limited pattern policy. It does not recognize every token, PEM block, custom header, encoded payload, address, personal identifier or arbitrary credential. It can produce false positives. Raw scanner fields are not copied unless explicitly selected by an adapter. Inspect output before sharing.
