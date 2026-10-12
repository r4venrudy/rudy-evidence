# Supported report subsets

Every adapter requires a request `scope`. Missing required identity fields, unknown severity and malformed selected fields reject the entire request. These are adapters for documented subsets, not full validators of every vendor schema. Extra unselected source fields are ignored after redaction.

| Format | Selected input | Limits / intentional omissions |
| --- | --- | --- |
| native | `findings` with producer, rule, title, severity, asset; optional scope/location/evidence/identifiers | Strict finding field names; exact identity deduplication |
| semgrep | `results`: check_id, path, start.line, extra.message, extra.severity, metadata.cwe | ERROR→high, WARNING→medium, INFO→info; no fixes or source snippets; scan errors are not completeness signals |
| nuclei | One object, array or NDJSON: template-id, matched-at, info.name/severity, optional matcher-name | Request/response bodies and extracted values are omitted |
| trivy | `Results[].Vulnerabilities`: target, vulnerability ID, package, installed/fixed versions, severity, title | Vulnerabilities only; no misconfiguration/secret/license import; UNKNOWN severity rejects |
| sarif | 2.1.0 runs/results: tool.driver.name, ruleId, message.text, level and one physical location | No artifact indexes/uriBaseId resolution, logical-only locations, multiple locations, suppressions or rule-default severity; unsupported identity forms reject |
| rudy-web-audit | Schema 1, target URL and warn/fail checks, severity, evidence and optional hop | Passing/info checks are omitted; scan errors do not become findings or establish completeness |
| rudy-sentinel | Alert array or NDJSON: rule, severity, process generation ID, sequence, MITRE ID, image, interpretation | Non-alert health records omitted; commands and raw event bodies omitted; host/session must be distinguished by scope |

SARIF level mappings: error→high, warning→medium, note/none→info. SARIF rule `security-severity` is not interpreted in this preview. Rudy's exporter preserves scope, exact severity, title, asset, location, evidence and identifiers through `rudy*` result properties. Importing that export preserves the canonical finding and fingerprint, but recalculates bundle source and redaction metadata. Physical file paths are URI-escaped; the exact original identity remains in properties.

Examples are synthetic fixtures, not vulnerability claims about real software. `CVE-2099-0001` in the Trivy fixture is a synthetic identifier.
