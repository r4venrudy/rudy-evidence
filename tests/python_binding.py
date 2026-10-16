import json
import os
import sys
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent / "bindings/python"))
from rudy_evidence import Evidence, EvidenceError

evidence = Evidence()
def check(_):
    out = evidence.process(dict(operation="redact", document={"text": "Türkçe 日本語", "password": "synthetic"}))
    assert out["document"] == {"text": "Türkçe 日本語", "password": "[REDACTED]"}
with ThreadPoolExecutor(max_workers=8) as pool:
    list(pool.map(check, range(1000)))
finding = dict(producer="example", rule_id="CONFIG.001", title="Review setting", severity="medium",
               asset={"kind": "file", "id": "src/main.cpp"}, evidence=["Observed value"])
bundle = evidence.normalize("native", "repo:example", {"findings": [finding]})
assert evidence.validate(bundle) == evidence.process(dict(operation="validate", document=bundle))
assert evidence.merge(bundle, bundle) == bundle
assert evidence.diff(bundle, bundle) == evidence.process(dict(operation="diff", baseline=bundle, document=bundle))
assert evidence.sarif(bundle)["version"] == "2.1.0"
assert evidence.redact({"token": "synthetic"})["document"] == {"token": "[REDACTED]"}
nuclei = json.loads((Path(__file__).parent.parent / "examples/nuclei.json").read_text(encoding="utf-8"))
rows = nuclei if isinstance(nuclei, list) else [nuclei]
lines = evidence.normalize_lines("nuclei", "web:example", "\n".join(json.dumps(row) for row in rows))
assert lines["findings"] == evidence.normalize("nuclei", "web:example", rows)["findings"]
try:
    evidence.process({"operation": "unknown"})
    raise AssertionError("Invalid operation accepted")
except EvidenceError:
    pass
print("Python binding: 1,000 concurrent Unicode/redaction calls and error handling passed.")
