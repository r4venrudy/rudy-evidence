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
try:
    evidence.process({"operation": "unknown"})
    raise AssertionError("Invalid operation accepted")
except EvidenceError:
    pass
print("Python binding: 1,000 concurrent Unicode/redaction calls and error handling passed.")
