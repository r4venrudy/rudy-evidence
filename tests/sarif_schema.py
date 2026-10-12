"""Development-only interoperability check against a pinned official OASIS schema."""
import hashlib
import json
from pathlib import Path
import subprocess
import sys
from urllib.request import urlopen
import jsonschema

url = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/25eb7663ad3ac54338b4f6a00a7004995e32e6da/sarif-2.1/schema/sarif-schema-2.1.0.json"
with urlopen(url, timeout=30) as response:
    schema_bytes = response.read(200_000)
validator = jsonschema.Draft4Validator(json.loads(schema_bytes), format_checker=jsonschema.FormatChecker())
root = Path(__file__).parent.parent
for name in ["native", "semgrep", "nuclei", "trivy", "sarif", "rudy-web-audit", "rudy-sentinel"]:
    bundle = subprocess.check_output([sys.argv[1], "normalize", name, "fixture", str(root / "examples" / (name + ".json"))], timeout=30)
    exported = subprocess.check_output([sys.argv[1], "sarif"], input=bundle, timeout=30)
    validator.validate(json.loads(exported))
print("Seven adapter exports validated against pinned OASIS SARIF 2.1.0, including URI format checks.")
print("Schema SHA256:", hashlib.sha256(schema_bytes).hexdigest())
