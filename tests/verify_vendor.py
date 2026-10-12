import hashlib
import json
from pathlib import Path
root = Path(__file__).parent.parent
manifest = json.loads((root / "vendor/manifest.json").read_text())
actual = {p.relative_to(root).as_posix(): hashlib.sha256(p.read_bytes()).hexdigest()
          for p in (root / "vendor").rglob("*") if p.is_file() and p.name != "manifest.json"}
if actual != manifest:
    raise SystemExit("Vendored file/hash set differs from the pinned manifest")
print(f"Verified {len(actual)} vendored files")
