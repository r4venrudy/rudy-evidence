"""Check the packaged CLI, read-only input mounts and stdin processing offline."""
import json
from pathlib import Path
import subprocess
import sys
import tempfile

image = sys.argv[1]
base = ["docker", "run", "--rm", "--network", "none", "--read-only", "--cap-drop", "ALL",
        "--security-opt", "no-new-privileges", "--pids-limit", "64"]

def run(args, *, data=None, mount=None, expected=0):
    cmd = base + (["-i"] if data is not None else [])
    if mount:
        cmd += ["--mount", f"type=bind,source={mount},target=/input,readonly"]
    result = subprocess.run(cmd + [image] + args, input=data, text=True,
                            capture_output=True, timeout=60)
    assert result.returncode == expected, result.stderr
    return result.stdout

with tempfile.TemporaryDirectory() as tmp:
    root = Path(tmp)
    root.chmod(0o755)
    source = Path(__file__).resolve().parents[1] / "examples" / "native.json"
    (root / "input.json").write_bytes(source.read_bytes())
    (root / "input.json").chmod(0o644)
    raw = run(["normalize", "native", "package:test", "/input/input.json"], mount=root)
    bundle = json.loads(raw)
    assert len(bundle["findings"]) == 1
    assert bundle["findings"][0]["rule_id"] == "CONFIG.001"
    assert json.loads(run(["validate", "-"], data=raw))["valid"] is True
    sarif = json.loads(run(["sarif", "-"], data=raw))
    assert sarif["version"] == "2.1.0" and len(sarif["runs"][0]["results"]) == 1
    assert run(["normalize", "native", "package:test", "-"], data="{broken", expected=1) == ""
    assert json.loads(run([]))["findings"], "Default command did not load packaged example"
print("Installed container passed normalization, validation, SARIF, stdin and invalid-input checks.")
