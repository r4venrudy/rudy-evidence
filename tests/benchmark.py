"""Repeatable synthetic benchmark. Includes process startup and pipe I/O."""
import json
import statistics
import subprocess
import sys
import time
rows = [{"producer": "benchmark", "rule_id": "CONFIG.001", "title": "Synthetic finding", "severity": "medium",
         "asset": {"kind": "file", "id": f"src/{i}.cpp"}} for i in range(10000)]
raw = json.dumps(dict(operation="normalize", format="native", scope="benchmark:synthetic", document={"findings": rows})).encode()
times = []
for _ in range(5):
    start = time.perf_counter()
    result = subprocess.run([sys.argv[1], "request"], input=raw, capture_output=True, timeout=60, check=True)
    times.append(time.perf_counter() - start)
    assert len(json.loads(result.stdout)["findings"]) == 10000
print(json.dumps(dict(records=10000, runs=5, input_bytes=len(raw), elapsed_seconds=times, median_seconds=statistics.median(times)), indent=2))
