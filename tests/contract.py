"""Black-box contract tests against the compiled CLI and shared library. Stdlib only."""
import copy
import ctypes
import json
import pathlib
import random
import subprocess
import sys
import tempfile
import unittest

CLI, DLL = sys.argv[1:3]
sys.argv[1:] = []

def call(request, ok=True):
    raw = request if isinstance(request, str) else json.dumps(request, ensure_ascii=True)
    p = subprocess.run([CLI, "request"], input=raw.encode(), capture_output=True, timeout=30)
    if ok:
        if p.returncode:
            raise AssertionError(p.stderr.decode())
        return json.loads(p.stdout)
    if p.returncode != 1 or p.stdout:
        raise AssertionError(f"Invalid input accepted: exit={p.returncode}, stderr={p.stderr!r}")
    return p.stderr.decode()

def seed(**overrides):
    return dict(producer="example", rule_id="CONFIG.001", title="Review setting", severity="medium",
                asset={"kind": "file", "id": "src/main.cpp"}, location={"path": "src/main.cpp", "line": 9},
                evidence=["Observed value"], identifiers=["CWE-16"], **overrides)

def normal(rows=None, scope="repo:example", **kwargs):
    return call(dict(operation="normalize", format="native", scope=scope,
                     document={"findings": rows if rows is not None else [seed()]}, **kwargs))

class Contract(unittest.TestCase):
    def test_official_blake3_empty_and_abc(self):
        for text, expected in [("", "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262"),
                               ("abc", "6437b3ac38465133ffb63b75273a8db548c558465d79db03fd359c6cd5bd9d85")]:
            self.assertEqual(call(dict(operation="digest", text=text))["digest"], "blake3:" + expected)

    def test_all_adapters_and_cli_commands(self):
        root = pathlib.Path(__file__).parent.parent / "examples"
        formats = ["native", "semgrep", "nuclei", "trivy", "sarif", "rudy-web-audit", "rudy-sentinel"]
        for fmt in formats:
            with self.subTest(format=fmt):
                p = subprocess.run([CLI, "normalize", fmt, "fixture:one", str(root / (fmt + ".json"))], capture_output=True, timeout=30)
                self.assertEqual(p.returncode, 0, p.stderr)
                doc = json.loads(p.stdout)
                self.assertEqual(len(doc["findings"]), 1)
                self.assertTrue(call(dict(operation="validate", document=doc))["valid"])

    def test_scope_separates_hosts(self):
        a, b = normal(scope="host:one"), normal(scope="host:two")
        self.assertNotEqual(a["findings"][0]["fingerprint"], b["findings"][0]["fingerprint"])
        merged = call(dict(operation="merge", documents=[a, b]))
        self.assertEqual(merged["summary"]["findings"], 2)

    def test_empty_bundle_retains_scope(self):
        self.assertEqual(normal([], "repo:empty")["sources"][0]["scope"], "repo:empty")

    def test_fingerprint_ignores_triage_but_preserves_identity(self):
        initial = normal()["findings"][0]["fingerprint"]
        for key, value in [("title", "Updated title"), ("severity", "critical"), ("evidence", ["New evidence"]), ("identifiers", [])]:
            row = seed(); row[key] = value
            self.assertEqual(initial, normal([row])["findings"][0]["fingerprint"])
        for key, value in [("producer", "another"), ("rule_id", "OTHER"), ("asset", {"kind": "host", "id": "other"}), ("location", {"line": 10})]:
            row = seed(); row[key] = value
            self.assertNotEqual(initial, normal([row])["findings"][0]["fingerprint"])

    def test_exact_dedup_unions_and_highest_severity(self):
        a, b = seed(), seed(); b.update(title="Another title", severity="critical", evidence=["Other"])
        doc = normal([a, b]); f = doc["findings"][0]
        self.assertEqual(doc["summary"]["findings"], 1)
        self.assertEqual(f["severity"], "critical")
        self.assertEqual(f["evidence"], ["Observed value", "Other"])
        self.assertEqual(doc, normal([b, a]) | {"sources": doc["sources"], "integrity": doc["integrity"]})

    def test_128_duplicate_evidence_items(self):
        row = seed(); row["evidence"] = [str(n) for n in range(128)]
        self.assertEqual(len(normal([row, row])["findings"][0]["evidence"]), 128)

    def test_merge_commutes_and_is_idempotent(self):
        a = normal(); row = seed(); row.update(rule_id="OTHER", severity="high"); b = normal([row])
        self.assertEqual(call(dict(operation="merge", documents=[a, b])), call(dict(operation="merge", documents=[b, a])))
        self.assertEqual(call(dict(operation="merge", documents=[a, a])), a)

    def test_diff_categories_do_not_claim_fixed(self):
        a, changed, added = seed(), seed(), seed()
        changed.update(severity="critical"); added.update(rule_id="NEW")
        removed = seed(); removed["rule_id"] = "REMOVED"
        stable = seed(); stable["rule_id"] = "STABLE"
        d = call(dict(operation="diff", baseline=normal([a, removed, stable]), document=normal([changed, added, stable])))
        for key in ["added", "changed", "absent", "unchanged"]:
            self.assertEqual(len(d[key]), 1)
        self.assertNotIn("fixed", d); self.assertNotIn("resolved", d)

    def test_redaction_keys_tokens_and_idempotence(self):
        doc = {"nested": [{"Authorization": "Bearer synthetic-secret", "api_key": {"anything": "synthetic"}}],
               "text": "password=synthetic-one Bearer synthetic-two ghp_synthetic_three Basic synthetic-four https://user:synthetic-five@example.test/",
               "ordinary": "hello"}
        out = call(dict(operation="redact", document=doc))
        self.assertNotIn("synthetic", json.dumps(out))
        self.assertEqual(out["document"]["ordinary"], "hello")
        tokens = call(dict(operation="redact", document="glpat-synthetic1 xoxb-synthetic-2 sk_live_synthetic3 npm_synthetic4 snpm_kept"))
        self.assertEqual(tokens["document"], "[REDACTED] [REDACTED] [REDACTED] [REDACTED] snpm_kept")
        keys = call(dict(operation="redact", document={"X-Api-Key": "synthetic", "env": "AWS_SECRET_ACCESS_KEY=synthetic"}))
        self.assertEqual(keys["document"], {"X-Api-Key": "[REDACTED]", "env": "AWS_SECRET_ACCESS_KEY=[REDACTED]"})
        again = call(dict(operation="redact", document=out["document"]))
        self.assertEqual(again["replacements"], 0)
        self.assertEqual(again["document"], out["document"])

    def test_redaction_is_applied_to_normalized_output(self):
        row = seed(); row["evidence"] = ["token=synthetic_secret"]
        b = normal([row]); self.assertNotIn("synthetic_secret", json.dumps(b))
        self.assertTrue(call(dict(operation="validate", document=b))["valid"])

    def test_tamper_integrity(self):
        b = normal(); b["findings"][0]["severity"] = "critical"
        self.assertIn("integrity", call(dict(operation="validate", document=b), False))

    def test_forged_fingerprint(self):
        row = seed(); row["fingerprint"] = "blake3:" + "0" * 64
        call(dict(operation="normalize", format="native", scope="repo:test", document={"findings": [row]}), False)

    def test_roundtrip_sarif_keeps_finding_information(self):
        row = seed(); row["location"]["path"] = "folder with space/ü.cpp"; row["location"]["column"] = 4
        row["asset"]["id"] = row["location"]["path"]
        a = normal([row]); exported = call(dict(operation="sarif", document=a))
        b = call(dict(operation="normalize", format="sarif", scope="import:one", document=exported))
        self.assertEqual(a["findings"], b["findings"])
        self.assertIn("%20", exported["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"])

    def test_sarif_rejects_ambiguous_identity(self):
        fixture = json.loads((pathlib.Path(__file__).parent.parent / "examples/sarif.json").read_text())
        for variant in ["unlocated", "base", "index", "multiple", "suppressed"]:
            doc = copy.deepcopy(fixture); r = doc["runs"][0]["results"][0]
            if variant == "unlocated": del r["locations"]
            if variant in ["base", "index"]: r["locations"][0]["physicalLocation"]["artifactLocation"]["uriBaseId" if variant == "base" else "index"] = "ROOT" if variant == "base" else 0
            if variant == "multiple": r["locations"] *= 2
            if variant == "suppressed": r["suppressions"] = [{"kind": "inSource"}]
            call(dict(operation="normalize", format="sarif", scope="repo:test", document=doc), False)

    def test_ndjson_blank_lines_and_long_envelope(self):
        row = {"template-id": "test", "matched-at": "https://example.test", "info": {"name": "Fixture", "severity": "high"}}
        text = "\r\n" + "\n".join(json.dumps(row) for _ in range(700)) + "\n\n"
        self.assertGreater(len(text), 65536)
        b = call(dict(operation="normalize-lines", format="nuclei", scope="site:one", text=text))
        self.assertEqual(b["summary"]["findings"], 1)

    def test_invalid_ndjson_fails_whole_batch(self):
        call(dict(operation="normalize-lines", format="nuclei", scope="test", text='{}\n{"bad"'), False)
        row = {"template-id": "test", "matched-at": "https://example.test", "info": {"name": "Fixture", "severity": "high"}}
        call(dict(operation="normalize-lines", format="nuclei", scope="test", text=json.dumps(row) + '\x00ignored'), False)

    def test_sarif_identity_is_not_inferred_from_asset_spelling(self):
        for kind in ["file", "other"]:
            row = seed(); row["asset"] = {"kind": kind, "id": "unlocated"}; row.pop("location")
            bundle = normal([row]); exported = call(dict(operation="sarif", document=bundle))
            if kind == "file":
                self.assertEqual(exported["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"], "unlocated")
            back = call(dict(operation="normalize", format="sarif", scope="test", document=exported))
            self.assertEqual(bundle["findings"], back["findings"])

    def test_rejects_missing_scope(self):
        call(dict(operation="normalize", format="native", document={"findings": []}), False)

    def test_rejects_duplicate_keys_at_any_depth(self):
        for raw in ['{"operation":"digest","operation":"redact"}', '{"operation":"redact","document":{"a":[{"x":1,"x":2}]}}']:
            self.assertIn("Duplicate", call(raw, False))

    def test_invalid_json_types_and_utf8(self):
        for raw in ["", "{", "[]", "null", '{"operation":5}', '{"operation":"redact","document":NaN}', '{"operation":"digest","text":"abc"}\u0000']:
            call(raw, False)
        p = subprocess.run([CLI, "request"], input=b'{"operation":"redact","document":"\xff"}', capture_output=True, timeout=30)
        self.assertEqual(p.returncode, 1)

    def test_depth_limit(self):
        call('{"operation":"redact","document":' + "[" * 40 + "0" + "]" * 40 + "}", False)

    def test_input_size_limit(self):
        call(" " * (16 * 1024 * 1024 + 1), False)

    def test_key_size_limit(self):
        call(dict(operation="redact", document={"a" * 257: 1}), False)

    def test_finding_limits_and_unknown_fields(self):
        for key, value in [("severity", "UNKNOWN"), ("asset", {"kind": "file"}), ("location", {"line": -1}),
                           ("location", {"line": 0}), ("location", {"column": True}), ("unknown", 1), ("title", "x" * 65537)]:
            row = seed(); row[key] = value
            call(dict(operation="normalize", format="native", scope="test", document={"findings": [row]}), False)
        call(dict(operation="normalize", format="native", scope="test", document={"findings": [seed()] * 10001}), False)

    def test_malformed_adapter_shapes(self):
        for fmt in ["semgrep", "trivy", "rudy-web-audit", "rudy-sentinel", "sarif", "native", "unrecognized"]:
            call(dict(operation="normalize", format=fmt, scope="test", document={"results": {}}), False)

    def test_diagnostics_do_not_echo_secret_input(self):
        error = call('{"operation":"redact","document":"synthetic_PRIVATE_secret', False)
        self.assertNotIn("synthetic_PRIVATE_secret", error)

    def test_seeded_input_mutations_never_crash(self):
        rng = random.Random(1974)
        raw = json.dumps(dict(operation="normalize", format="native", scope="test", document={"findings": [seed()]})).encode()
        for _ in range(100):
            mutated = bytearray(raw)
            for _ in range(rng.randint(1, 5)):
                mutated[rng.randrange(len(mutated))] = rng.randrange(256)
            p = subprocess.run([CLI, "request"], input=mutated, capture_output=True, timeout=30)
            self.assertIn(p.returncode, [0, 1])

    def test_c_abi_utf8_and_error_ownership(self):
        class Buffer(ctypes.Structure):
            _fields_ = [("data", ctypes.c_void_p), ("size", ctypes.c_size_t)]
        lib = ctypes.CDLL(DLL)
        lib.re_process.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.POINTER(Buffer), ctypes.POINTER(Buffer)]
        lib.re_process.restype = ctypes.c_int
        lib.re_free.argtypes = [ctypes.POINTER(Buffer)]
        raw = json.dumps(dict(operation="redact", document="Türkçe 日本語"), ensure_ascii=False).encode()
        result, error = Buffer(), Buffer()
        status = lib.re_process(raw, len(raw), ctypes.byref(result), ctypes.byref(error))
        try:
            self.assertEqual(status, 0)
            self.assertEqual(json.loads(ctypes.string_at(result.data, result.size))["document"], "Türkçe 日本語")
        finally:
            lib.re_free(ctypes.byref(result)); lib.re_free(ctypes.byref(error))
        self.assertFalse(result.data); self.assertEqual(result.size, 0)

    def test_cli_usage_and_missing_file(self):
        for args, code in [(["nonsense"], 2), (["validate", "missing-report.json"], 1), (["--version"], 0), (["--help"], 0)]:
            p = subprocess.run([CLI, *args], capture_output=True, timeout=30)
            self.assertEqual(p.returncode, code, p.stderr)

    def test_cli_reads_standard_input_once(self):
        bundle = json.dumps(normal()).encode()
        for args in (["merge", "-", "-"], ["diff", "-", "-"]):
            p = subprocess.run([CLI, *args], input=bundle, capture_output=True, timeout=30)
            self.assertEqual((p.returncode, p.stdout), (1, b""), args)
            self.assertIn(b"standard input", p.stderr)

    def test_unicode_file_paths_and_scope(self):
        with tempfile.TemporaryDirectory() as temp:
            path = pathlib.Path(temp) / "Türkçe-日本語.json"
            path.write_text(json.dumps({"findings": [seed()]}), encoding="utf-8")
            p = subprocess.run([CLI, "normalize", "native", "repo:Türkçe-日本語", str(path)], capture_output=True, timeout=30)
            self.assertEqual(p.returncode, 0, p.stderr)
            self.assertEqual(json.loads(p.stdout)["findings"][0]["scope"], "repo:Türkçe-日本語")

if __name__ == "__main__":
    unittest.main(verbosity=2)
