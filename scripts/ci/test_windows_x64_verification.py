"""Asset-free behavioral checks for the verification helpers (synthetic inputs)."""
import importlib.util
import json
from pathlib import Path
import subprocess
import shutil
import tempfile
import unittest

spec = importlib.util.spec_from_file_location("verification", Path(__file__).with_name("windows_x64_verification.py"))
v = importlib.util.module_from_spec(spec)


class VerificationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        spec.loader.exec_module(v)

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)

    def compile(self, name, source, *flags):
        c = self.root / (name + ".c")
        c.write_text(source)
        out = self.root / name
        subprocess.run(["x86_64-w64-mingw32-gcc", str(c), "-o", str(out), *flags], check=True,
                       capture_output=True)
        return out

    def test_real_pe_and_case_insensitive_transitive_closure(self):
        dll = self.compile("Example.DLL", "__declspec(dllexport) int answer(void) {return 42;}",
                           "-shared", "-Wl,--out-implib," + str(self.root / "libexample.a"))
        exe = self.compile("example.exe", "__declspec(dllimport) int answer(void); int main(void) {return answer()!=42;}",
                           "-L" + str(self.root), "-lexample")
        stage, records = self.root / "stage", self.root / "records"
        stage.mkdir()
        records.mkdir()
        v.stage_pe([exe], [self.root], stage, records)
        self.assertEqual(sorted(p.name for p in stage.iterdir()), ["Example.DLL", "example.exe"])
        receipt = json.loads((records / "PE.json").read_text())
        self.assertEqual(receipt["example.exe"]["machine"], "0x8664")
        self.assertIn("example.dll", [s.lower() for s in receipt["example.exe"]["imports"]])
        self.assertTrue(any(s.lower() == "kernel32.dll" for s in receipt["Example.DLL"]["imports"]))
        dll.unlink()
        stage2 = self.root / "missing"
        stage2.mkdir()
        with self.assertRaisesRegex(RuntimeError, "Missing non-system dependency"):
            v.stage_pe([exe], [], stage2, records)

    def test_bad_architecture_and_missing_inspector_fail(self):
        # Header-only synthetic PE, never executed. Test the independent header gate.
        data = bytearray(160)
        data[:2] = b"MZ"
        data[60:64] = (64).to_bytes(4, "little")
        data[64:68] = b"PE\0\0"
        data[68:70] = (0x14c).to_bytes(2, "little")
        data[88:90] = (0x10b).to_bytes(2, "little")
        path = self.root / "synthetic-x86.exe"
        path.write_bytes(data)
        with self.assertRaisesRegex(RuntimeError, "AMD64/PE32"):
            v.pe_header(path)
        path.write_bytes(b"MZ")
        with self.assertRaisesRegex(RuntimeError, "Truncated"):
            v.pe_header(path)
        with self.assertRaises(FileNotFoundError):
            v.run([str(self.root / "absent-objdump"), "-p", str(path)])

    def test_system_allowlist_and_missing_license(self):
        self.assertTrue(v.system_dll("KERNEL32.DLL"))
        self.assertTrue(v.system_dll("api-ms-win-core-file-l1-1-0.dll"))
        self.assertFalse(v.system_dll("unknown-runtime.dll"))
        self.assertFalse(v.system_dll("libstdc++-6.dll"))
        records = self.root / "records"
        records.mkdir()
        license = self.root / "LICENSE"
        license.write_text("Synthetic license fixture\n")
        receipt = v.copy_licenses(self.root, records, ["LICENSE"])
        self.assertEqual(receipt["LICENSE"], v.sha256(license))
        self.assertEqual((records / "licenses/LICENSE").read_text(), "Synthetic license fixture\n")
        with self.assertRaises(FileNotFoundError):
            v.copy_licenses(self.root, records, ["missing-LICENSE"])
        license.write_text("")
        with self.assertRaisesRegex(RuntimeError, "Empty license"):
            v.copy_licenses(self.root, records, ["LICENSE"])

    def test_recursive_submodule_receipts_and_commit_mismatch(self):
        child = self.root / "dependency"
        child.mkdir()
        parent = self.root / "parent"
        parent.mkdir()
        for path in (child, parent):
            v.run(["git", "init", "-q", str(path)])
            v.run(["git", "-C", str(path), "config", "user.name", "Synthetic Fixture"])
            v.run(["git", "-C", str(path), "config", "user.email", "fixture@example.invalid"])
            (path / "source.txt").write_text("Synthetic source fixture\n")
            v.run(["git", "-C", str(path), "add", "."])
            v.run(["git", "-C", str(path), "commit", "-qm", "synthetic fixture"])
        v.run(["git", "-c", "protocol.file.allow=always", "-C", str(parent),
               "submodule", "add", "-q", str(child), "lib/dependency"])
        v.run(["git", "-C", str(parent), "commit", "-qam", "synthetic submodule"])
        receipt = v.source_receipt(parent, pristine=True)
        self.assertEqual(receipt["submodules"][0]["path"], "lib/dependency")
        self.assertEqual(receipt["submodules"][0]["expected_commit"],
                         v.run(["git", "-C", str(child), "rev-parse", "HEAD"]).strip())
        dependency = parent / "lib/dependency"
        (dependency / "source.txt").write_text("Synthetic build patch\n")
        with self.assertRaisesRegex(RuntimeError, "not pristine"):
            v.source_receipt(parent, pristine=True)
        patched = v.source_receipt(parent, pristine=False)
        self.assertIn("Synthetic build patch", patched["submodules"][0]["diff"])
        v.run(["git", "-C", str(dependency), "-c", "user.name=Synthetic Fixture",
               "-c", "user.email=fixture@example.invalid", "commit", "-qam", "drift fixture"])
        with self.assertRaisesRegex(RuntimeError, "Submodule commit mismatch"):
            v.source_receipt(parent, pristine=False)
        v.run(["git", "-C", str(parent), "add", "lib/dependency"])
        with self.assertRaisesRegex(RuntimeError, "Submodule commit mismatch"):
            v.source_receipt(parent, pristine=False)
        v.run(["git", "-C", str(parent), "reset", "--", "lib/dependency"])
        v.run(["git", "-C", str(dependency), "checkout", "HEAD^"])
        shutil.rmtree(dependency)
        with self.assertRaisesRegex(RuntimeError, "Uninitialized submodule"):
            v.source_receipt(parent, pristine=False)

    def test_hash_verification_detects_changed_file(self):
        path = self.root / "record.txt"
        path.write_text("abc")
        manifest = {"record.txt": "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"}
        self.assertEqual(v.sha256(path), manifest["record.txt"])
        v.verify_hashes(self.root, manifest)
        path.write_text("changed\n")
        with self.assertRaisesRegex(RuntimeError, "Hash mismatch"):
            v.verify_hashes(self.root, manifest)

    def test_source_receipts_and_dirty_source_gate(self):
        v.run(["git", "init", "-q", str(self.root)])
        v.run(["git", "-C", str(self.root), "config", "user.name", "Synthetic Fixture"])
        v.run(["git", "-C", str(self.root), "config", "user.email", "fixture@example.invalid"])
        file = self.root / "source.c"
        file.write_text("int synthetic_fixture;\n")
        v.run(["git", "-C", str(self.root), "add", "source.c"])
        v.run(["git", "-C", str(self.root), "commit", "-qm", "synthetic fixture"])
        receipt = v.source_receipt(self.root, pristine=True)
        self.assertEqual(receipt["status"], "")
        self.assertEqual(receipt["submodules"], [])
        file.write_text("int changed_fixture;\n")
        with self.assertRaisesRegex(RuntimeError, "not pristine"):
            v.source_receipt(self.root, pristine=True)
        receipt2 = v.source_receipt(self.root, pristine=False)
        self.assertIn("changed_fixture", receipt2["diff"])
        self.assertEqual(receipt2["commit"], receipt["commit"])


if __name__ == "__main__":
    unittest.main()
