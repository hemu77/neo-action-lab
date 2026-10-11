"""Mutation tests for the documentation acceptance checker."""
import importlib.util
import tempfile
import unittest
import warnings
import zipfile
from pathlib import Path

MODULE = Path(__file__).resolve().parents[1] / "verify_docs.py"
if not MODULE.exists():
    MODULE = MODULE.parent.parent / "verify_docs.py"
spec = importlib.util.spec_from_file_location("verify_docs", MODULE)
verify = importlib.util.module_from_spec(spec)
spec.loader.exec_module(verify)


def fixture(root):
    docs = root / "submission"
    docs.mkdir()
    sections = {title: "" for title in verify.HEADINGS}
    sections["Summary"] = "architecture " * 1850
    sections["Interfaces (JSON schemas)"] = '```json\n{"$defs":{"IntentContract":{},"AffordanceEntry":{},"Action":{},"GateDecision":{}}}\n```'
    sections[verify.HEADINGS[5]] = "\n".join(f"| G{i} | definition |" for i in range(1, 13))
    sections[verify.HEADINGS[6]] = "\n".join(f"| {i} | step | G1 | ALLOW |" for i in range(1, 9))
    sections[verify.HEADINGS[6]] += "\n" + "\n".join(f"| {i+8} | attack | G{rule} | DENY |" for i, rule in enumerate((2, 3, 4, 5), 1))
    sections["References"] = "\n".join(verify.REQUIRED_REFERENCES)
    architecture = "\n".join(f"## {title}\n{body}\n" for title, body in sections.items())
    threats = "threat " * 500 + "\n" + "\n".join(f"| T{i} | hidden | {'Accepted' if i > 12 else 'Reduced'} | G1 |" for i in range(1, 17))
    policy = "policy " * 550 + "\n" + "\n".join(f"## {title}\n" + "\n".join("- example G1 T1" for _ in range(count)) for title, count in (("Autonomous", 6), ("CONFIRM", 6), ("DENY", 3)))
    for name, body in zip(verify.NAMES, (architecture, threats, policy)):
        (docs / name).write_text(body, encoding="utf-8")
    archive = root / "neo-action-security-architecture.zip"
    with zipfile.ZipFile(archive, "w") as z:
        for name in verify.NAMES: z.write(docs / name, name)
    return docs, archive


class DocumentationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.docs, self.archive = fixture(Path(self.temp.name))

    def results(self):
        return {name: ok for name, ok, _ in verify.run(self.docs, self.archive)}

    def change(self, name, transform):
        path = self.docs / name
        path.write_text(transform(path.read_text(encoding="utf-8")), encoding="utf-8")

    def test_complete_fixture_and_supplied_references_pass(self):
        self.assertTrue(all(self.results().values()))
        self.assertIn("Gen and xAI Partner", verify.REQUIRED_REFERENCES[0])
        self.change(verify.ARCH, lambda text: text.replace(verify.REQUIRED_REFERENCES[0], "missing title"))
        self.assertFalse(self.results()["supplied reference titles"])

    def test_tables_outside_required_section_do_not_satisfy_checks(self):
        self.change(verify.ARCH, lambda text: text.replace(f"## {verify.HEADINGS[5]}", f"## {verify.HEADINGS[5]}\n\n## Unrelated rules").replace(f"## {verify.HEADINGS[6]}", f"## {verify.HEADINGS[6]}\n\n## Unrelated trace"))
        result = self.results()
        self.assertFalse(result["G1-G12 rule table"])
        self.assertFalse(result["decision trace"])

    def test_overclaim_word_boundaries_and_unknown_references(self):
        self.change(verify.POLICY, lambda text: text + "\nIt resolves dates; it does not guarantee safety.")
        self.assertTrue(self.results()["no overclaims"])
        self.change(verify.POLICY, lambda text: text + "\nIt solves every attack. G99 T99")
        self.assertFalse(self.results()["no overclaims"])
        self.assertFalse(self.results()["cross references"])

    def test_duplicate_zip_and_extra_file_are_rejected(self):
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", UserWarning)
            with zipfile.ZipFile(self.archive, "a") as z:
                z.write(self.docs / verify.ARCH, verify.ARCH)
        self.assertFalse(self.results()["ZIP contents and bytes"])
        (self.docs / "extra.txt").write_text("extra", encoding="utf-8")
        self.assertFalse(self.results()["submission files"])

    def test_empty_docs_and_invalid_json_are_rejected(self):
        self.change(verify.ARCH, lambda text: text.replace('"$defs":', '"$defs" broken:'))
        self.assertFalse(self.results()["JSON schemas"])
        self.change(verify.POLICY, lambda _: "")
        self.assertFalse(self.results()[f"word count: {verify.POLICY}"])
        self.assertFalse(self.results()["confirmation policy examples"])


if __name__ == "__main__":
    unittest.main()
