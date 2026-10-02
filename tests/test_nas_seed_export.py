from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from scripts.export_nas_seed_corpus import export_corpus


class NasSeedExportTests(unittest.TestCase):
    def test_exports_sixteen_seeds_to_separate_parser_directories(self):
        source = Path(__file__).resolve().parents[1] / "data/raw/nas_seed_suite_20261002/seeds.json"
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "corpus"
            manifest = export_corpus(source, output)
            self.assertEqual(len(manifest["seeds"]), 16)
            self.assertEqual(len(list((output / "gmm").glob("*.bin"))), 8)
            self.assertEqual(len(list((output / "gsm").glob("*.bin"))), 8)
            saved = json.loads((output / "manifest.json").read_text(encoding="utf-8"))
            self.assertEqual(saved["schema_version"], "nas-curated-corpus-v1")

    def test_refuses_to_overwrite_existing_corpus(self):
        source = Path(__file__).resolve().parents[1] / "data/raw/nas_seed_suite_20261002/seeds.json"
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "corpus"
            output.mkdir()
            (output / "keep.txt").write_text("preserve", encoding="utf-8")
            with self.assertRaises(FileExistsError):
                export_corpus(source, output)
            self.assertEqual((output / "keep.txt").read_text(encoding="utf-8"), "preserve")


if __name__ == "__main__":
    unittest.main()
