import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from src.parallel_source_v4.image_ocr import prepare, prepared, recognize, reviewed_handoff
from trace_gc.canonical import bytes_digest
from trace_gc.pdf_image_evidence import CHECKS, candidate_hash
from tools.image_evidence_fixtures import TEXT, synthetic_pdf

try:
    import fitz
    import PIL
    AVAILABLE = True
except ImportError:
    AVAILABLE = False


@unittest.skipUnless(AVAILABLE, "PyMuPDF and Pillow required for image evidence")
class ImageHandoffIoTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        (self.root / "source.pdf").write_bytes(synthetic_pdf())
        prepare(self.root, "source.pdf", "prepared", source_id="synthetic-paper", dpi=72)

    def cached(self):
        (self.root / "cache.json").write_text(json.dumps({"raw_text": TEXT, "status": "success"}))
        return recognize(self.root, "prepared", "ocr", cached_output="cache.json")

    def review(self, candidate_hash_override=None):
        candidate = json.loads((self.root / "ocr/candidate.json").read_text())
        (self.root / "review.json").write_text(json.dumps({
            "candidate_sha256": candidate_hash_override or candidate_hash(candidate),
            "reviewer": "synthetic-test-review", "reviewer_kind": "assistant",
            "reviewed_at": "2026-09-28T12:00:00Z", "disposition": "complete",
            "checks": {key: True for key in CHECKS}, "notes": "Authored fixture, not independent qualification."}))

    def handoff(self):
        return reviewed_handoff(self.root, "prepared", "ocr", "review.json", "handoff", scope="test")

    def test_legacy_cache_preserves_raw_bytes_and_remains_held_after_review(self):
        result = self.cached()
        self.assertEqual(result["new_local_ocr_calls"], 0)
        self.assertEqual((self.root / "cache.json").read_bytes(), (self.root / "ocr/raw-ocr.json").read_bytes())
        self.review()
        result = self.handoff()
        self.assertEqual(result["status"], "HELD")
        self.assertEqual(result["reason"], "ocr_input_provenance_unverified")
        self.assertEqual(json.loads((self.root / "handoff/catalog-records.json").read_text()), [])

    def test_original_and_page_image_changes_block_preparation_readback(self):
        (self.root / "prepared/page.png").write_bytes(b"tampered")
        with self.assertRaisesRegex(ValueError, "source_or_artifact_changed"):
            prepared(self.root, "prepared")

    def test_review_of_another_candidate_is_rejected(self):
        self.cached(); self.review("a" * 64)
        with self.assertRaisesRegex(ValueError, "review_targets_another_candidate"):
            self.handoff()
        self.assertFalse((self.root / "handoff/handoff.json").exists())

    def test_candidate_from_another_crop_cannot_borrow_preparation_review(self):
        self.cached()
        candidate = json.loads((self.root / "ocr/candidate.json").read_text())
        candidate["source_id"] = "another-paper"
        (self.root / "ocr/candidate.json").write_text(json.dumps(candidate))
        self.review()
        with self.assertRaisesRegex(ValueError, "candidate_targets_another_preparation"):
            self.handoff()

    def test_source_mutated_after_review_is_rejected_before_any_receipt(self):
        self.cached(); self.review()
        from src.parallel_source_v4 import image_ocr
        original = image_ocr.handoff
        def mutate(*args, **kwargs):
            result = original(*args, **kwargs)
            (self.root / "source.pdf").write_bytes(b"different original")
            return result
        with patch.object(image_ocr, "handoff", side_effect=mutate):
            with self.assertRaisesRegex(ValueError, "image_input_changed_before_publication"):
                self.handoff()
        self.assertFalse((self.root / "handoff/handoff.json").exists())

    def test_paths_stay_inside_explicit_root_and_outputs_are_immutable(self):
        with self.assertRaisesRegex(ValueError, "expected_safe_relative_path"):
            prepare(self.root, "../source.pdf", "prepared", source_id="x")
        with self.assertRaisesRegex(ValueError, "immutable"):
            prepare(self.root, "source.pdf", "prepared", source_id="x", dpi=144)

    def test_installed_ocr_output_is_bound_without_running_provider_in_test(self):
        from src.parallel_source_v4 import image_ocr
        def process(command, **kwargs):
            raw_path = Path(command[command.index("-OutputPath") + 1])
            crop_path = Path(command[command.index("-CropPath") + 1])
            raw_path.write_text(json.dumps({"engine": "authored-synthetic-ocr-adapter", "revision": "fixture-v1",
                "configuration": {"inference": False}, "input_crop_sha256": bytes_digest(crop_path.read_bytes()),
                "output_status": "complete", "text": TEXT}))
            class Result:
                returncode = 0
            return Result()
        with patch.object(image_ocr.sys, "platform", "win32"), patch.object(image_ocr.subprocess, "run", side_effect=process):
            recognize(self.root, "prepared", "ocr")
        self.review()
        result = self.handoff()
        self.assertEqual(result["status"], "REVIEWED_TEXT_EVIDENCE")
        self.assertFalse(result["admitted"])
        self.assertEqual(len(json.loads((self.root / "handoff/catalog-records.json").read_text())), 3)


if __name__ == "__main__":
    unittest.main()
