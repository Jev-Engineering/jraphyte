"""Authored packet integrity tests, never empirical source certification."""
from copy import deepcopy
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from src import paper_review_packets as packets
from tests.test_selector_promotion import closure_fixture, failure_observation, NOW
from trace_gc.pdf_source_parallel_v4 import digest_value, json_bytes
from trace_gc.pdf_structure_parallel_v4 import seal

AVAILABLE = bool(importlib.util.find_spec("fitz") and importlib.util.find_spec("PIL"))


def write(root, name, value):
    raw = value if type(value) is bytes else json_bytes(value) + b"\n"
    path = root / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(raw)
    return {"relative": name, "sha256": packets.sha(raw)}


def fixture(root):
    prediction, _, args, assets = closure_fixture()
    source = args["pdf_bytes"]
    prediction = seal({**prediction, "page_sha256": packets.sha(source), "page_size": [500, 500],
        "status": "complete", "proposal": True, "complete_candidate": True,
        "section_owner": "abstract", "transcription": "native_pdf"})
    descriptors = {"source": write(root, "source.pdf", source), "page": write(root, "page.pdf", source),
        "image": write(root, "image.png", assets["page1.png"]), "native": write(root, "run/native/f001.json", args["native"]),
        "assessment": write(root, "run/assessments/parallel_structure_v4/f001.json", prediction)}
    identity = {k+"_sha256": descriptors[k]["sha256"] for k in ("source", "page", "image")}
    observation = failure_observation(prediction, identity)
    reviews = {"version": "promotion-fidelity-review-v1", "cases": {"f001": {"candidate_observations": [observation]}}}
    manifest = {"mode": "fresh", "experiment_sha256": "e"*64, "cases": [{"id": "f001",
        "native_relative": descriptors["native"]["relative"], "file_sha256": descriptors["native"]["sha256"],
        "native_sha256": digest_value(args["native"]), **identity}]}
    native_manifest = write(root, "run/native_manifest.json", manifest)
    results = {"native_manifest_sha256": native_manifest["sha256"], "experiment_sha256": "e"*64,
        "assessment_files_sha256": {"assessments/parallel_structure_v4/f001.json": descriptors["assessment"]["sha256"]},
        "execution_identity": {"method_hashes": {"authored_prior_tree": "f"*64}}}
    protocol = {"version": packets.VERSION, "scope": "authored_fixture", "native_manifest": native_manifest,
        "results": write(root, "run/results.json", results), "reviews": write(root, "reviews.json", reviews),
        "cases": {"f001": descriptors}}
    return protocol, write(root, "protocol.json", protocol)


class DescriptorTests(unittest.TestCase):
    def test_escape_is_rejected_before_read(self):
        with tempfile.TemporaryDirectory() as directory, patch.object(Path, "read_bytes") as read:
            with self.assertRaisesRegex(ValueError, "expected_safe_relative_path"):
                packets.Inputs(Path(directory)).read({"relative": "../secret", "sha256": "a"*64})
            read.assert_not_called()

    def test_hash_and_duplicate_json_fail_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            descriptor = write(root, "bad.json", b'{"x":1,"x":2}')
            with self.assertRaises(ValueError): packets.Inputs(root).read(descriptor, json_value=True)
            descriptor["sha256"] = "0"*64
            with self.assertRaisesRegex(ValueError, "packet_input_hash_mismatch"):
                packets.Inputs(root).read(descriptor)


@unittest.skipUnless(AVAILABLE, "optional PyMuPDF/Pillow authored fixtures")
class PacketTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.protocol, self.descriptor = fixture(self.root)
        # Real PDF/render/native verification is retained. The platform runtime
        # is tested by the private pinned CLI readback, not this authored suite.
        self.runtime = patch.object(packets, "runtime_receipt", return_value={"authored_runtime": True})
        self.runtime.start(); self.addCleanup(self.runtime.stop)

    def prepare(self):
        result = packets.prepare(self.root, self.descriptor, "out", evaluated_at=NOW)
        return {"relative": "out/receipt.json", "sha256": result["receipt_sha256"]}

    def save_protocol(self):
        self.descriptor = write(self.root, "protocol.json", self.protocol)

    def test_prepare_replay_preserves_failure_and_full_page_context(self):
        before = (self.root / "run/assessments/parallel_structure_v4/f001.json").read_bytes()
        receipt = self.prepare()
        self.assertEqual(packets.verify(self.root, receipt)["status"], "VERIFIED_PREPARATION_ONLY")
        packet = json.loads((self.root / "out/f001/packet.json").read_bytes())
        self.assertEqual(packet["negative_observations"][0]["status"], "fail")
        self.assertEqual(packet["status"], "WAIT_FULL_REGION_SOURCE_REVIEW")
        self.assertTrue(packet["selected_glyph_ids"])
        self.assertTrue(packet["outside_selected_extent_glyph_ids"])
        self.assertFalse(packet["proposal"])
        self.assertFalse(packet["crop_implies_section_ownership"])
        self.assertIsNone(packet["review"])
        self.assertIsNone(packet["corrected_transcription"])
        self.assertEqual(packet["prior_exposure"], "authored_fixture")
        self.assertEqual(packet["execution_mode"], "SYNTHETIC_AUTHORED")
        self.assertEqual(before, (self.root / "run/assessments/parallel_structure_v4/f001.json").read_bytes())

    def test_each_negative_case_is_required_even_if_protocol_and_hash_are_changed(self):
        reviews = json.loads((self.root / "reviews.json").read_bytes())
        reviews["cases"]["f002"] = deepcopy(reviews["cases"]["f001"])
        self.protocol["reviews"] = write(self.root, "reviews.json", reviews)
        self.save_protocol()
        with self.assertRaisesRegex(ValueError, "every_notation_failure"):
            self.prepare()

    def test_stale_negative_observation_never_becomes_a_packet(self):
        reviews = json.loads((self.root / "reviews.json").read_bytes())
        reviews["cases"]["f001"]["candidate_observations"][0]["assessment_sha256"] = "0"*64
        self.protocol["reviews"] = write(self.root, "reviews.json", reviews)
        self.save_protocol()
        with self.assertRaisesRegex(ValueError, "observation_identity_mismatch"):
            self.prepare()

    def test_boolean_offsets_and_wrong_source_image_are_rejected_on_bound_buffers(self):
        assets = self.protocol["cases"]["f001"]
        payloads = {k: (self.root/v["relative"]).read_bytes() for k,v in assets.items()}
        prediction = json.loads(payloads["assessment"])
        altered = deepcopy(prediction); altered["spans"][0]["start"] = False
        with self.assertRaisesRegex(ValueError, "typed_native_offsets"):
            packets._source(payloads, seal(altered))
        from io import BytesIO
        from PIL import Image
        stream = BytesIO(); Image.new("RGB", (834, 834), "white").save(stream, format="PNG")
        with self.assertRaisesRegex(ValueError, "review_image_not_original"):
            packets._source({**payloads, "image": stream.getvalue()}, prediction)

    def test_out_of_bounds_span_is_rejected_before_range_expansion(self):
        assets = self.protocol["cases"]["f001"]
        payloads = {k: (self.root/v["relative"]).read_bytes() for k,v in assets.items()}
        prediction = json.loads(payloads["assessment"])
        prediction["spans"][0]["end"] = 10**12
        with patch.object(packets, "range", create=True, side_effect=AssertionError("unsafe expansion")) as expand:
            with self.assertRaisesRegex(ValueError, "invalid_selected_span"):
                packets._source(payloads, seal(prediction))
            expand.assert_not_called()

    def test_actual_unicode_source_offsets_stay_codepoints(self):
        with patch("tests.test_selector_promotion.TEXT", "We study caf\u00e9 and x2."):
            self.protocol, self.descriptor = fixture(self.root)
        self.prepare()
        packet = json.loads((self.root / "out/f001/packet.json").read_bytes())
        sidecar = json.loads((self.root / "out/f001/notation.json").read_bytes())
        self.assertIn("\u00e9", packet["native_candidate_text"])
        span = packet["ordered_selected_spans"][0]
        selected = {g["id"]: g for g in sidecar["characters"]}
        self.assertEqual("".join(selected[i]["raw"] for i in packet["selected_glyph_ids"]), span["text"])
        self.assertEqual(len(packet["selected_glyph_ids"]), len(span["text"]))

    def test_changed_output_and_changed_input_cannot_verify(self):
        receipt = self.prepare()
        output = self.root / "out/f001/packet.json"
        original = output.read_bytes(); output.write_bytes(original + b" ")
        with self.assertRaisesRegex(ValueError, "output_readback_mismatch"):
            packets.verify(self.root, receipt)
        output.write_bytes(original)
        (self.root / "image.png").write_bytes(b"changed")
        with self.assertRaisesRegex(ValueError, "input_hash_mismatch"):
            packets.verify(self.root, receipt)

    def test_input_mutation_during_publication_leaves_durable_invalidation(self):
        real_write = packets.write_bytes_once
        original = (self.root / "image.png").read_bytes()
        def racing_write(path, raw):
            result = real_write(path, raw)
            (self.root / "image.png").write_bytes(b"changed")
            return result
        with patch.object(packets, "write_bytes_once", racing_write), self.assertRaisesRegex(ValueError, "input_changed"):
            self.prepare()
        (self.root / "image.png").write_bytes(original)
        self.assertTrue((self.root / "out/INVALIDATED.json").is_file())
        self.assertFalse((self.root / "out/receipt.json").exists())

    def test_current_tool_identity_is_required_for_replay(self):
        receipt = self.prepare()
        with patch.object(packets, "code_identity", return_value={"changed": True}), self.assertRaisesRegex(ValueError, "receipt_replay_mismatch"):
            packets.verify(self.root, receipt)


if __name__ == "__main__":
    unittest.main()
