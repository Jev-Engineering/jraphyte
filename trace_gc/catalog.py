"""Immutable semantic records, independent of mutable lifecycle/status projections."""
from __future__ import annotations
from copy import deepcopy
from typing import Any, Iterable
from .canonical import digest, text_digest
from .errors import boundary, require
from .schema import validate

KINDS = {"source", "claim", "evidence", "candidate", "pack", "observation", "evaluation",
         "resolution-batch", "resolution", "plan", "qualification", "receipt", "transaction", "schema", "graph-snapshot", "policy"}

from .retrieval.contracts import KINDS as RETRIEVAL_KINDS
KINDS.update(RETRIEVAL_KINDS)
KINDS.add("image-evidence-v1")

class Catalog:
    def __init__(self, records: Iterable[dict[str, Any]] = ()):
        self._records: dict[str, dict[str, Any]] = {}
        for record in records:
            self.add(record)

    @boundary
    def add(self, record: dict[str, Any]) -> str:
        validate("record", record)
        require(record["kind"] in KINDS, "RECORD_KIND", record["kind"])
        validate(record["kind"], record["body"])
        require(record["hash"] == digest({"kind": record["kind"], "body": record["body"]}),
                "RECORD_HASH", record["id"])
        if record["id"] in self._records:
            require(self._records[record["id"]] == record, "IMMUTABLE_RECORD", record["id"])
        self._records[record["id"]] = deepcopy(record)
        return record["id"]

    def put(self, kind: str, body: dict[str, Any], id_: str | None = None) -> str:
        h = digest({"kind": kind, "body": body})
        return self.add({"id": id_ or f"{kind}:{h}", "kind": kind, "hash": h, "body": body})

    def record(self, id_: str, kind: str | None = None) -> dict[str, Any]:
        require(id_ in self._records, "MISSING_REFERENCE", str(id_))
        record = self._records[id_]
        require(kind is None or record["kind"] == kind, "REFERENCE_TYPE", f"{id_} must be {kind}")
        return deepcopy(record)

    def get(self, id_: str, kind: str | None = None) -> dict[str, Any]:
        return self.record(id_, kind)["body"]

    def hash(self, id_: str) -> str:
        return self.record(id_)["hash"]

    def all(self, kind: str | None = None) -> list[dict[str, Any]]:
        return [deepcopy(r) for r in self._records.values() if kind is None or r["kind"] == kind]

    def __contains__(self, id_: str) -> bool:
        return id_ in self._records

    def source(self, source_id: str, version: str, text: str, *, scope: str, representation: str = "utf8-text-v1") -> str:
        return self.put("source", {"source_id": source_id, "version": version,
                        "representation": representation, "text": text, "text_hash": text_digest(text),
                        "security_scope": scope, "parser_version": "identity-v1", "raw_document_hash": None})

    def claim(self, text: str) -> str:
        return self.put("claim", {"text": text, "language": "en", "revision": 1})

    def evidence(self, source_snapshot_id: str, start: int = 0, end: int | None = None) -> str:
        s = self.get(source_snapshot_id, "source")
        end = len(s["text"]) if end is None else end
        require(type(start) is int and type(end) is int and 0 <= start < end <= len(s["text"]),
                "PROVENANCE_MISMATCH", "invalid Unicode code-point span")
        return self.put("evidence", {"source_snapshot_id": source_snapshot_id,
                        "source_hash": self.hash(source_snapshot_id), "start": start, "end": end,
                        "quote": s["text"][start:end], "offset_unit": "UNICODE_CODEPOINT",
                        "transformation": "identity-v1"})

    def verify_evidence(self, id_: str) -> None:
        e = self.get(id_, "evidence")
        s = self.get(e["source_snapshot_id"], "source")
        from .pdf_image_evidence import verify_image_source
        verify_image_source(self, s)
        require(s["text"] is not None, "REPLAY_CONTENT_UNAVAILABLE", "source has been erased")
        require(self.hash(e["source_snapshot_id"]) == e["source_hash"] and
                text_digest(s["text"]) == s["text_hash"] and
                0 <= e["start"] < e["end"] <= len(s["text"]) and
                s["text"][e["start"]:e["end"]] == e["quote"], "PROVENANCE_MISMATCH", id_)

    def candidate(self, *, id_: str, run_id: str, assertion: dict[str, Any], claim_id: str,
                  evidence_ids: list[str], prerequisites: list[str] | None = None,
                  alternatives: list[str] | None = None, kind: str = "ASSERTION",
                  mode: str = "SYNTHETIC", generator: str = "fixed-generator-v1") -> str:
        self.get(claim_id, "claim")
        for ref in evidence_ids:
            self.verify_evidence(ref)
        if assertion["predicate"] in {"supports", "refutes"}:
            require(assertion["object"] == claim_id, "CLAIM_BINDING", "use immutable claim ID as object")
            require(all(self.get(self.get(e, "evidence")["source_snapshot_id"], "source")["source_id"] == assertion["subject"]
                        for e in evidence_ids), "EVIDENCE_SUBJECT_BINDING", "citation must name the asserted source")
        return self.put("candidate", {"run_id": run_id, "candidate_kind": kind,
                        "assertion": assertion, "claim_id": claim_id, "claim_hash": self.hash(claim_id),
                        "evidence_ids": sorted(evidence_ids), "prerequisites": sorted(prerequisites or []),
                        "alternatives": sorted(alternatives or []), "generator_version": generator,
                        "execution_mode": mode, "revision": 1}, id_)
