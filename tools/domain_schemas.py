"""Standalone schemas for immutable research-domain metadata (contract v1)."""
from copy import deepcopy


def extend(schemas):
    s = {"type": "string", "minLength": 1}
    h = {"type": "string", "pattern": "^[0-9a-f]{64}$"}
    timestamp = {"type": "string", "format": "date-time"}
    positive = {"type": "integer", "minimum": 1}
    domain_id = {"type": "string", "pattern": "^research:[a-z0-9][a-z0-9._-]*$"}

    def nullable(value):
        return {"anyOf": [deepcopy(value), {"type": "null"}]}

    def array(value, minimum=0):
        return {"type": "array", "items": deepcopy(value), "minItems": minimum, "uniqueItems": True}

    def obj(values):
        return {"type": "object", "properties": deepcopy(values), "required": list(values),
                "additionalProperties": False}

    review = obj({"status": {"enum": ["PROPOSED", "APPROVED"]},
                  "reviewer_id": nullable(s), "reviewed_at": nullable(timestamp), "rationale": s})
    predecessor = {"supersedes": nullable(s), "supersedes_hash": nullable(h)}
    schemas["research-domain-taxonomy"] = obj({
        "contract_version": {"const": 1}, "taxonomy_key": s, "version": positive,
        "domains": array(obj({"id": domain_id, "label": s, "definition": s,
                               "parent_ids": array(domain_id), "status": {"enum": ["ACTIVE", "RETIRED"]}}), 1),
        **predecessor, "provenance": obj({"method": {"const": "CURATED"}, "method_version": s, "basis": s}),
        "review": review,
    })
    schemas["classification-assignment"] = obj({
        "contract_version": {"const": 1}, "source_snapshot_id": s, "source_hash": h, "security_scope": s,
        "taxonomy_id": s, "taxonomy_hash": h, "domain_ids": array(domain_id),
        "status": {"enum": ["CLASSIFIED", "UNCLASSIFIED", "RETIRED"]},
        "effective_revision": positive, **predecessor,
        "provenance": obj({"method": {"enum": ["HUMAN_REVIEW", "RULE_ASSISTED", "MODEL_ASSISTED"]},
                            "classifier_id": s, "classifier_version": s,
                            "basis": array(obj({"record_id": s, "record_hash": h}), 1)}),
        "review": review,
    })
    schemas["record"]["properties"]["kind"]["enum"].extend(
        ["research-domain-taxonomy", "classification-assignment"])

