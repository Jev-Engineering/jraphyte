"""Versioned topical classification contracts; no source/evidence schema edits."""
from copy import deepcopy


def extend(schemas):
    text = {"type": "string", "minLength": 1, "maxLength": 512}
    h = {"type": "string", "pattern": "^[0-9a-f]{64}$"}
    n = {"type": "integer", "minimum": 0, "maximum": 9007199254740991}
    pos = {**n, "minimum": 1}
    stamp = {"type": "string", "format": "date-time"}
    domain_id = {"type": "string", "pattern": "^[a-z][a-z0-9]*(?:[._:-][a-z0-9]+)*$", "maxLength": 128}

    def obj(props):
        return {"type": "object", "properties": deepcopy(props),
                "required": list(props), "additionalProperties": False}

    def arr(item, maximum=64, minimum=0):
        return {"type": "array", "items": deepcopy(item), "uniqueItems": True,
                "minItems": minimum, "maxItems": maximum}

    def nullable(item):
        return {"anyOf": [deepcopy(item), {"type": "null"}]}

    version = {"const": "trace-research-domain-v1"}
    schemas["research-domain-taxonomy"] = obj({
        "contract_version": version, "namespace": domain_id, "version": text,
        "domains": arr(obj({"id": domain_id, "label": text,
                            "parent_ids": arr(domain_id, 32)}), 4096, 1),
        "unclassified_semantics": {"const": "EXPLICIT_STATE_WITH_NO_LABELS"},
        "membership_semantics": {"const": "EXPLICIT_LABELS_NO_IMPLICIT_ANCESTORS"},
        "authorization_granted": {"const": False},
    })
    proposal = {
        "contract_version": version,
        "source_snapshot_id": text, "source_hash": h, "security_scope": text,
        "source_epoch": n, "taxonomy_id": text, "taxonomy_hash": h,
        "taxonomy_version": text, "domain_ids": arr(domain_id),
        "state": {"enum": ["CLASSIFIED", "UNCLASSIFIED", "RETIRED"]},
        "method": obj({"kind": {"enum": ["HUMAN", "RULE", "MODEL"]},
                       "name": text, "version": text, "artifact_hash": h}),
        "basis": arr(obj({"record_id": text, "record_hash": h,
                          "locator": {"enum": ["SOURCE_TEXT", "EVIDENCE_SPAN"]}}), 64, 1),
        "revision": pos, "effective_graph_version": pos,
        "supersedes": nullable(text), "supersedes_hash": nullable(h),
        "execution_mode": {"enum": ["SYNTHETIC", "RECORDED", "LIVE"]},
        "created_at": stamp, "authorization_granted": {"const": False},
    }
    schemas["classification-proposal"] = obj(proposal)
    schemas["classification-assignment"] = obj({
        **proposal, "proposal_id": text, "proposal_hash": h,
        "review_receipt_id": text, "review_receipt_hash": h,
        "reviewed_approver": text, "reviewed_at": stamp,
    })
    for kind in ("research-domain-taxonomy", "classification-proposal", "classification-assignment"):
        if kind not in schemas["record"]["properties"]["kind"]["enum"]:
            schemas["record"]["properties"]["kind"]["enum"].append(kind)
    schemas["receipt"]["properties"]["purpose"]["enum"].append("CLASSIFICATION_REVIEW")
    publication_version = {"const": "trace-domain-publication-v1"}
    mapping = lambda item: {"type": "object", "additionalProperties": deepcopy(item)}
    schemas["classification-plan"] = obj({
        "contract_version": publication_version,
        "action": {"enum": ["MIGRATE_CLASSIFICATION_STATE", "PUBLISH_CLASSIFICATION"]},
        "run_id": text, "graph_version": n, "base_state_hash": h,
        "idempotency_key": text, "security_scope": text,
        "execution_mode": {"enum": ["SYNTHETIC", "RECORDED", "LIVE"]},
        "assignment_id": nullable(text), "assignment_hash": nullable(h),
        "taxonomy_id": nullable(text), "taxonomy_hash": nullable(h),
        "source_hashes": mapping(h), "source_epochs": mapping(n), "created_at": stamp,
    })
    schemas["record"]["properties"]["kind"]["enum"].append("classification-plan")
    schemas["receipt"]["properties"]["purpose"]["enum"].extend([
        "CLASSIFICATION_PREFLIGHT", "CLASSIFICATION_PUBLISH"])
    # Optional: do not rewrite or rehash old graph snapshot bodies.
    schemas["graph-snapshot"]["properties"]["research_domains"] = obj({
        "contract_version": publication_version, "revision": pos,
        "assignments": mapping(obj({"assignment_id": text, "assignment_hash": h})),
    })
