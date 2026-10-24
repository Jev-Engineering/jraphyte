"""Additive, pinned research-domain query/context/replay contracts."""
from copy import deepcopy


def extend(schemas):
    s = {"type": "string", "minLength": 1}
    h = {"type": "string", "pattern": "^[0-9a-f]{64}$"}
    n = {"type": "integer", "minimum": 0}
    b = {"type": "boolean"}
    ids = {"type": "array", "items": s, "uniqueItems": True}
    def obj(props):
        return {"type": "object", "properties": deepcopy(props), "required": list(props), "additionalProperties": False}
    def nullable(value):
        return {"anyOf": [deepcopy(value), {"type": "null"}]}
    scope = obj({"contract_version": {"const": 1}, "taxonomy_id": s, "taxonomy_hash": h,
                 "domain_ids": {"type": "array", "items": {"type": "string", "pattern": "^research:[a-z0-9][a-z0-9._-]*$"},
                                "uniqueItems": True, "maxItems": 100},
                 "match": {"enum": ["ANY", "ALL"]}, "include_unclassified": b, "include_descendants": b})
    identity = obj({"contract_version": {"const": 1}, "revision": n, "hash": h, "migrated": b})
    metadata = obj({"version": {"const": "authorized-research-domain-selection-v1"}, "scope_hash": h,
                    "classification_hash": h, "anchor_assertion_ids": ids, "closure_assertion_ids": ids,
                    "source_assignments": {"type": "object", "additionalProperties": nullable(s)}})
    schemas["research-domain-scope"] = deepcopy(scope)
    schemas["classification-read-identity"] = deepcopy(identity)
    for kind in ("retrieval-query", "retrieval-plan"):
        schemas[kind]["properties"]["research_domain_scope"] = nullable(scope)
    for kind in ("graph-context", "retrieval-lineage", "graphrag-answer"):
        schemas[kind]["properties"]["research_domain_scope"] = nullable(scope)
        schemas[kind]["properties"]["classification_identity"] = deepcopy(identity)
    for kind in ("graph-context", "graphrag-answer"):
        schemas[kind]["properties"]["items"]["items"]["properties"]["research_domain"] = deepcopy(metadata)
    for key in ("original_classification_identity", "replayed_classification_identity"):
        schemas["retrieval-replay"]["properties"][key] = deepcopy(identity)
    schemas["retrieval-replay"]["properties"]["original_research_domain_scope"] = nullable(scope)
    schemas["retrieval-replay"]["properties"]["replayed_research_domain_scope"] = nullable(scope)
