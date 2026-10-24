"""Additive, version-selected topical retrieval contracts; old records stay valid."""
from copy import deepcopy


def extend(schemas):
    from trace_gc.retrieval.domain_scope import VERSION
    S = {"type": "string", "minLength": 1}
    N = {"type": "integer", "minimum": 0}
    H = {"type": "string", "pattern": "^[0-9a-f]{64}$"}
    B = {"type": "boolean"}
    def arr(value): return {"type": "array", "items": deepcopy(value)}
    IDS = {**arr(S), "uniqueItems": True}
    def obj(props): return {"type": "object", "properties": deepcopy(props), "required": list(props), "additionalProperties": False}
    def nullable(value): return {"anyOf": [deepcopy(value), {"type": "null"}]}
    def mapping(value): return {"type": "object", "additionalProperties": deepcopy(value)}
    scope = obj({"taxonomy_id": S, "taxonomy_hash": H, "domain_ids": IDS,
                 "include_unclassified": B, "match": {"const": "ANY_EXPLICIT_LABEL"}})
    binding = obj({"scope": scope, "scope_hash": H, "projection_hash": H, "projection_revision": N})
    query = schemas["retrieval-query"]
    legacy = query["properties"]["version"]["const"]
    query["properties"]["version"] = {"enum": [legacy, VERSION]}
    query["properties"]["research_domain_scope"] = scope
    query["allOf"] = [{"if": {"properties": {"version": {"const": VERSION}}},
                       "then": {"required": ["research_domain_scope"]},
                       "else": {"not": {"required": ["research_domain_scope"]}}}]
    membership = obj({"state": {"enum": ["CLASSIFIED", "UNCLASSIFIED", "RETIRED"]}, "domain_ids": IDS,
        "assignment_id": nullable(S), "assignment_hash": nullable(H), "assignment_revision": N,
        "taxonomy_id": nullable(S), "taxonomy_hash": nullable(H), "taxonomy_version": nullable(S),
        "projection_hash": H, "projection_revision": N})
    fact = obj({"assertion_id": S, "subject": S, "predicate": S, "object": S,
                "qualifiers": mapping({"type": "string"}), "evidence_ids": IDS})
    details = obj({**binding["properties"], "anchor_assertion_ids": IDS,
                   "closure_assertions": arr(fact), "source_memberships": mapping(membership),
                   "authorization_granted": {"const": False}})
    for kind in ("graph-context", "graphrag-answer"):
        schemas[kind]["properties"]["items"]["items"]["properties"]["research_domain_context"] = deepcopy(details)
    schemas["retrieval-plan"]["properties"]["research_domain_scope"] = deepcopy(scope)
    for kind in ("graph-context", "retrieval-lineage"):
        schemas[kind]["properties"]["research_domain_binding"] = deepcopy(binding)
