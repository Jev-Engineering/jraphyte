"""Application-owned, deny-by-default ACLs. Queries cannot grant access."""
from __future__ import annotations
from copy import deepcopy
from typing import Any
from ..canonical import digest
from ..catalog import Catalog
from ..errors import require
from .telemetry import measured_acl


def access_policy(*, tenant: str, workspace: str, user: str, roles: list[str] | None = None,
                  clearance: int = 0, grants: dict[str, dict[str, Any]] | None = None,
                  revision: str = "acl-v1") -> dict[str, Any]:
    """Call only from the trusted application's authentication/authorization layer.

    Keys are exact ``node:ID``, ``edge:ID``, ``source:SNAPSHOT_ID``, ``decision:ID``.
    Missing grants deny access. No wildcard expansion across graph connections.
    """
    return {"version": revision, "tenant": tenant, "workspace": workspace, "user": user,
            "roles": sorted(set(roles or [])), "clearance": clearance, "grants": deepcopy(grants or {})}


def grant(tenant: str, workspace: str, *, users: list[str] | None = None,
          roles: list[str] | None = None, classification: int = 0) -> dict[str, Any]:
    return {"tenant": tenant, "workspace": workspace, "users": users or [], "roles": roles or [],
            "classification": classification}


class AccessFilter:
    @measured_acl("__init__")
    def __init__(self, policy: dict[str, Any], catalog: Catalog, statuses: dict[str, Any], *, historical: bool = False):
        from ..schema import validate
        validate("graph-access", policy)
        self.policy, self.catalog, self.statuses = deepcopy(policy), catalog, deepcopy(statuses)
        self.historical = historical

    @property
    def fingerprint(self) -> str:
        return digest({"acl": self.policy, "statuses": self.statuses})

    @measured_acl("allows")
    def allows(self, kind: str, ref: str) -> bool:
        p = self.policy
        g = p["grants"].get(f"{kind}:{ref}")
        if not g or g["tenant"] != p["tenant"] or g["workspace"] != p["workspace"]:
            return False
        return (g["classification"] <= p["clearance"] and
                (not g["users"] or p["user"] in g["users"]) and
                (not g["roles"] or bool(set(g["roles"]) & set(p["roles"]))))

    @measured_acl("source")
    def source(self, source_id: str) -> bool:
        if not self.allows("source", source_id) or source_id not in self.catalog:
            return False
        source = self.catalog.get(source_id, "source")
        status = self.statuses.get(source_id)
        return (source["security_scope"] == self.policy["tenant"] and bool(status) and
                status["permission"] == "READ" and not status["tombstone"] and status["active"])

    @measured_acl("evidence")
    def evidence(self, ref: str) -> bool:
        if ref not in self.catalog:
            return False
        source_id = self.catalog.get(ref, "evidence")["source_snapshot_id"]
        if not self.source(source_id):
            return False
        self.catalog.verify_evidence(ref)  # Existing Evidence Firewall, not a replacement.
        return True

    @measured_acl("edge")
    def edge(self, ref: str, fact: dict[str, Any]) -> bool:
        a = fact["assertion"]
        return (self.allows("edge", ref) and self.allows("node", a["subject"]) and
                self.allows("node", a["object"]) and all(self.evidence(e) for e in fact["evidence_ids"]))

    @measured_acl("decision")
    def decision(self, ref: str) -> bool:
        if not self.allows("decision", ref) or ref not in self.catalog:
            return False
        record = self.catalog.record(ref)
        b = record["body"]
        ids = b.get("evidence_ids", [])
        if record["kind"] == "candidate":
            a = b["assertion"]
            if not self.allows("node", a["subject"]) or not self.allows("node", a["object"]):
                return False
        if b.get("candidate_id") in self.catalog:
            c = self.catalog.get(b["candidate_id"], "candidate")
            a = c["assertion"]
            if not self.allows("node", a["subject"]) or not self.allows("node", a["object"]):
                return False
            ids = list(set(ids) | set(c["evidence_ids"]))
        return all(self.evidence(e) for e in ids)

    @measured_acl("require_scope")
    def require_scope(self, scope: str) -> None:
        require(scope == self.policy["tenant"], "SECURITY_SCOPE", "authenticated tenant differs from query")
