"""Application-owned Ed25519 trust store; model output cannot enroll an issuer.

Private keys are injected into signer services, never read from bundles or
shipped in this project. Public key enrollment/revocation is an administrator
operation outside the inference API. Receipts are capabilities, not confidence.
"""
from __future__ import annotations
import base64
from dataclasses import dataclass
from datetime import timedelta
from typing import Any, Iterable
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from .canonical import canonical_bytes, digest
from .compiler import now, timestamp
from .errors import ContractError, require
from .schema import validate

@dataclass(frozen=True)
class IssuerPolicy:
    public_key: bytes
    principal: str
    purposes: frozenset[str]
    operations: frozenset[str]
    scopes: frozenset[str]
    modes: frozenset[str]
    maximum_risk: int = 5
    can_review: bool = False

class Signer:
    def __init__(self, issuer: str, private_key: Ed25519PrivateKey):
        require(bool(issuer),"ISSUER_ID","issuer ID required")
        self.issuer,self._key=issuer,private_key
    @classmethod
    def ephemeral(cls, issuer: str) -> "Signer":
        """For isolated demos/tests; enrollment still must be explicit."""
        return cls(issuer,Ed25519PrivateKey.generate())
    def public_key(self) -> bytes:
        return self._key.public_key().public_bytes(serialization.Encoding.Raw,serialization.PublicFormat.Raw)
    def issue(self, purpose: str, payload: dict[str,Any], *, issued_at: str | None = None,
              expires_at: str | None = None, lifetime_seconds: int = 600) -> dict[str,Any]:
        when=issued_at or now()
        expires=expires_at or (timestamp(when)+timedelta(seconds=lifetime_seconds)).isoformat().replace("+00:00","Z")
        require(timestamp(expires)>timestamp(when),"RECEIPT_INTERVAL","expiry must follow issuance")
        body={"purpose":purpose,"issuer":self.issuer,"issued_at":when,"expires_at":expires,"payload":payload}
        receipt={**body,"signature":base64.b64encode(self._key.sign(canonical_bytes(body))).decode("ascii")}
        validate("receipt",receipt)
        return receipt

class TrustStore:
    def __init__(self):
        self._issuers: dict[str,IssuerPolicy]={}
        self._revoked: set[str]=set()
    def enroll(self, issuer: str, policy: IssuerPolicy) -> None:
        require(issuer not in self._issuers,"ISSUER_EXISTS","rotate with a new key ID")
        require(len(policy.public_key)==32 and 0<=policy.maximum_risk<=5,"ISSUER_CONFIG","invalid key/risk bound")
        self._issuers[issuer]=policy
    def revoke(self, issuer: str) -> None:
        require(issuer in self._issuers,"UNTRUSTED_ISSUER",issuer)
        self._revoked.add(issuer)
    def verify(self, receipt: dict[str,Any], purpose: str, *, at: str | None = None) -> IssuerPolicy:
        validate("receipt",receipt)
        issuer=receipt["issuer"]
        require(issuer in self._issuers and issuer not in self._revoked,"UNTRUSTED_ISSUER",issuer)
        policy=self._issuers[issuer]
        require(receipt["purpose"]==purpose and purpose in policy.purposes,"RECEIPT_PURPOSE",purpose)
        body={k:v for k,v in receipt.items() if k!="signature"}
        try:
            signature=base64.b64decode(receipt["signature"],validate=True)
            Ed25519PublicKey.from_public_bytes(policy.public_key).verify(signature,canonical_bytes(body))
        except (ValueError,InvalidSignature) as exc:raise ContractError("SIGNATURE_INVALID",issuer) from exc
        instant=timestamp(at or now())
        require(timestamp(receipt["issued_at"])<=instant<timestamp(receipt["expires_at"]),"RECEIPT_EXPIRED","receipt not currently applicable")
        payload=receipt["payload"]
        if "security_scope" in payload:require(payload["security_scope"] in policy.scopes,"AUTHORIZATION_SCOPE",issuer)
        if "execution_mode" in payload:require(payload["execution_mode"] in policy.modes,"AUTHORIZATION_MODE",issuer)
        return policy

AUTH_FIELDS={"plan_hash","run_id","security_scope","execution_mode","operation_ids","operations","reviewed_by","qualification_ids"}

def authorize_plan(signer: Signer, plan: dict[str,Any], plan_hash: str, *, reviewed_by: str | None = None,
                   issued_at: str | None = None, expires_at: str | None = None) -> dict[str,Any]:
    return signer.issue("AUTHORIZATION",{"plan_hash":plan_hash,"run_id":plan["run_id"],"security_scope":plan["security_scope"],
                        "execution_mode":plan["execution_mode"],"operation_ids":sorted(op["id"] for op in plan["operations"]),
                        "operations":{op["id"]:op["operation"] for op in plan["operations"]},"reviewed_by":reviewed_by,
                        "qualification_ids":sorted(plan["qualification_ids"])},issued_at=issued_at,expires_at=expires_at)

def verify_authorization(trust: TrustStore, receipt: dict[str,Any], plan: dict[str,Any], plan_hash: str,
                         *, at: str | None = None, sandbox: bool = False) -> bool:
    issuer=trust.verify(receipt,"AUTHORIZATION",at=at);p=receipt["payload"]
    require(set(p)==AUTH_FIELDS,"AUTHORIZATION_FIELDS","authorization payload contract")
    require(p["plan_hash"]==plan_hash and p["run_id"]==plan["run_id"] and p["security_scope"]==plan["security_scope"] and
            p["execution_mode"]==plan["execution_mode"],"AUTHORIZATION_BINDING","receipt does not authorize these plan bytes")
    require(p["operation_ids"]==sorted(op["id"] for op in plan["operations"]) and
            p["operations"]=={op["id"]:op["operation"] for op in plan["operations"]} and
            p["qualification_ids"]==sorted(plan["qualification_ids"]),"AUTHORIZATION_OPERATIONS","operation scope mismatch")
    require(all(op["operation"] in issuer.operations and int(op["risk_class"][1:])<=issuer.maximum_risk for op in plan["operations"]),
            "AUTHORIZATION_PERMISSION","issuer lacks operation/risk permission")
    reviewed=p["reviewed_by"] is not None
    if reviewed:require(issuer.can_review and p["reviewed_by"]==issuer.principal,"REVIEW_AUTHORITY","review attribution must match a trusted reviewer")
    if any(op["operation"] in {"RETRACT_ASSERTION","APPLY_SCHEMA_MIGRATION","PROPOSE_SCHEMA_MIGRATION","INITIALIZE_RESEARCH_DOMAINS","SET_SOURCE_CLASSIFICATION"} or op["risk_class"]=="R5" for op in plan["operations"]):
        require(reviewed,"REVIEW_REQUIRED","consequential maintenance and R5 require review")
    if plan["execution_mode"]=="SYNTHETIC":
        require(sandbox and reviewed,"SYNTHETIC_PUBLICATION_FORBIDDEN","synthetic input can only exercise an explicitly isolated reviewed test store")
    return reviewed

def attest_observation(signer: Signer, record: dict[str,Any], *, lifetime_seconds: int = 31536000) -> dict[str,Any]:
    o=record["body"]
    return signer.issue("OBSERVATION",{"observation_hash":record["hash"],"wire_request_hash":o["wire_request_hash"],
                        "wire_response_hash":o["wire_response_hash"],"execution_mode":o["execution_mode"],
                        "security_scope":o["security_scope"],"run_id":o["run_id"],"model_version":o["model_requested"]},
                        issued_at=o["completed_at"],lifetime_seconds=lifetime_seconds)

def verify_observation_attestation(trust: TrustStore, receipt: dict[str,Any], record: dict[str,Any]) -> None:
    o=record["body"]
    trust.verify(receipt,"OBSERVATION",at=o["completed_at"])
    require(receipt["payload"]=={"observation_hash":record["hash"],"wire_request_hash":o["wire_request_hash"],
            "wire_response_hash":o["wire_response_hash"],"execution_mode":o["execution_mode"],"security_scope":o["security_scope"],
            "run_id":o["run_id"],"model_version":o["model_requested"]},"OBSERVATION_ATTESTATION","untrusted observation provenance")
