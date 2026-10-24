"""Isolated SQLite reference backend and atomic publication boundary.

This is a conformance/test backend, not a replacement for the pinned legacy
GraphStore. It uses the same original-assertion / reversible-view semantics.
Every state/status/record/journal change is in one BEGIN IMMEDIATE transaction.
The deployment adapter in legacy.py rejects nonmatching upstream bytes. Its
explicit conformance command is a separate mandatory deployment acceptance gate.
"""
from __future__ import annotations
import sqlite3
import threading
from copy import deepcopy
from pathlib import Path
from typing import Any,Callable
from .canonical import digest,dumps,loads
from .catalog import Catalog
from .compiler import now,timestamp
from .constraints import validate_graph,normalize
from .errors import ContractError,require
from .plans import validate_plan,deactivate,REQUIRED_CHECKS,Lifecycle
from .qualification import QualificationRegistry,context_for,evaluate_policy
from .trust import TrustStore,Signer,verify_authorization,verify_observation_attestation

class SQLiteReferenceBackend:
    """Single-host inspectable reference backend. No external graph connection."""
    def __init__(self,path: str | Path, *, catalog: Catalog, schema_id: str, nodes: dict[str,str], sandbox: bool=False):
        self.path,self.sandbox=str(path),sandbox
        self._lock=threading.RLock()
        self.db=sqlite3.connect(self.path,isolation_level=None,timeout=10,check_same_thread=False)
        try:
            self.db.execute("PRAGMA foreign_keys=ON")
            self.db.execute("PRAGMA journal_mode=WAL")
            self.db.execute("PRAGMA synchronous=FULL")
            self.db.executescript("""
            CREATE TABLE IF NOT EXISTS trace_state(id INTEGER PRIMARY KEY CHECK(id=1),body TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS trace_meta(id INTEGER PRIMARY KEY CHECK(id=1),body TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS trace_records(id TEXT PRIMARY KEY,hash TEXT NOT NULL,kind TEXT NOT NULL,body TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS trace_erased(id TEXT PRIMARY KEY,hash TEXT NOT NULL,kind TEXT NOT NULL,reason TEXT NOT NULL,erased_at TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS trace_source_status(id TEXT PRIMARY KEY,body TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS trace_journal(version INTEGER PRIMARY KEY,key TEXT UNIQUE NOT NULL,fingerprint TEXT NOT NULL,body TEXT NOT NULL,hash TEXT NOT NULL);
            """)
            schema=catalog.get(schema_id,"schema")
            validate_graph(nodes,{},schema["relations"])
            initial={"graph_version":0,"schema_id":schema_id,"schema_hash":catalog.hash(schema_id),"nodes":deepcopy(nodes),
                     "assertions":{},"source_epochs":{},"metadata":{},"schema_proposals":{}}
            self.db.execute("BEGIN IMMEDIATE")
            row=self.db.execute("SELECT body FROM trace_state WHERE id=1").fetchone()
            if row is None:
                self.db.execute("INSERT INTO trace_state VALUES(1,?)",(dumps(initial),))
                self.db.execute("INSERT INTO trace_meta VALUES(1,?)",(dumps({"sandbox":sandbox,"genesis_hash":digest(initial),"genesis_state":initial}),))
                self._persist([catalog.record(schema_id)])
            else:
                meta=loads(self.db.execute("SELECT body FROM trace_meta WHERE id=1").fetchone()[0])
                require(meta["sandbox"]==sandbox,"BACKEND_MODE","a sandbox database cannot be reopened as production")
                state=loads(row[0])
                require(state["schema_id"]==schema_id and state["schema_hash"]==catalog.hash(schema_id),"SCHEMA_HASH","reopen with current schema")
            self.db.execute("COMMIT")
        except BaseException:
            try:
                if self.db.in_transaction:self.db.execute("ROLLBACK")
            finally:
                self.db.close()
            raise

    def close(self) -> None:self.db.close()
    def __enter__(self):return self
    def __exit__(self,*args):self.close()
    def state(self) -> dict[str,Any]:
        with self._lock:return loads(self.db.execute("SELECT body FROM trace_state WHERE id=1").fetchone()[0])
    def statuses(self) -> dict[str,Any]:
        with self._lock:return {ref:loads(body) for ref,body in self.db.execute("SELECT id,body FROM trace_source_status ORDER BY id")}
    def snapshot(self,catalog: Catalog) -> str:
        with self._lock:
            # A consistent read snapshot even with another connection writing.
            own=not self.db.in_transaction
            if own:self.db.execute("BEGIN")
            try:
                state=self.state();schema_row=self.db.execute("SELECT id,hash,kind,body FROM trace_records WHERE id=?",(state["schema_id"],)).fetchone()
                require(schema_row is not None,"REPLAY_CONTENT_UNAVAILABLE","schema record missing")
                catalog.add({"id":schema_row[0],"hash":schema_row[1],"kind":schema_row[2],"body":loads(schema_row[3])})
                body={k:state[k] for k in ("graph_version","schema_id","schema_hash","nodes","assertions","source_epochs")}
                if "research_domains" in state:
                    from .domain_publication import hydrate_projection
                    hydrate_projection(catalog, state, self.load_catalog())
                    body["research_domains"] = deepcopy(state["research_domains"])
                result=catalog.put("graph-snapshot",body)
                if own:self.db.execute("COMMIT")
                return result
            except BaseException:
                if own and self.db.in_transaction:self.db.execute("ROLLBACK")
                raise
    def _persist(self,records: list[dict[str,Any]]) -> None:
        for r in records:
            require(self.db.execute("SELECT 1 FROM trace_erased WHERE id=?",(r["id"],)).fetchone() is None,"TOMBSTONE_REUSE",r["id"])
            previous=self.db.execute("SELECT hash FROM trace_records WHERE id=?",(r["id"],)).fetchone()
            require(previous is None or previous[0]==r["hash"],"IMMUTABLE_RECORD",r["id"])
            self.db.execute("INSERT OR IGNORE INTO trace_records VALUES(?,?,?,?)",(r["id"],r["hash"],r["kind"],dumps(r["body"])))
    def _transaction(self, *, key: str, fingerprint: str, expected_version: int, operation: dict[str,Any],
                     catalog: Catalog, apply: Callable[[dict[str,Any],dict[str,Any]],dict[str,Any]],
                     authorization_hash: str, preflight_hash: str, upstream_head: str | None = None,
                     fault: Callable[[str],None] | None = None, at: str | None = None,
                     lineage_prefix: list[dict[str,Any]] | None = None) -> dict[str,Any]:
        require(bool(key) and type(expected_version) is int and expected_version>=0,"TRANSACTION_INPUT","explicit version/key required")
        def checkpoint(name: str) -> None:
            if fault is not None:fault(name)
        with self._lock:
            self.db.execute("BEGIN IMMEDIATE")
            try:
                when=at or now()
                previous=self.db.execute("SELECT fingerprint,body FROM trace_journal WHERE key=?",(key,)).fetchone()
                if previous:
                    require(previous[0]==fingerprint,"IDEMPOTENCY_CONFLICT","same key, different immutable action")
                    event=loads(previous[1]);self.db.execute("ROLLBACK")
                    return {"replayed":True,"event":event,"receipt":event["transaction_receipt"]}
                state=self.state();statuses=self.statuses()
                require(state["graph_version"]==expected_version,"STALE_GRAPH_VERSION","optimistic version mismatch")
                before=digest(state)
                resulting=apply(deepcopy(state),deepcopy(statuses))
                require(resulting["graph_version"]==expected_version,"TRANSACTION_INPUT","apply may not forge graph version")
                resulting["graph_version"]+=1
                resulting["source_epochs"]={ref:s["epoch"] for ref,s in self.statuses().items()}
                version=resulting["graph_version"]
                # Catalog records are immutable sidecars; no alternate accepted graph authority.
                self._persist(catalog.all())
                head=self.db.execute("SELECT hash FROM trace_journal ORDER BY version DESC LIMIT 1").fetchone()
                previous_hash=head[0] if head else None
                event_core={"version":version,"idempotency_key":key,"fingerprint":fingerprint,"before_hash":before,
                            "after_hash":digest(resulting),"state_after":resulting,"source_status":self.statuses(),
                            "operation":operation,"record_hashes":{r["id"]:r["hash"] for r in catalog.all()},
                            "authorization_hash":authorization_hash,"preflight_hash":preflight_hash,
                            "previous_hash":previous_hash,"upstream_head":upstream_head,"committed_at":when,
                            "lineage_prefix":deepcopy(lineage_prefix or [])}
                event_hash=digest(event_core)
                receipt={"backend":"sqlite-reference-v1","version":version,"idempotency_key":key,
                         "plan_hash":operation.get("plan_hash",digest(operation)),"before_hash":before,"after_hash":digest(resulting),
                         "previous_hash":previous_hash,"event_hash":event_hash,"operation_hash":digest(operation),
                         "authorization_hash":authorization_hash,"preflight_hash":preflight_hash,
                         "upstream_head":upstream_head,"committed_at":when}
                rh=digest({"kind":"transaction","body":receipt})
                receipt_record={"id":f"transaction:{rh}","hash":rh,"kind":"transaction","body":receipt}
                self._persist([receipt_record])
                event={**event_core,"hash":event_hash,"transaction_receipt":receipt}
                checkpoint("before_state_write")
                self.db.execute("UPDATE trace_state SET body=? WHERE id=1",(dumps(resulting),))
                checkpoint("after_state_write")
                self.db.execute("INSERT INTO trace_journal VALUES(?,?,?,?,?)",(version,key,fingerprint,dumps(event),event_hash))
                checkpoint("after_journal_write");checkpoint("before_commit")
                self.db.execute("COMMIT")
                catalog.add(receipt_record)
                return {"replayed":False,"event":event,"receipt":receipt}
            except BaseException:
                if self.db.in_transaction:self.db.execute("ROLLBACK")
                raise

    def admit_sources(self,catalog: Catalog,source_ids: list[str], *, trust: TrustStore,authorization: dict[str,Any],
                      security_scope: str,execution_mode: str,expected_version: int,key: str,at: str | None=None) -> dict[str,Any]:
        action={"action":"ADMIT","source_hashes":{ref:catalog.hash(ref) for ref in sorted(source_ids)},
                "security_scope":security_scope,"execution_mode":execution_mode,"expected_version":expected_version}
        def apply(state,statuses):
            issuer=trust.verify(authorization,"SOURCE_STATUS",at=at)
            require("SOURCE_ADMIT" in issuer.operations and authorization["payload"]==action,"SOURCE_AUTHORITY","source admission scope")
            for ref in source_ids:
                source=catalog.get(ref,"source")
                require(source["security_scope"]==security_scope,"SECURITY_SCOPE",ref)
                if ref in statuses:
                    require(not statuses[ref]["tombstone"],"TOMBSTONE_REUSE",ref)
                    continue
                status={"active":True,"permission":"READ","epoch":0,"updated_at":at or now(),"tombstone":False}
                self.db.execute("INSERT INTO trace_source_status VALUES(?,?)",(ref,dumps(status)))
            return state
        catalog.put("receipt",authorization)
        return self._transaction(key=key,fingerprint=digest(action),expected_version=expected_version,operation=action,
                                 catalog=catalog,apply=apply,authorization_hash=digest(authorization),preflight_hash=digest(action),at=at)

    def change_source_status(self,catalog: Catalog,source_id: str, *, active: bool,permission: str,expected_epoch: int,
                             expected_version: int,key: str,reason: str,authorization: dict[str,Any],trust: TrustStore,
                             tombstone: bool=False,at: str | None=None) -> dict[str,Any]:
        source=catalog.get(source_id,"source")
        require(type(active) is bool and type(tombstone) is bool and permission in {"READ","DENIED"} and bool(reason),"SOURCE_STATUS","invalid change")
        action={"action":"ERASE" if tombstone else "STATUS_CHANGE","source_id":source_id,"source_hash":catalog.hash(source_id),
                "active":active,"permission":permission,"expected_epoch":expected_epoch,"expected_version":expected_version,
                "security_scope":source["security_scope"],"reason":reason,"tombstone":tombstone}
        def apply(state,statuses):
            issuer=trust.verify(authorization,"SOURCE_STATUS",at=at)
            required="SOURCE_ERASE" if tombstone else "SOURCE_WITHDRAW" if not active else "SOURCE_PERMISSION"
            require(required in issuer.operations and authorization["payload"]==action,"SOURCE_AUTHORITY","status authority/scope mismatch")
            require(source_id in statuses and statuses[source_id]["epoch"]==expected_epoch,"STALE_SOURCE_EPOCH",source_id)
            require(not statuses[source_id]["tombstone"],"TOMBSTONE_REUSE",source_id)
            require(not tombstone or (not active and permission=="DENIED"),"TOMBSTONE_STATUS","erasure must revoke use")
            status={"active":active,"permission":permission,"epoch":expected_epoch+1,"updated_at":at or now(),"tombstone":tombstone}
            self.db.execute("UPDATE trace_source_status SET body=? WHERE id=?",(dumps(status),source_id))
            if not active or permission=="DENIED" or tombstone:
                # Revocation follows the authoritative persisted graph, never a caller's incomplete catalog.
                persisted_evidence={ref:loads(body) for ref,body in self.db.execute("SELECT id,body FROM trace_records WHERE kind='evidence'")}
                for fact in state["assertions"].values():
                    if fact["active"]:require(set(fact["evidence_ids"])<=persisted_evidence.keys(),"BACKEND_AUDIT","active assertion evidence is missing")
                affected_evidence={ref for ref,body in persisted_evidence.items() if body["source_snapshot_id"]==source_id}
                roots={ref for ref,fact in state["assertions"].items() if set(fact["evidence_ids"])&affected_evidence}
                deactivate(state["assertions"],roots)
            # Physical erasure is performed after this committed revocation by erase_cached_content.
            return state
        catalog.put("receipt",authorization)
        return self._transaction(key=key,fingerprint=digest(action),expected_version=expected_version,operation=action,catalog=catalog,
                                 apply=apply,authorization_hash=digest(authorization),preflight_hash=digest(action),at=at)

    def erase_cached_content(self,source_id: str, *, reason: str) -> dict[str,Any]:
        """Idempotent cleanup after authorized tombstoning; exact replay then reports loss.

        Never reports a source erased before revocation is durably committed.
        Caller-held copies and exports are outside this local retention boundary.
        """
        require(bool(reason),"ERASURE_REASON","reason required")
        with self._lock:
            self.db.execute("BEGIN IMMEDIATE")
            try:
                status=self.statuses().get(source_id)
                require(status is not None and status["tombstone"],"ERASURE_AUTHORITY","committed authorized tombstone required")
                records=[{"id":i,"hash":h,"kind":k,"body":loads(b)} for i,h,k,b in self.db.execute("SELECT id,hash,kind,body FROM trace_records")]
                lost={source_id}
                # Conservative reference closure: discard cached derived content.
                # This is content-reference matching, not an assertion of legal erasure completeness.
                def strings(value):
                    if isinstance(value,str):yield value
                    elif isinstance(value,list):
                        for v in value:yield from strings(v)
                    elif isinstance(value,dict):
                        for k,v in value.items():yield k;yield from strings(v)
                changed=True
                while changed:
                    changed=False
                    for r in records:
                        if r["id"] not in lost and set(strings(r["body"]))&lost:
                            lost.add(r["id"]);changed=True
                for r in records:
                    if r["id"] in lost:
                        self.db.execute("INSERT OR IGNORE INTO trace_erased VALUES(?,?,?,?,?)",(r["id"],r["hash"],r["kind"],reason,now()))
                        self.db.execute("DELETE FROM trace_records WHERE id=?",(r["id"],))
                self.db.execute("COMMIT")
                return {"status":"EXACT_REPLAY_UNAVAILABLE","source_id":source_id,"erased_ids":sorted(lost),"scope":"this backend's cached records only"}
            except BaseException:
                if self.db.in_transaction:self.db.execute("ROLLBACK")
                raise

    def load_catalog(self) -> Catalog:
        lost=self.db.execute("SELECT id FROM trace_erased LIMIT 1").fetchone()
        require(lost is None,"REPLAY_CONTENT_UNAVAILABLE","one or more source-derived records were erased; tombstone metadata remains")
        return Catalog({"id":i,"hash":h,"kind":k,"body":loads(b)} for i,h,k,b in self.db.execute("SELECT id,hash,kind,body FROM trace_records"))

    def view(self,catalog: Catalog) -> dict[str,Any]:
        from collections import defaultdict
        state=self.state();relations=catalog.get(state["schema_id"],"schema")["relations"]
        identities=validate_graph(state["nodes"],state["assertions"],relations)
        edges=defaultdict(list)
        for ref,fact in state["assertions"].items():
            if not fact["active"]:continue
            s,p,o=normalize(fact["assertion"],relations)
            if p not in {"same_as","different_from"}:
                s,o=identities[s],identities[o]
                if relations[p]["symmetric"] and s>o:s,o=o,s
            edges[(s,p,o,dumps(fact["assertion"]["qualifiers"]))].append(ref)
        return {"version":state["graph_version"],"identities":identities,
                "edges":[{"subject":s,"predicate":p,"object":o,"qualifiers":loads(q),"assertion_ids":sorted(ids)}
                         for (s,p,o,q),ids in sorted(edges.items())]}

    def audit(self) -> dict[str,Any]:
        meta=loads(self.db.execute("SELECT body FROM trace_meta WHERE id=1").fetchone()[0])
        previous=None;after=meta["genesis_hash"];count=0;last_status={}
        require(digest(meta["genesis_state"])==after,"BACKEND_AUDIT","genesis differs")
        for version,key,fingerprint,body,hash_ in self.db.execute("SELECT version,key,fingerprint,body,hash FROM trace_journal ORDER BY version"):
            event=loads(body);count+=1
            core={k:v for k,v in event.items() if k not in {"hash","transaction_receipt"}}
            require(version==count and event["version"]==version and key==event["idempotency_key"] and fingerprint==event["fingerprint"],"BACKEND_AUDIT","sequence/fingerprint differs")
            require(event["previous_hash"]==previous and event["before_hash"]==after and digest(core)==hash_==event["hash"],"BACKEND_AUDIT","journal chain differs")
            require(digest(event["state_after"])==event["after_hash"],"BACKEND_AUDIT","post-state differs")
            for ref,expected_hash in event["record_hashes"].items():
                row=self.db.execute("SELECT hash,kind,body FROM trace_records WHERE id=?",(ref,)).fetchone()
                if row:
                    require(row[0]==expected_hash and digest({"kind":row[1],"body":loads(row[2])})==expected_hash,"BACKEND_AUDIT","record bytes changed")
                else:
                    erased=self.db.execute("SELECT hash FROM trace_erased WHERE id=?",(ref,)).fetchone()
                    require(erased is not None and erased[0]==expected_hash,"BACKEND_AUDIT","missing record without tombstone")
            receipt=event["transaction_receipt"]
            require(receipt["event_hash"]==hash_ and receipt["version"]==version and receipt["before_hash"]==event["before_hash"] and
                    receipt["after_hash"]==event["after_hash"] and receipt["operation_hash"]==digest(event["operation"]),"BACKEND_AUDIT","receipt/journal disagreement")
            expected_receipt={"backend":"sqlite-reference-v1","version":version,"idempotency_key":key,
                "plan_hash":event["operation"].get("plan_hash",digest(event["operation"])),"before_hash":event["before_hash"],
                "after_hash":event["after_hash"],"previous_hash":event["previous_hash"],"event_hash":hash_,
                "operation_hash":digest(event["operation"]),"authorization_hash":event["authorization_hash"],
                "preflight_hash":event["preflight_hash"],"upstream_head":event["upstream_head"],"committed_at":event["committed_at"]}
            require(receipt==expected_receipt,"BACKEND_AUDIT","receipt was altered independently of the journal")
            previous,after,last_status=hash_,event["after_hash"],event["source_status"]
        state=self.state()
        require(state["graph_version"]==count and digest(state)==after and self.statuses()==last_status,"BACKEND_AUDIT","current state/status differs from journal")
        return {"events":count,"head_hash":previous,"state_hash":after,"sandbox":self.sandbox,
                "erased_record_count":self.db.execute("SELECT count(*) FROM trace_erased").fetchone()[0]}

class CompilerService:
    """Application-owned trusted boundary. Configuration never comes from a model."""
    def __init__(self,backend: SQLiteReferenceBackend,trust: TrustStore,validator_signer: Signer, *,
                 policy_version: str, population: str,security_scope: str,
                 qualification_registry: QualificationRegistry | None=None,
                 policy_hash: str | None=None, publication_mode: str="ANALYSIS_ONLY"):
        require(publication_mode in {"ANALYSIS_ONLY","REVIEWED","QUALIFIED"},"POLICY_MODE","unsupported publication mode")
        self.backend,self.trust,self.signer=backend,trust,validator_signer
        self.policy_version,self.population,self.scope=policy_version,population,security_scope
        self.registry=qualification_registry
        self.policy_hash,self.publication_mode=policy_hash,publication_mode

    def _check_policy_and_provenance(self,catalog: Catalog,plan: dict[str,Any],*,reviewed: bool,at: str | None=None) -> None:
        require(plan["policy_version"]==self.policy_version and plan["security_scope"]==self.scope,"POLICY_BINDING","service configuration differs")
        policy=catalog.get(plan["policy_id"],"policy")
        require(plan["execution_mode"]!="SYNTHETIC" or self.backend.sandbox,"SYNTHETIC_PUBLICATION_FORBIDDEN","synthetic plans cannot reach a non-sandbox publication boundary")
        require(self.publication_mode!="ANALYSIS_ONLY" and self.policy_hash==catalog.hash(plan["policy_id"]) and
                policy["mode"]==self.publication_mode,"ANALYSIS_ONLY","publication requires explicitly pinned application policy")
        require(policy["population"]==self.population,"POLICY_BINDING","service population differs")
        if self.publication_mode=="REVIEWED":require(reviewed,"REVIEW_REQUIRED","reviewed mode requires trusted reviewer")
        attestations={r["body"]["payload"].get("observation_hash"):r["body"] for r in catalog.all("receipt") if r["body"]["purpose"]=="OBSERVATION"}
        for op in plan["operations"]:
            if "evaluation_id" not in op:continue
            evaluation=catalog.get(op["evaluation_id"],"evaluation")
            expected=context_for(catalog,op["candidate_id"],evaluation["observation_ids"],evaluation["resolution_batch_id"],population=self.population,policy_version=self.policy_version)
            require(evaluation["context"]==expected and plan["contexts"][op["id"]]==expected,"QUALIFICATION_SCOPE","population/context differs from service configuration")
            # Only explicit trusted review can authorize an unqualified abstention.
            require(evaluation["outcome"]!="REJECT","POLICY_REJECTED","a rejected candidate cannot be silently overridden")
            if not reviewed:
                require(self.registry is not None and evaluation["qualification_id"] is not None,"UNQUALIFIED_POLICY","automatic write requires qualification")
                recomputed_id=evaluate_policy(catalog,candidate_id=op["candidate_id"],batch_id=evaluation["resolution_batch_id"],
                                policy_version=self.policy_version,population=self.population,registry=self.registry,
                                qualification_id=evaluation["qualification_id"],at=at)
                recomputed=catalog.get(recomputed_id,"evaluation")
                require(evaluation["outcome"]==recomputed["outcome"]=="ACCEPT" and evaluation["score"]==recomputed["score"],"UNQUALIFIED_POLICY","policy result cannot be asserted by input")
            for obs_id in evaluation["observation_ids"]:
                record=catalog.record(obs_id,"observation")
                if not self.backend.sandbox:
                    require(record["hash"] in attestations,"OBSERVATION_UNATTESTED","trusted observation/import receipt required")
                    verify_observation_attestation(self.trust,attestations[record["hash"]],record)

    def preflight(self,catalog: Catalog,plan_id: str,*,reviewed: bool=False,at: str | None=None) -> dict[str,Any]:
        plan=catalog.get(plan_id,"plan")
        # Preview cannot authorize; every check is repeated under the commit lock.
        state=self.backend.state()
        require(state["graph_version"]==plan["graph_version"] and state["schema_hash"]==plan["schema_hash"],"STALE_GRAPH_VERSION","preflight snapshot")
        snapshot=catalog.get(plan["snapshot_id"],"graph-snapshot")
        require(snapshot=={k:state[k] for k in snapshot},"SNAPSHOT_BINDING","snapshot must match actual backend, not caller declarations")
        validate_plan(catalog,plan,source_status=self.backend.statuses())
        self._check_policy_and_provenance(catalog,plan,reviewed=reviewed,at=at)
        payload={"plan_hash":catalog.hash(plan_id),"graph_version":plan["graph_version"],"schema_hash":plan["schema_hash"],
                 "source_epochs":plan["source_epochs"],"checks":{key:True for key in sorted(REQUIRED_CHECKS)},
                 "run_id":plan["run_id"],"security_scope":plan["security_scope"],"execution_mode":plan["execution_mode"],
                 "policy_version":self.policy_version,"population":self.population,"review_required":reviewed}
        return self.signer.issue("PREFLIGHT",payload,issued_at=at)

    def publish(self,catalog: Catalog,plan_id: str,*,authorization: dict[str,Any],preflight: dict[str,Any],
                upstream_head: str | None=None,fault: Callable[[str],None] | None=None,at: str | None=None) -> dict[str,Any]:
        plan=catalog.get(plan_id,"plan");plan_hash=catalog.hash(plan_id)
        operation={"action":"PUBLISH_PLAN","plan_id":plan_id,"plan_hash":plan_hash,"policy_version":self.policy_version,
                   "population":self.population,"security_scope":self.scope}
        def apply(state,statuses):
            reviewed=verify_authorization(self.trust,authorization,plan,plan_hash,at=at,sandbox=self.backend.sandbox)
            self.trust.verify(preflight,"PREFLIGHT",at=at)
            expected={"plan_hash":plan_hash,"graph_version":plan["graph_version"],"schema_hash":plan["schema_hash"],
                      "source_epochs":plan["source_epochs"],"checks":{key:True for key in sorted(REQUIRED_CHECKS)},
                      "run_id":plan["run_id"],"security_scope":plan["security_scope"],"execution_mode":plan["execution_mode"],
                      "policy_version":self.policy_version,"population":self.population,"review_required":preflight["payload"].get("review_required")}
            require(preflight["payload"]==expected and (not expected["review_required"] or reviewed),"PREFLIGHT_FAILED","invalid/missing checks or required review")
            snapshot=catalog.get(plan["snapshot_id"],"graph-snapshot")
            require(state["schema_hash"]==plan["schema_hash"] and snapshot=={k:state[k] for k in snapshot},"SNAPSHOT_BINDING","commit snapshot differs")
            prospective=validate_plan(catalog,plan,source_status=statuses)
            self._check_policy_and_provenance(catalog,plan,reviewed=reviewed,at=at)
            state["nodes"],state["assertions"]=prospective["nodes"],prospective["assertions"]
            for op in plan["operations"]:
                if op["operation"]=="APPLY_SCHEMA_MIGRATION":state["schema_id"]=op["target_schema_id"];state["schema_hash"]=catalog.hash(op["target_schema_id"])
                elif op["operation"]=="PROPOSE_SCHEMA_MIGRATION":state["schema_proposals"][op["id"]]=deepcopy(op)
                elif op["operation"]=="ATTACH_CANDIDATE_METADATA":state["metadata"].setdefault(op["candidate_id"],{})[op["id"]]=deepcopy(op["metadata"])
            return state
        catalog.put("receipt",authorization);catalog.put("receipt",preflight)
        from .ledger import build_ledger
        lineage=build_ledger(catalog,run_id=plan["run_id"],execution_mode=plan["execution_mode"],created_at=plan["created_at"])
        computed_head=lineage[-1]["hash"] if lineage else None
        require(upstream_head is None or upstream_head==computed_head,"LEDGER_BINDING","supplied head differs from verified lineage")
        return self.backend._transaction(key=plan["idempotency_key"],fingerprint=digest(operation),expected_version=plan["graph_version"],
                  operation=operation,catalog=catalog,apply=apply,authorization_hash=digest(authorization),preflight_hash=digest(preflight),
                  upstream_head=computed_head,fault=fault,at=at,lineage_prefix=lineage)
