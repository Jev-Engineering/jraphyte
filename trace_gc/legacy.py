"""Pinned legacy GraphStore bridge; the upstream store remains graph authority.

The bridge does not vendor upstream code. It verifies the exact Git blob from
the original source manifest before import. Runtime contracts, source status,
and audit sidecars are rechecked/written inside the *upstream* SQLite transaction,
using SQL hooks tied to that pinned implementation. There is no second current
accepted-graph table. Run the external conformance command before deployment.

Supported upstream atomic shapes: assertion additions, retractions, metadata /
schema proposals (audit-only graph revisions), and relation-schema migrations.
Mixed add/retract transactions and node-type migrations are rejected because the
pinned upstream public operation contract cannot express them atomically.
"""
from __future__ import annotations
import hashlib
import importlib.util
import sys
import threading
from copy import deepcopy
from dataclasses import asdict
from pathlib import Path
from typing import Any,Callable
from .backend import SQLiteReferenceBackend
from .canonical import digest,dumps,loads
from .catalog import Catalog
from .compiler import now
from .errors import ContractError,require
from .resolver import primary_observation

PINNED_CORE_BLOB="68217feec539d37e4a524432c93df035f9a0fe39"


def git_blob_hash(data: bytes) -> str:
    return hashlib.sha1(b"blob "+str(len(data)).encode()+b"\0"+data).hexdigest()


def load_pinned_core(path: str | Path):
    file=Path(path).resolve();raw=file.read_bytes()
    require(git_blob_hash(raw)==PINNED_CORE_BLOB,"UPSTREAM_PIN_MISMATCH","core.py does not match the reviewed Git blob")
    name="_trace_gc_pinned_upstream_"+PINNED_CORE_BLOB
    if name in sys.modules:return sys.modules[name]
    spec=importlib.util.spec_from_file_location(name,file)
    require(spec is not None and spec.loader is not None,"UPSTREAM_IMPORT","cannot load core.py")
    module=importlib.util.module_from_spec(spec);sys.modules[name]=module
    try:
        # Execute the exact verified bytes, not a second path read or cached .pyc.
        exec(compile(raw,str(file),"exec"),module.__dict__)
    except BaseException:sys.modules.pop(name,None);raise
    require(all(hasattr(module,n) for n in ("GraphStore","Policy","Relation","candidate","evidence","bind")),"UPSTREAM_API","required API missing")
    return module


class _TransactionConnection:
    """Hooks run after BEGIN, after idempotency lookup, and before actual COMMIT."""
    def __init__(self,db):
        self.raw=db;self.guard=None;self.finish=None;self.guarded=False;self.begin_guard=None
    def execute(self,sql,parameters=()):
        normalized=" ".join(sql.upper().split())
        if normalized == "BEGIN IMMEDIATE" and self.begin_guard is not None:
            result = self.raw.execute(sql, parameters)
            try:
                self.begin_guard()
            except BaseException:
                # Upstream BEGIN occurs before its try block. Release the lock
                # here if a fresh retry capability check fails.
                self.raw.execute("ROLLBACK")
                raise
            return result
        if self.guard is not None and self.raw.in_transaction and normalized=="SELECT BODY FROM STATE WHERE ID=1" and not self.guarded:
            self.guarded=True;self.guard()
        if self.finish is not None and normalized=="COMMIT" and self.guarded:self.finish()
        return self.raw.execute(sql,parameters)
    def __getattr__(self,name):return getattr(self.raw,name)


class PinnedLegacyBackend(SQLiteReferenceBackend):
    """Use with CompilerService, never by passing authority fields from a model.

    `legacy_policy` is explicit administrator configuration, not synthesized
    from scores or permissive defaults. `sandbox=True` is durably pinned.
    """
    def __init__(self,path: str | Path, *, core_path: str | Path,catalog: Catalog,schema_id: str,
                 nodes: dict[str,str],legacy_policy: dict[str,Any],sandbox: bool=False):
        self.core=load_pinned_core(core_path)
        self.path,self.sandbox=str(path),sandbox;self._lock=threading.RLock();self._nodes=deepcopy(nodes)
        require(set(legacy_policy)=={"version","thresholds","contracts","allowed_modes"},"UPSTREAM_POLICY","explicit upstream policy contract required")
        schema=catalog.get(schema_id,"schema")
        policy=self.core.Policy(**deepcopy(legacy_policy))
        self._store=self.core.GraphStore(self.path,{k:self.core.Relation(**v) for k,v in schema["relations"].items()},policy)
        self.db=_TransactionConnection(self._store.db);self._store.db=self.db
        self.db.executescript("""
        CREATE TABLE IF NOT EXISTS trace_meta(id INTEGER PRIMARY KEY CHECK(id=1),body TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS trace_records(id TEXT PRIMARY KEY,hash TEXT NOT NULL,kind TEXT NOT NULL,body TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS trace_erased(id TEXT PRIMARY KEY,hash TEXT NOT NULL,kind TEXT NOT NULL,reason TEXT NOT NULL,erased_at TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS trace_source_status(id TEXT PRIMARY KEY,body TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS trace_journal(version INTEGER PRIMARY KEY,key TEXT UNIQUE NOT NULL,fingerprint TEXT NOT NULL,body TEXT NOT NULL,hash TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS trace_evidence_alias(trace_id TEXT PRIMARY KEY,upstream_id TEXT UNIQUE NOT NULL,source_id TEXT NOT NULL);
        """)
        self.db.execute("BEGIN IMMEDIATE")
        try:
            previous=self.db.execute("SELECT body FROM trace_meta WHERE id=1").fetchone()
            if previous is None:
                require(self._store.snapshot()["version"]==0,"UPSTREAM_IMPORT_REQUIRED","existing graphs need an explicit reviewed provenance import")
                meta={"sandbox":sandbox,"core_blob":PINNED_CORE_BLOB,"legacy_policy_hash":digest(asdict(policy)),"schema_id":schema_id,
                      "metadata":{},"schema_proposals":{},"initial_nodes":deepcopy(nodes)}
                self.db.execute("INSERT INTO trace_meta VALUES(1,?)",(dumps(meta),));self._persist([catalog.record(schema_id)])
                initial=self.state();meta.update(genesis_state=initial,genesis_hash=digest(initial))
                self.db.execute("UPDATE trace_meta SET body=? WHERE id=1",(dumps(meta),))
            else:
                meta=loads(previous[0])
                require(meta["sandbox"]==sandbox and meta["core_blob"]==PINNED_CORE_BLOB,"BACKEND_MODE","backend mode/pin cannot be relabeled")
                require(meta["legacy_policy_hash"]==digest(asdict(policy)),"UPSTREAM_POLICY","policy changes require reviewed migration")
                require(meta["schema_id"]==schema_id,"SCHEMA_HASH","reopen using current runtime schema identity")
            self.db.execute("COMMIT")
        except BaseException:
            if self.db.in_transaction:self.db.execute("ROLLBACK")
            self.db.close();raise

    def _meta(self):return loads(self.db.execute("SELECT body FROM trace_meta WHERE id=1").fetchone()[0])

    def state(self) -> dict[str,Any]:
        raw=self._store.snapshot();meta=self._meta()
        schema=self.db.execute("SELECT hash,body FROM trace_records WHERE id=?",(meta["schema_id"],)).fetchone()
        require(schema is not None and loads(schema[1])["relations"]==raw["schema"],"SCHEMA_HASH","upstream/schema sidecar disagreement")
        aliases={upstream:trace for trace,upstream in self.db.execute("SELECT trace_id,upstream_id FROM trace_evidence_alias")}
        facts={}
        for ref,f in raw["facts"].items():
            require(set(f["evidence"])<=aliases.keys(),"UPSTREAM_IMPORT_REQUIRED","unknown upstream evidence alias")
            facts[ref]={"assertion":{"subject":f["subject"],"predicate":f["predicate"],"object":f["object"],"qualifiers":f["qualifiers"]},
                        "evidence_ids":sorted(aliases[x] for x in f["evidence"]),"prerequisites":f["depends_on"],"active":f["active"],"revision":1 if f["active"] else 2}
        result = {"graph_version":raw["version"],"schema_id":meta["schema_id"],"schema_hash":schema[0],"nodes":raw["nodes"],"assertions":facts,
                "source_epochs":{r:s["epoch"] for r,s in self.statuses().items()},"metadata":meta["metadata"],"schema_proposals":meta["schema_proposals"]}
        if "research_domains" in meta:
            result["research_domains"] = deepcopy(meta["research_domains"])
        return result

    def snapshot(self,catalog: Catalog) -> str:
        # The common snapshot hydrator calls this bridge's state() and reads
        # immutable sidecars; it never creates or reads a second trace_state.
        return SQLiteReferenceBackend.snapshot(self, catalog)

    def _lower(self,operation,catalog):
        from .domain_publication import MIGRATE, PUBLISH
        if operation.get("action") in {MIGRATE, PUBLISH}:
            # The trusted apply closure verifies exact signed classification
            # bytes. An empty upstream commit supplies the same atomic revision
            # and journal boundary as existing audit-only metadata operations.
            return None, [], [], []
        if "plan_hash" not in operation:return None,[],[],[]
        matches=[r for r in catalog.all("plan") if r["hash"]==operation["plan_hash"]]
        require(len(matches)==1,"TRANSACTION_PLAN_BINDING","exact immutable plan required")
        plan=matches[0]["body"];ops=plan["operations"]
        kinds={op["operation"] for op in ops}
        families={"add" if k.startswith("ADD_") else "retract" if k=="RETRACT_ASSERTION" else "migrate" if k=="APPLY_SCHEMA_MIGRATION" else "audit" for k in kinds}
        require(len(families)==1,"UPSTREAM_ATOMIC_SHAPE","pinned upstream cannot atomically combine these operation families")
        if "migrate" in families:
            require(len(ops)==1 and not ops[0]["mapping"],"UPSTREAM_NODE_MIGRATION_UNSUPPORTED","upstream migration only changes relation schema")
        sources={};facts=[];aliases=[]
        for op in ops:
            if not op["operation"].startswith("ADD_"):continue
            mapped=[]
            for ref in op["evidence_ids"]:
                e=catalog.get(ref,"evidence");s=catalog.get(e["source_snapshot_id"],"source")
                lowered=self.core.evidence(s["source_id"],s["version"],s["text"],origin=e["source_snapshot_id"],start=e["start"],end=e["end"])
                sources[lowered["id"]]=lowered;mapped.append(lowered["id"]);aliases.append((ref,lowered["id"],e["source_snapshot_id"]))
            c=catalog.get(op["candidate_id"],"candidate");evaluation=catalog.get(op["evaluation_id"],"evaluation")
            observation=primary_observation(catalog,op["candidate_id"],evaluation["observation_ids"])
            require(observation is not None,"MISSING_OBSERVATION",op["id"])
            item=self.core.candidate(op["assertion_id"],c["assertion"]["subject"],c["assertion"]["predicate"],c["assertion"]["object"],mapped,
                                     depends_on=op["prerequisite_ids"],qualifiers=c["assertion"]["qualifiers"])
            facts.append(self.core.bind(item,observation["probabilities"],observation["semantic_outcome"],model=observation["model_requested"],
                mode=observation["execution_mode"].lower(),request_hash=observation["wire_request_hash"],policy_version=self._store.policy.version,
                labels=self._store.policy.contracts[c["assertion"]["predicate"]]))
        return plan,list(sources.values()),facts,aliases

    def _transaction(self, *, key, fingerprint, expected_version, operation, catalog, apply,
                     authorization_hash,preflight_hash,upstream_head=None,fault=None,at=None,lineage_prefix=None,replay_guard=None):
        require(bool(key) and type(expected_version) is int and expected_version>=0,"TRANSACTION_INPUT","explicit key/version required")
        plan,sources,facts,aliases=self._lower(operation,catalog)
        when=at or now();result={};prospective={};before=None
        def guard():
            nonlocal before,prospective,when
            when = at or now()
            current=self.state()
            require(current["graph_version"]==expected_version,"STALE_GRAPH_VERSION","upstream CAS mismatch")
            require(self.db.execute("SELECT COUNT(*) FROM trace_journal").fetchone()[0]==expected_version,"UPSTREAM_UNMEDIATED_WRITE","upstream contains an unbound write")
            before=digest(current);prospective=apply(deepcopy(current),deepcopy(self.statuses()))
            if expected_version==0 and operation.get("action")=="ADMIT":prospective["nodes"].update(self._nodes)
            self._persist(catalog.all())
            for trace,upstream,source in aliases:
                old=self.db.execute("SELECT upstream_id,source_id FROM trace_evidence_alias WHERE trace_id=?",(trace,)).fetchone()
                require(old is None or old==(upstream,source),"IMMUTABLE_RECORD","evidence alias changed")
                self.db.execute("INSERT OR IGNORE INTO trace_evidence_alias VALUES(?,?,?)",(trace,upstream,source))
        def finish():
            # Upstream has updated its state and inserted its journal row, but has not committed.
            if fault:fault("before_state_write")
            meta=self._meta();meta.update(schema_id=prospective["schema_id"],metadata=prospective["metadata"],schema_proposals=prospective["schema_proposals"])
            if "research_domains" in prospective:
                meta["research_domains"] = deepcopy(prospective["research_domains"])
            self.db.execute("UPDATE trace_meta SET body=? WHERE id=1",(dumps(meta),))
            current=self.state();expected=deepcopy(prospective);expected["graph_version"]+=1
            expected["source_epochs"]={ref:s["epoch"] for ref,s in self.statuses().items()}
            require(current==expected,"UPSTREAM_RESULT_MISMATCH","upstream result differs from deterministically validated plan")
            row=self.db.execute("SELECT version,hash FROM journal WHERE key=?",(key,)).fetchone()
            require(row is not None and row[0]==current["graph_version"],"UPSTREAM_JOURNAL","atomic upstream journal row missing")
            head=self.db.execute("SELECT hash FROM trace_journal ORDER BY version DESC LIMIT 1").fetchone();previous=head[0] if head else None
            core={"version":row[0],"idempotency_key":key,"fingerprint":fingerprint,"before_hash":before,"after_hash":digest(current),
                  "state_after":current,"source_status":self.statuses(),"operation":operation,"record_hashes":{r["id"]:r["hash"] for r in catalog.all()},
                  "authorization_hash":authorization_hash,"preflight_hash":preflight_hash,"previous_hash":previous,"upstream_head":upstream_head,
                  "committed_at":when,"lineage_prefix":deepcopy(lineage_prefix or []),"upstream_journal_hash":row[1],"upstream_core_blob":PINNED_CORE_BLOB}
            eh=digest(core)
            receipt={"backend":"pinned-legacy-v1","version":row[0],"idempotency_key":key,"plan_hash":operation.get("plan_hash",digest(operation)),
                     "before_hash":before,"after_hash":digest(current),"previous_hash":previous,"event_hash":eh,"operation_hash":digest(operation),
                     "authorization_hash":authorization_hash,"preflight_hash":preflight_hash,"upstream_head":upstream_head,"committed_at":when}
            h=digest({"kind":"transaction","body":receipt});record={"id":f"transaction:{h}","kind":"transaction","hash":h,"body":receipt}
            self._persist([record]);event={**core,"hash":eh,"transaction_receipt":receipt}
            if fault:fault("after_state_write")
            self.db.execute("INSERT INTO trace_journal VALUES(?,?,?,?,?)",(row[0],key,fingerprint,dumps(event),eh))
            from .retrieval.domain_projection import update_installed_index
            update_installed_index(self, current)
            if fault:fault("after_journal_write");fault("before_commit")
            result.update(event=event,record=record)
        def begin_guard():
            if replay_guard is not None:
                replay_guard()
            previous = self.db.raw.execute("SELECT fingerprint FROM trace_journal WHERE key=?", (key,)).fetchone()
            require(previous is None or previous[0] == fingerprint, "IDEMPOTENCY_CONFLICT",
                    "same key, different immutable bridge action")
        with self._lock:
            self.db.guard,self.db.finish,self.db.guarded=guard,finish,False
            self.db.begin_guard = begin_guard
            try:
                if plan and plan["operations"][0]["operation"]=="RETRACT_ASSERTION":
                    self._store.retract(fact_ids=[o["assertion_id"] for o in plan["operations"]],expected_version=expected_version,key=key,reason="; ".join(o["reason"] for o in plan["operations"]))
                elif plan and plan["operations"][0]["operation"]=="APPLY_SCHEMA_MIGRATION":
                    op=plan["operations"][0];schema=catalog.get(op["target_schema_id"],"schema")
                    self._store.migrate({k:self.core.Relation(**v) for k,v in schema["relations"].items()},schema_version=schema["version"],
                        reviewed_by="external-verified-receipt:"+authorization_hash,reason=op["reason"],expected_version=expected_version,key=key)
                elif operation.get("action") in {"STATUS_CHANGE","ERASE"}:
                    status=self.statuses().get(operation["source_id"])
                    require(not (operation["active"] and operation["permission"]=="READ" and status and
                            (not status["active"] or status["permission"]!="READ")),"UPSTREAM_REACTIVATION_UNSUPPORTED","withdrawal is permanent for upstream evidence; use a new source snapshot")
                    evidence=[r[0] for r in self.db.execute("SELECT upstream_id FROM trace_evidence_alias WHERE source_id=?",(operation["source_id"],))]
                    self._store.retract(evidence_ids=evidence,expected_version=expected_version,key=key,reason=operation["reason"])
                else:
                    self._store.commit(nodes=self._nodes if expected_version==0 and operation.get("action")=="ADMIT" else {},sources=sources,
                                       facts=facts,expected_version=expected_version,key=key)
                if not result:
                    row=self.db.execute("SELECT fingerprint,body FROM trace_journal WHERE key=?",(key,)).fetchone()
                    require(row is not None and row[0]==fingerprint,"IDEMPOTENCY_CONFLICT","same upstream action but different immutable plan")
                    event=loads(row[1]);return {"replayed":True,"event":event,"receipt":event["transaction_receipt"]}
                catalog.add(result["record"])
                return {"replayed":False,"event":result["event"],"receipt":result["event"]["transaction_receipt"]}
            except ValueError as exc:
                if isinstance(exc,ContractError):raise
                raise ContractError("UPSTREAM_CONTRACT",str(exc)) from exc
            finally:
                self.db.guard=self.db.finish=self.db.begin_guard=None
                self.db.guarded=False

    def audit(self):
        upstream=self._store.audit();meta=self._meta();previous=None;after=meta["genesis_hash"];count=0;last_status={}
        for version,key,fingerprint,text,h in self.db.execute("SELECT version,key,fingerprint,body,hash FROM trace_journal ORDER BY version"):
            event=loads(text);count+=1;core={k:v for k,v in event.items() if k not in {"hash","transaction_receipt"}}
            require(version==count and event["previous_hash"]==previous and event["before_hash"]==after and digest(core)==h==event["hash"],"BACKEND_AUDIT","bridge chain differs")
            row=self.db.execute("SELECT hash FROM journal WHERE version=? AND key=?",(version,key)).fetchone()
            require(row and row[0]==event["upstream_journal_hash"] and event["upstream_core_blob"]==PINNED_CORE_BLOB,"UPSTREAM_JOURNAL","atomic graph/lineage binding differs")
            require(event["fingerprint"]==fingerprint and digest(event["state_after"])==event["after_hash"],"BACKEND_AUDIT","bridge state hash differs")
            for ref,hash_ in event["record_hashes"].items():
                r=self.db.execute("SELECT hash,kind,body FROM trace_records WHERE id=?",(ref,)).fetchone()
                if r:require(r[0]==hash_==digest({"kind":r[1],"body":loads(r[2])}),"BACKEND_AUDIT","record changed")
                else:
                    erased=self.db.execute("SELECT hash FROM trace_erased WHERE id=?",(ref,)).fetchone()
                    require(erased and erased[0]==hash_,"BACKEND_AUDIT","record missing without tombstone")
            previous,after,last_status=h,event["after_hash"],event["source_status"]
        require(count==upstream["events"] and digest(self.state())==after and last_status==self.statuses(),"BACKEND_AUDIT","unmediated graph/status write")
        return {"events":count,"head_hash":previous,"state_hash":after,"sandbox":self.sandbox,"upstream":upstream,
                "core_blob":PINNED_CORE_BLOB,"erased_record_count":self.db.execute("SELECT COUNT(*) FROM trace_erased").fetchone()[0]}
