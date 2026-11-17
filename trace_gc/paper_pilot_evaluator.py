"""Public aggregate PaperPilot evaluator with operator-private receipt input.

``export_receipts`` reads an already opened ``PaperPilot`` (whose constructor has
verified the checkpoint chain, blobs and backend journal) and projects its
durable requests plus *current* backend source/assertion status into sanitized
rows. ``evaluate`` compares those rows with a frozen evaluation protocol and
reports PASS/FAIL/HOLD/NOT_RUN/INVALIDATED rows with explicit denominators.

The report is unsigned aggregate arithmetic. It does not authenticate the
receipt file, judge entailment, or qualify issue #23; claim support comes only
from the attributed answer reviews already recorded by the pilot. A SYNTHETIC
run is labelled mechanics-only regardless of its verdict.
"""
from __future__ import annotations

from pathlib import Path
import re

from .canonical import bytes_digest, digest, text_digest
from .errors import boundary, require
from .paper_ingestion import REPRESENTATION as NATIVE
from .pdf_image_evidence import REPRESENTATION as IMAGE
from .retrieval.security import AccessFilter

VERSION = "paper-pilot-aggregate-evaluator-v1"
RECEIPTS_VERSION = "paper-pilot-receipts-v1"
PROTOCOL_VERSION = "paper-pilot-evaluation-protocol-v1"
EXPECTATIONS = ("SUPPORTED", "ABSTAIN")
RECOVERY_STATUSES = ("PASS", "FAIL", "HOLD")
REPRESENTATIONS = {NATIVE, IMAGE}
RECOVERY_EVIDENCE = ("AUTHORED_SYNTHETIC", "REAL_RUN")
ROW_STATUSES = ("PASS", "FAIL", "HOLD", "NOT_RUN", "INVALIDATED")
_HEX = re.compile(r"[0-9a-f]{64}")
_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9:._/-]{0,199}")
_ABSTAIN = {"ABSTAIN_NO_AUTHORIZED_EVIDENCE": "NO_AUTHORIZED_EVIDENCE", "ABSTAIN_MODEL": "MODEL_ABSTAINED"}

_ANSWER_STATES = {*_ABSTAIN, "INTENT_PENDING", "CONTEXT_ONLY", "WAIT_ANSWER_RESPONSE",
                  "WAIT_ANSWER_REVIEW", "SUPPORTED", "REJECTED_UNSUPPORTED_CLAIM"}


def evaluator_identity() -> dict:
    return {"version": VERSION, "code_sha256": bytes_digest(Path(__file__).read_bytes())}


def question_sha256(text: str) -> str:
    """Protocols and receipts name questions by hash so reports carry no question text."""
    return text_digest(text)


def _sha(value, path):
    require(type(value) is str and _HEX.fullmatch(value) is not None, "EVALUATOR_INPUT", "lowercase SHA-256", path=path)


def _ident(value, path):
    require(type(value) is str and _ID.fullmatch(value) is not None, "EVALUATOR_INPUT", "bounded identifier", path=path)


def _keys(value, keys, path):
    require(type(value) is dict and set(value) == set(keys), "EVALUATOR_INPUT", "exact fields required", path=path)


def _opt(value, check, path):
    if value is not None:
        check(value, path)


def _ids(values, path, *, nonempty=False):
    require(type(values) is list and (bool(values) or not nonempty),
            "EVALUATOR_INPUT", "identifier list required", path=path)
    for i, value in enumerate(values):
        _ident(value, f"{path}[{i}]")
    require(len(values) == len(set(values)), "EVALUATOR_INPUT", "duplicate identifier", path=path)


def _bool(value, path, *, nullable=False):
    require(type(value) is bool or (nullable and value is None), "EVALUATOR_INPUT", "boolean required", path=path)


# --------------------------------------------------------------------------- export

def _completed(pilot, kind):
    return [r for r in pilot.requests.values() if r["kind"] == kind and "result" in r]


def _evidence_row(pilot, evidence_id):
    evidence = pilot.catalog.get(evidence_id, "evidence")
    source = pilot.catalog.get(evidence["source_snapshot_id"], "source")
    page = page_png = crop_png = None
    if source["representation"] == IMAGE:
        image = pilot.catalog.get(source["image_evidence_id"], "image-evidence-v1")
        page, page_png, crop_png = image["physical_page"], image["render"]["page_png_sha256"], image["crop"]["png_sha256"]
    elif "page_lineage" in source:
        lineage = source["page_lineage"]
        page, page_png = lineage["physical_page"], lineage["page_png_sha256"]
    return {"evidence_id": evidence_id, "evidence_sha256": pilot.catalog.hash(evidence_id),
            "source_snapshot_id": evidence["source_snapshot_id"], "source_id": source["source_id"],
            "source_hash": evidence["source_hash"], "representation": source["representation"],
            "raw_document_sha256": source["raw_document_hash"], "physical_page": page,
            "page_png_sha256": page_png, "crop_png_sha256": crop_png,
            "currently_readable": True}


def _assertion_row(pilot, assertion_id, state, journal, evidence_refs, acl):
    row = state["assertions"][assertion_id]
    refs = [evidence_refs[ref] for ref in row["evidence_ids"]]
    result = {"assertion_id": assertion_id, "active": row["active"], "evidence_ids": refs}
    chain = {"transaction_event_hash": None, "transaction_version": None, "plan_id": None,
             "resolution_id": None, "resolution_outcome": None, "observation_ids": [], "observations_ok": False}
    if not acl.edge(assertion_id, row):
        return {**result, **chain, "currently_readable": False}
    for publish in _completed(pilot, "PUBLISH"):
        preflight = pilot.requests[publish["args"]["preflight_id"]]["result"]
        plan_id = pilot.requests[preflight["resolve_id"]]["result"]["plan_id"]
        ops = [o for o in pilot.catalog.get(plan_id, "plan")["operations"]
               if o["operation"] == "ADD_ASSERTION" and o["candidate_id"] == assertion_id]
        if not ops:
            continue
        receipt = publish["result"]["receipt"]
        resolution = pilot.catalog.get(ops[0]["resolution_id"], "resolution")
        observations = resolution["observation_ids"]
        chain = {"transaction_event_hash": receipt["event_hash"] if journal.get(receipt["event_hash"]) == receipt and
                     receipt["plan_hash"] == pilot.catalog.hash(plan_id) else None,
                 "transaction_version": receipt["version"], "plan_id": plan_id,
                 "resolution_id": ops[0]["resolution_id"], "resolution_outcome": resolution["outcome"],
                 "observation_ids": list(observations),
                 "observations_ok": bool(observations) and all(
                     pilot.catalog.get(o, "observation")["status"] == "OK" for o in observations)}
    return {**result, **chain, "currently_readable": True}


def _answer_rows(pilot, current_stamp, graph_version):
    by_arg = {}
    for request in pilot.requests.values():
        for field in ("retrieval_id", "prepared_id", "response_id"):
            if field in request["args"] and request["kind"] in {"PREPARE_ANSWER", "ANSWER_RESPONSE", "REVIEW_ANSWER"}:
                by_arg.setdefault((field, request["args"][field]), []).append(request)
    rows = []
    for retrieval in [r for r in pilot.requests.values() if r["kind"] == "RETRIEVE"]:
        chain = {"retrieval_id": retrieval["id"], "prepare_id": None, "response_id": None, "review_id": None}
        last = retrieval
        for field, slot in (("retrieval_id", "prepare_id"), ("prepared_id", "response_id"), ("response_id", "review_id")):
            if "result" not in last:
                break
            following = by_arg.get((field, last["id"]), [])
            if not following:
                break
            last = following[-1]
            chain[slot] = last["id"]
        state = last.get("result", {}).get("state", "INTENT_PENDING")
        retrieved = retrieval.get("result")
        claims, reviewer_kind = [], None
        retrieval_version = (pilot.catalog.get(retrieved["context_id"], "graphrag-answer")["graph_version"]
                             if retrieved is not None else None)
        answer_version = retrieval_version
        response = pilot.requests.get(chain["response_id"] or "", {}).get("result")
        if response is not None:
            require(retrieval_version == response["draft"]["graph_version"],
                    "EVALUATOR_INPUT", "response graph version differs from retrieval")
            review = pilot.requests.get(chain["review_id"] or "", {}).get("result")
            support = review["review"]["claim_support"] if review else [None] * len(response["draft"]["claims"])
            reviewer_kind = review["review"]["reviewer_kind"] if review else None
            claims = [{"evidence_ids": list(c["evidence_ids"]), "support": s}
                      for c, s in zip(response["draft"]["claims"], support)]
        prepared = pilot.requests.get(chain["prepare_id"] or "", {}).get("result")
        if prepared is not None and "draft" in prepared:
            require(retrieval_version == prepared["draft"]["graph_version"],
                    "EVALUATOR_INPUT", "prepared graph version differs from retrieval")
        rows.append({**chain, "question_sha256": text_digest(retrieval["args"]["request"]["text"]), "state": state,
                     "abstention_reason": _ABSTAIN.get(state), "claims": claims, "reviewer_kind": reviewer_kind,
                     "answer_graph_version": answer_version,
                     "retrieval_context_current": retrieved is not None and retrieved["stamp"] == current_stamp,
                     "graph_version_current": answer_version is not None and answer_version == graph_version})
    return rows


@boundary
def export_receipts(pilot) -> dict:
    """Sanitized receipt rows from an opened PaperPilot and its current backend state."""
    checkpoint_head = pilot._head
    audit = pilot.backend.audit()
    state, statuses = pilot.backend.state(), pilot.backend.statuses()
    current_stamp = pilot._stamp()
    access = pilot._access()
    acl = AccessFilter(access, pilot.catalog, statuses)
    journal = {r["body"]["event_hash"]: r["body"] for r in pilot.backend.load_catalog().all("transaction")}
    reviews = []
    for request in _completed(pilot, "REVIEW_SOURCE") + _completed(pilot, "REVIEW_SOURCE_IMAGE"):
        payload = request["args"]["receipt"]["payload"]
        source = pilot.catalog.get(request["result"]["source_id"], "source")
        snapshot = request["result"]["source_id"]
        status = statuses.get(snapshot)
        readable = (acl.allows("source", snapshot) and source["security_scope"] == access["tenant"]
                    and status is not None and status["permission"] == "READ" and status["active"]
                    and not status["tombstone"])
        reviews.append({"request_id": request["id"] if readable else None,
                        "source_snapshot_id": snapshot if readable else None,
                        "source_id": source["source_id"] if readable else None,
                        "representation": source["representation"] if readable else None,
                        "reviewer_kind": payload["reviewer_kind"],
                        "all_checks_passed": all(v is True for v in payload["checks"].values()),
                        "independent_review": False})
    answers = _answer_rows(pilot, current_stamp, state["graph_version"])
    cited = sorted({e for a in answers for c in a["claims"] for e in c["evidence_ids"]} |
                   {e for row in state["assertions"].values() for e in row["evidence_ids"]})
    evidence = []
    evidence_refs = {}
    for ref in cited:
        if acl.evidence(ref):
            evidence_refs[ref] = ref
            evidence.append(_evidence_row(pilot, ref))
        else:
            marker = f"denied:{len(evidence)}"
            evidence_refs[ref] = marker
            evidence.append({"evidence_id": marker, "currently_readable": False})
    for answer in answers:
        for claim in answer["claims"]:
            claim["evidence_ids"] = [evidence_refs[ref] for ref in claim["evidence_ids"]]
    assertions = [_assertion_row(pilot, ref, state, journal, evidence_refs, acl)
                  for ref in sorted(state["assertions"])]
    require(state["graph_version"] == audit["events"] and digest(state) == audit["state_hash"] and
            digest(statuses) == current_stamp["statuses_sha256"] and
            digest(access) == current_stamp["access_sha256"] and pilot._stamp() == current_stamp and
            pilot.backend.audit() == audit and pilot._head == checkpoint_head,
            "EVALUATOR_INPUT", "pilot checkpoint or graph changed during export")
    return {"version": RECEIPTS_VERSION, "run_id": pilot.config["run_id"],
            "execution_mode": pilot.config["execution_mode"], "checkpoint_head": checkpoint_head,
            "graph": {"graph_version": state["graph_version"], "journal_head": audit["head_hash"],
                      "state_sha256": audit["state_hash"]},
            "source_reviews": reviews,
            "assertions": assertions, "evidence": evidence,
            "answers": answers, "provider_calls_by_exporter": 0}


# --------------------------------------------------------------------------- validation

def _validate_protocol(protocol):
    _keys(protocol, {"version", "protocol_id", "questions", "expected_assertions", "required_recovery"}, "protocol")
    require(protocol["version"] == PROTOCOL_VERSION, "EVALUATOR_INPUT", "protocol version", path="protocol.version")
    _ident(protocol["protocol_id"], "protocol.protocol_id")
    require(type(protocol["questions"]) is list and bool(protocol["questions"]), "EVALUATOR_INPUT",
            "frozen questions required", path="protocol.questions")
    for i, q in enumerate(protocol["questions"]):
        path = f"protocol.questions[{i}]"
        _keys(q, {"question_sha256", "expectation", "required_source_ids"}, path)
        _sha(q["question_sha256"], path + ".question_sha256")
        require(q["expectation"] in EXPECTATIONS, "EVALUATOR_INPUT", "expectation", path=path)
        _ids(q["required_source_ids"], path + ".required_source_ids", nonempty=q["expectation"] == "SUPPORTED")
        require(q["expectation"] == "SUPPORTED" or not q["required_source_ids"], "EVALUATOR_INPUT",
                "abstention questions cite no required source", path=path)
    require(len({q["question_sha256"] for q in protocol["questions"]}) == len(protocol["questions"]),
            "EVALUATOR_INPUT", "duplicate question", path="protocol.questions")
    _ids(protocol["expected_assertions"], "protocol.expected_assertions")
    _ids(protocol["required_recovery"], "protocol.required_recovery")


def _validate_receipts(receipts):
    _keys(receipts, {"version", "run_id", "execution_mode", "checkpoint_head", "graph", "source_reviews",
                     "assertions", "evidence", "answers", "provider_calls_by_exporter"}, "receipts")
    require(receipts["version"] == RECEIPTS_VERSION and receipts["execution_mode"] in ("LIVE", "SYNTHETIC") and
            type(receipts["provider_calls_by_exporter"]) is int and receipts["provider_calls_by_exporter"] == 0,
            "EVALUATOR_INPUT", "receipt header", path="receipts")
    _ident(receipts["run_id"], "receipts.run_id")
    _sha(receipts["checkpoint_head"], "receipts.checkpoint_head")
    _keys(receipts["graph"], {"graph_version", "journal_head", "state_sha256"}, "receipts.graph")
    version, journal_head = receipts["graph"]["graph_version"], receipts["graph"]["journal_head"]
    require(type(version) is int and version >= 0 and (version == 0) == (journal_head is None),
            "EVALUATOR_INPUT", "graph version and journal head", path="receipts.graph")
    _opt(journal_head, _sha, "receipts.graph.journal_head")
    _sha(receipts["graph"]["state_sha256"], "receipts.graph.state_sha256")
    for name in ("source_reviews", "assertions", "evidence", "answers"):
        require(type(receipts[name]) is list, "EVALUATOR_INPUT", "receipt rows must be an array",
                path="receipts." + name)
    for i, r in enumerate(receipts["source_reviews"]):
        path = f"receipts.source_reviews[{i}]"
        _keys(r, {"request_id", "source_snapshot_id", "source_id", "representation", "reviewer_kind",
                  "all_checks_passed", "independent_review"}, path)
        lineage_fields = ("request_id", "source_snapshot_id", "source_id", "representation")
        if any(r[field] is not None for field in lineage_fields):
            for field in lineage_fields:
                _ident(r[field], f"{path}.{field}")
            require(r["representation"] in REPRESENTATIONS, "EVALUATOR_INPUT",
                    "unsupported evidence representation", path=path)
        require(r["reviewer_kind"] in ("assistant", "human") and r["independent_review"] is False,
                "EVALUATOR_INPUT", "attributed non-independent review", path=path)
        _bool(r["all_checks_passed"], path)
    for i, a in enumerate(receipts["assertions"]):
        path = f"receipts.assertions[{i}]"
        _keys(a, {"assertion_id", "active", "evidence_ids", "transaction_event_hash",
                  "transaction_version", "plan_id", "resolution_id", "resolution_outcome",
                  "observation_ids", "observations_ok", "currently_readable"}, path)
        _ident(a["assertion_id"], path)
        _bool(a["currently_readable"], path)
        _bool(a["active"], path); _bool(a["observations_ok"], path)
        _ids(a["evidence_ids"], path + ".evidence_ids"); _ids(a["observation_ids"], path + ".observation_ids")
        _opt(a["transaction_event_hash"], _sha, path)
        require(a["transaction_version"] is None or type(a["transaction_version"]) is int, "EVALUATOR_INPUT", "version", path=path)
        for field in ("plan_id", "resolution_id", "resolution_outcome"):
            _opt(a[field], _ident, f"{path}.{field}")
    for i, e in enumerate(receipts["evidence"]):
        path = f"receipts.evidence[{i}]"
        require(type(e) is dict, "EVALUATOR_INPUT", "evidence row required", path=path)
        _bool(e.get("currently_readable"), path)
        if not e["currently_readable"]:
            _keys(e, {"evidence_id", "currently_readable"}, path)
            _ident(e["evidence_id"], path)
            continue
        _keys(e, {"evidence_id", "evidence_sha256", "source_snapshot_id", "source_id", "source_hash",
                  "representation", "raw_document_sha256", "physical_page", "page_png_sha256",
                  "crop_png_sha256", "currently_readable"}, path)
        for field in ("evidence_id", "source_snapshot_id", "source_id", "representation"):
            _ident(e[field], f"{path}.{field}")
        require(e["representation"] in REPRESENTATIONS, "EVALUATOR_INPUT",
                "unsupported evidence representation", path=path)
        for field in ("evidence_sha256", "source_hash", "raw_document_sha256"):
            _sha(e[field], f"{path}.{field}")
        for field in ("page_png_sha256", "crop_png_sha256"):
            _opt(e[field], _sha, f"{path}.{field}")
        require(e["physical_page"] is None or (type(e["physical_page"]) is int and e["physical_page"] > 0),
                "EVALUATOR_INPUT", "physical page", path=path)
    for i, a in enumerate(receipts["answers"]):
        path = f"receipts.answers[{i}]"
        fields = {"retrieval_id", "prepare_id", "response_id", "review_id", "question_sha256", "state",
                  "abstention_reason", "claims", "reviewer_kind", "answer_graph_version", "graph_version_current"}
        if type(a) is dict and "retrieval_context_current" in a:
            fields.add("retrieval_context_current")
            _bool(a["retrieval_context_current"], f"{path}.retrieval_context_current")
        _keys(a, fields, path)
        _ident(a["retrieval_id"], path)
        for field in ("prepare_id", "response_id", "review_id"):
            _opt(a[field], _ident, f"{path}.{field}")
        state = a["state"]
        require(type(state) is str and state in _ANSWER_STATES and
                a["abstention_reason"] == _ABSTAIN.get(state),
                "EVALUATOR_INPUT", "answer state and abstention reason", path=path)
        _sha(a["question_sha256"], path + ".question_sha256")
        require(a["reviewer_kind"] in (None, "assistant", "human") and
                (a["answer_graph_version"] is None or type(a["answer_graph_version"]) is int),
                "EVALUATOR_INPUT", "answer review/version", path=path)
        _bool(a["graph_version_current"], path)
        version = a["answer_graph_version"]
        require(a["graph_version_current"] == (version is not None and
                version == receipts["graph"]["graph_version"]),
                "EVALUATOR_INPUT", "answer graph version consistency", path=path)
        require(type(a["claims"]) is list, "EVALUATOR_INPUT", "claims", path=path)
        require(state not in _ABSTAIN or not a["claims"], "EVALUATOR_INPUT",
                "abstention cannot carry claims", path=path)
        for j, c in enumerate(a["claims"]):
            _keys(c, {"evidence_ids", "support"}, f"{path}.claims[{j}]")
            _ids(c["evidence_ids"], f"{path}.claims[{j}].evidence_ids", nonempty=True)
            _bool(c["support"], f"{path}.claims[{j}]", nullable=True)
    for name, keys in (("assertions", ("assertion_id",)), ("evidence", ("evidence_id",)),
                       ("source_reviews", ("request_id",)),
                       ("answers", ("retrieval_id", "prepare_id", "response_id", "review_id"))):
        for key in keys:
            refs = [row[key] for row in receipts[name] if row[key] is not None]
            require(len(refs) == len(set(refs)), "EVALUATOR_INPUT", "duplicate row", path="receipts." + name)


def _validate_recovery(rows, protocol):
    require(type(rows) is list, "EVALUATOR_INPUT", "recovery rows", path="recovery")
    for i, r in enumerate(rows):
        path = f"recovery[{i}]"
        _keys(r, {"scenario", "status", "receipt_sha256", "evidence_class"}, path)
        require(r["scenario"] in protocol["required_recovery"], "EVALUATOR_INPUT", "undeclared scenario", path=path)
        require(r["status"] in RECOVERY_STATUSES and r["evidence_class"] in RECOVERY_EVIDENCE,
                "EVALUATOR_INPUT", "recovery status/class", path=path)
        _sha(r["receipt_sha256"], path + ".receipt_sha256")
    require(len({r["scenario"] for r in rows}) == len(rows), "EVALUATOR_INPUT", "duplicate scenario", path="recovery")


# --------------------------------------------------------------------------- evaluation

def _summary(rows):
    counts = {s: 0 for s in ROW_STATUSES}
    for row in rows:
        counts[row["status"]] += 1
    return {"denominator": len(rows), **{k.lower(): v for k, v in counts.items()}}


def _chain(evidence, ref):
    e = evidence.get(ref)
    if e is None:
        return "MISSING_EVIDENCE"
    if not e["currently_readable"]:
        return "SOURCE_NOT_CURRENTLY_READABLE"
    if e["physical_page"] is None or e["page_png_sha256"] is None:
        return "MISSING_PAGE_LINEAGE"
    if e["representation"] == IMAGE and e["crop_png_sha256"] is None:
        return "MISSING_CROP_LINEAGE"
    return None


def _question(q, attempt, evidence):
    row = {"question_sha256": q["question_sha256"], "expectation": q["expectation"]}
    if attempt is None:
        return {**row, "status": "NOT_RUN", "reason": "NO_ANSWER_ATTEMPT"}
    row.update(retrieval_id_sha256=text_digest(attempt["retrieval_id"]), state=attempt["state"])
    state = attempt["state"]
    if state in _ABSTAIN:
        expected_response = state == "ABSTAIN_MODEL"
        if (attempt["prepare_id"] is None or (attempt["response_id"] is not None) != expected_response or
                attempt["review_id"] is not None or attempt["reviewer_kind"] is not None):
            return {**row, "status": "FAIL", "reason": "INCOMPLETE_ABSTENTION_STAGE"}
        if not attempt["graph_version_current"] or attempt.get("retrieval_context_current") is not True:
            return {**row, "status": "HOLD", "reason": "ABSTENTION_CONTEXT_REFRESH_REQUIRED"}
        reason = _ABSTAIN[state]
        if q["expectation"] == "ABSTAIN":
            return {**row, "status": "PASS", "reason": reason}
        return {**row, "status": "FAIL", "reason": "ABSTAINED_ON_SUPPORTED_QUESTION:" + reason}
    if q["expectation"] == "ABSTAIN":
        if state in {"SUPPORTED", "WAIT_ANSWER_REVIEW", "REJECTED_UNSUPPORTED_CLAIM"}:
            return {**row, "status": "FAIL", "reason": "ANSWERED_UNSUPPORTED_QUESTION"}
        return {**row, "status": "HOLD", "reason": "PENDING:" + state}
    if state == "REJECTED_UNSUPPORTED_CLAIM":
        return {**row, "status": "FAIL", "reason": "REVIEW_REJECTED_CLAIM"}
    if state != "SUPPORTED":
        return {**row, "status": "HOLD", "reason": "PENDING:" + state}
    problems = {_chain(evidence, ref) for c in attempt["claims"] for ref in c["evidence_ids"]} - {None}
    if not all(attempt[key] for key in ("prepare_id", "response_id", "review_id", "reviewer_kind")):
        return {**row, "status": "FAIL", "reason": "INCOMPLETE_ANSWER_REVIEW_CHAIN"}
    if not attempt["claims"] or not all(c["support"] is True for c in attempt["claims"]):
        return {**row, "status": "FAIL", "reason": "SUPPORT_JUDGMENT_INCOMPLETE"}
    if problems == {"SOURCE_NOT_CURRENTLY_READABLE"}:
        return {**row, "status": "INVALIDATED", "reason": "CITED_SOURCE_WITHDRAWN_OR_DENIED"}
    if problems:
        return {**row, "status": "FAIL", "reason": "INCOMPLETE_CITATION_CHAIN:" + ",".join(sorted(problems))}
    cited = {evidence[ref]["source_id"] for c in attempt["claims"] for ref in c["evidence_ids"]}
    missing = sorted(set(q["required_source_ids"]) - cited)
    if missing:
        return {**row, "status": "FAIL", "reason": "REQUIRED_SOURCE_NOT_CITED", "missing_source_id_sha256": sorted(text_digest(ref) for ref in missing)}
    if not attempt["graph_version_current"] or attempt.get("retrieval_context_current") is not True:
        return {**row, "status": "HOLD", "reason": "GRAPH_CHANGED_AFTER_ANSWER_REFRESH_REQUIRED"}
    return {**row, "status": "PASS", "reason": "SUPPORTED_WITH_COMPLETE_CURRENT_CHAINS"}


def _assertion(ref, rows, evidence, graph):
    row = rows.get(ref)
    if row is None:
        return {"assertion_id_sha256": text_digest(ref), "status": "NOT_RUN", "reason": "NOT_PUBLISHED"}
    if not row["currently_readable"] or any(
            _chain(evidence, e) == "SOURCE_NOT_CURRENTLY_READABLE" for e in row["evidence_ids"]):
        return {"assertion_id_sha256": text_digest(ref), "status": "INVALIDATED", "reason": "ASSERTION_OR_SOURCE_DENIED"}
    version = row["transaction_version"]
    complete = (row["transaction_event_hash"] is not None and
                version is not None and 0 < version <= graph["graph_version"] and
                (version < graph["graph_version"] or row["transaction_event_hash"] == graph["journal_head"]) and
                row["plan_id"] is not None and row["resolution_id"] is not None and bool(row["observation_ids"]) and
                row["resolution_outcome"] == "SELECTED" and row["observations_ok"] and bool(row["evidence_ids"]) and
                all(_chain(evidence, e) is None for e in row["evidence_ids"]))
    if not complete:
        return {"assertion_id_sha256": text_digest(ref), "status": "FAIL", "reason": "INCOMPLETE_GRAPH_CHAIN"}
    if not row["active"]:
        return {"assertion_id_sha256": text_digest(ref), "status": "INVALIDATED", "reason": "ASSERTION_INACTIVE"}
    return {"assertion_id_sha256": text_digest(ref), "status": "PASS", "reason": "TRANSACTION_PLAN_RESOLUTION_OBSERVATION_CHAIN"}


@boundary
def evaluate(protocol: dict, receipts: dict, recovery: list) -> dict:
    """Aggregate report; recovery rows are application-attested scenario outcomes."""
    _validate_protocol(protocol)
    _validate_receipts(receipts)
    _validate_recovery(recovery, protocol)
    evidence = {e["evidence_id"]: e for e in receipts["evidence"]}
    latest = {}
    for attempt in receipts["answers"]:
        latest[attempt["question_sha256"]] = attempt  # export order is checkpoint order
    declared = {q["question_sha256"] for q in protocol["questions"]}
    questions = [_question(q, latest.get(q["question_sha256"]), evidence) for q in protocol["questions"]]
    questions += [{"question_sha256": h, "expectation": None, "status": "FAIL", "reason": "UNDECLARED_QUESTION"}
                  for h in sorted(set(latest) - declared)]
    published = {a["assertion_id"]: a for a in receipts["assertions"]}
    assertions = [_assertion(ref, published, evidence, receipts["graph"])
                  for ref in protocol["expected_assertions"]]
    assertions += [{"assertion_id_sha256": text_digest(ref), "status": "FAIL", "reason": "UNEXPECTED_ASSERTION"}
                   for ref in sorted(set(published) - set(protocol["expected_assertions"]))]
    chains = []
    for attempt in latest.values():
        for position, claim in enumerate(attempt["claims"], start=1):
            problems = sorted({_chain(evidence, ref) for ref in claim["evidence_ids"]} - {None})
            if problems:
                status = "INVALIDATED" if problems == ["SOURCE_NOT_CURRENTLY_READABLE"] else "FAIL"
                reason = ",".join(problems)
            elif not attempt["graph_version_current"] or attempt.get("retrieval_context_current") is not True:
                status, reason = "HOLD", "CITATION_CONTEXT_REFRESH_REQUIRED"
            else:
                status, reason = "PASS", "CITATION_EVIDENCE_SOURCE_PAGE"
            chains.append({"question_sha256": attempt["question_sha256"], "claim_position": position,
                           "status": status, "reason": reason})
    supplied = {r["scenario"]: r for r in recovery}
    recovery_rows = [{"scenario_sha256": text_digest(name), "status": supplied[name]["status"], "evidence_class": supplied[name]["evidence_class"],
                      "receipt_sha256": supplied[name]["receipt_sha256"]} if name in supplied else
                     {"scenario_sha256": text_digest(name), "status": "NOT_RUN", "evidence_class": None, "receipt_sha256": None}
                     for name in protocol["required_recovery"]]
    reviews = receipts["source_reviews"]
    sections = {"questions": questions, "assertions": assertions, "citation_chains": chains, "recovery": recovery_rows}
    abstention = [q for q in questions if q["expectation"] == "ABSTAIN"]
    all_rows = [r for rows in sections.values() for r in rows]
    verdict = ("FAIL" if any(r["status"] == "FAIL" for r in all_rows) else
               "PASS" if all_rows and all(r["status"] == "PASS" for r in all_rows) else "HOLD")
    synthetic = receipts["execution_mode"] == "SYNTHETIC" or any(
        r["evidence_class"] == "AUTHORED_SYNTHETIC" for r in recovery_rows)
    report = {"version": VERSION, "evaluator": evaluator_identity(), "protocol_id_sha256": text_digest(protocol["protocol_id"]),
              "protocol_sha256": digest(protocol), "receipts_sha256": digest(receipts),
              "recovery_sha256": digest(recovery), "run_id_sha256": text_digest(receipts["run_id"]),
              "checkpoint_head": receipts["checkpoint_head"], "graph": receipts["graph"],
              "evidence_class": "AUTHORED_SYNTHETIC_MECHANICS_ONLY" if synthetic else "UNSIGNED_AGGREGATE_OF_LIVE_RECEIPTS",
              "verdict": verdict,
              "metrics": {**{name: _summary(rows) for name, rows in sections.items()},
                          "abstention": _summary(abstention),
                          "source_reviews": {"denominator": len(reviews),
                                             "all_checks_passed": sum(r["all_checks_passed"] for r in reviews),
                                             "assistant": sum(r["reviewer_kind"] == "assistant" for r in reviews),
                                             "human": sum(r["reviewer_kind"] == "human" for r in reviews),
                                             "independent": 0}},
              "rows": sections, "source_text_included": False, "provider_calls": 0,
              "authorization_granted": False, "qualifies_issue_23": False,
              "limits": ["Claim support is the recorded attributed review, not an entailment check by this evaluator.",
                         "Receipt rows are unsigned; bind them to the private run by checkpoint and journal heads.",
                         "Extraction completeness and graph correctness need separate predeclared attributed review."]}
    return report
