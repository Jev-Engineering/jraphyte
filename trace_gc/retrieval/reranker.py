"""Bounded Jev relevance judgments through the existing pack/observation adapter."""
from __future__ import annotations
from copy import deepcopy
import time
from typing import Callable, Any
from ..canonical import digest
from ..compiler import compile_pack, now
from ..errors import require
from ..programs import RETRIEVAL_VERSION, retrieval_question
from ..adapter import validate_observation
from .contracts import VERSION

class JevReranker:
    version = "jev-relevance-reranker-v1"
    def __init__(self, execute: Callable[[str], list[str]], *, model_version: str = "jev-1.13.0",
                 token_counter: Any = None, tokenizer_version: str = "utf8-byte-estimate-v1"):
        self.execute, self.model_version = execute, model_version
        self.token_counter, self.tokenizer_version = token_counter, tokenizer_version

    def rerank(self, retriever, result_id: str, *, candidate_id: str) -> str:
        c = retriever.catalog
        result = c.get(result_id, "retrieval-result")
        original = c.get(result["graph_context_id"], "graph-context")
        require("reranking_observation_ids" not in original, "RERANK_OBSERVATION", "rerank the original retrieval branch once")
        request = c.get(result["query_id"], "retrieval-query")
        require(request["candidate_id"] == candidate_id and request["requesting_component"].startswith("upstream"),
                "RETRIEVAL_ROLE", "bounded reranking needs an upstream candidate")
        candidate = c.get(candidate_id, "candidate")
        items = original["items"][:request["budget"]["maximum_semantic_items"]]
        if not items:
            return result_id
        pack_id = compile_pack(c, id_="rerank-pack:" + digest([result_id, self.version, self.model_version]),
            run_id=candidate["run_id"], candidate_ids=[candidate_id],
            questions=[retrieval_question(candidate_id, i["id"], id_=f"relevance-{n}") for n, i in enumerate(items)],
            snapshot_id=original["snapshot_id"], security_scope=request["security_scope"],
            execution_mode=candidate["execution_mode"], model_version=self.model_version, program_version=RETRIEVAL_VERSION,
            graph_context_ids=[result["graph_context_id"]], source_retrieval_ids=[result_id],
            token_counter=self.token_counter, tokenizer_version=self.tokenizer_version)
        from .service import validate_current_context
        validate_current_context(retriever, result["graph_context_id"], pack_id=pack_id)
        started = time.monotonic()
        observation_ids = self.execute(pack_id)
        latency = (time.monotonic()-started)*1000
        validate_current_context(retriever, result["graph_context_id"], pack_id=pack_id)
        pack = c.get(pack_id, "pack")
        questions = {q["id"]: q for q in pack["questions"]}
        seen = set()
        bonuses: dict[str, float] = {}
        for ref in observation_ids:
            validate_observation(c, ref)
            obs = c.get(ref, "observation")
            require(obs["pack_id"] == pack_id and obs["question_id"] not in seen,
                    "RERANK_OBSERVATION", "wrong pack or duplicate judgment")
            seen.add(obs["question_id"])
            # Classification affects order only; never remove a contradiction or
            # turn a relevance score into an acceptance probability.
            bonuses[questions[obs["question_id"]]["context_item_id"]] = (
                1.0 if obs["semantic_outcome"] == "RELEVANT" else -1.0 if obs["semantic_outcome"] == "IRRELEVANT" else 0.0)
        require(seen == set(questions), "RERANK_OBSERVATION", "incomplete relevance judgments")
        context = deepcopy(original)
        context["ranking_scores"] = {key: value+bonuses.get(key, 0.0) for key, value in context["ranking_scores"].items()}
        context["items"].sort(key=lambda i: (i["kind"] != "CONFLICT", -context["ranking_scores"][i["id"]], i["id"]))
        context["retrieval_fingerprint"] = digest({"base": original["retrieval_fingerprint"], "reranker": self.version,
            "program": RETRIEVAL_VERSION, "model": self.model_version, "maximum_semantic_items": len(items)})
        context["reranking_observation_ids"] = sorted(observation_ids)
        context["reranking_base_context_id"] = result["graph_context_id"]
        context["created_at"] = now()
        context_id = c.put("graph-context", context)
        lineage = deepcopy(c.get(result["lineage_id"], "retrieval-lineage"))
        lineage["graph_context_id"] = context_id
        lineage["strategy_versions"]["SEMANTIC_JEV"] = self.version
        lineage["retrieval_strategies"] = list(dict.fromkeys(lineage["retrieval_strategies"]+["SEMANTIC_JEV"]))
        for row in lineage["candidates"]:
            if row["item_id"] in context["ranking_scores"]:
                row["score"] = context["ranking_scores"][row["item_id"]]
                row["features"]["semantic_relevance_utility"] = bonuses.get(row["item_id"], 0.0)
                row["methods"] = sorted(set(row["methods"]+["SEMANTIC_JEV"]))
        lineage["usage"].update(semantic_packs=1, semantic_items=len(items), jev_latency_ms=latency,
            tokens_supplied_to_jev=pack["budget"]["state_tokens"]+sum(pack["budget"]["question_tokens"].values()))
        lineage["created_at"] = now()
        lineage_id = c.put("retrieval-lineage", lineage)
        return c.put("retrieval-result", {**deepcopy(result), "graph_context_id": context_id,
            "lineage_id": lineage_id, "usage": lineage["usage"],
            "warnings": sorted(set(result["warnings"]+["RELEVANCE_IS_NOT_TRUTH"])), "created_at": now()})


def validate_reranked_context(catalog, context):
    """Rebuild a relevance-only change from the original immutable model receipts."""
    from .service import validate_context
    require("reranking_base_context_id" in context, "RERANK_OBSERVATION", "missing original context")
    ref = context["reranking_base_context_id"]
    base = catalog.get(ref, "graph-context")
    require("reranking_observation_ids" not in base, "RERANK_OBSERVATION", "stacked reranking is not supported")
    validate_context(catalog, ref)
    expected = deepcopy(base)
    bonuses = {}
    pack_ids = set()
    for obs_id in context["reranking_observation_ids"]:
        validate_observation(catalog, obs_id)
        obs = catalog.get(obs_id, "observation")
        pack = catalog.get(obs["pack_id"], "pack")
        pack_ids.add(obs["pack_id"])
        require(pack["graph_context_ids"] == [ref] and pack["program_version"] == RETRIEVAL_VERSION,
                "RERANK_OBSERVATION", "reranker original-context binding differs")
        q = next(q for q in pack["questions"] if q["id"] == obs["question_id"])
        require(q["context_item_id"] not in bonuses, "RERANK_OBSERVATION", "duplicate relevance item")
        bonuses[q["context_item_id"]] = 1.0 if obs["semantic_outcome"] == "RELEVANT" else -1.0 if obs["semantic_outcome"] == "IRRELEVANT" else 0.0
    request = catalog.get(base["query_id"], "retrieval-query")
    wanted = {i["id"] for i in base["items"][:request["budget"]["maximum_semantic_items"]]}
    require(len(pack_ids) == 1 and set(bonuses) == wanted, "RERANK_OBSERVATION", "relevance coverage differs")
    pack = catalog.get(next(iter(pack_ids)), "pack")
    expected["ranking_scores"] = {key: value+bonuses.get(key, 0.0) for key, value in base["ranking_scores"].items()}
    expected["items"].sort(key=lambda i: (i["kind"] != "CONFLICT", -expected["ranking_scores"][i["id"]], i["id"]))
    expected["retrieval_fingerprint"] = digest({"base": base["retrieval_fingerprint"], "reranker": JevReranker.version,
        "program": RETRIEVAL_VERSION, "model": pack["model_version"], "maximum_semantic_items": len(wanted)})
    expected["reranking_base_context_id"] = ref
    expected["reranking_observation_ids"] = context["reranking_observation_ids"]
    expected["created_at"] = context["created_at"]
    require(expected == context, "RERANK_OBSERVATION", "reranker altered something other than bounded relevance order")
