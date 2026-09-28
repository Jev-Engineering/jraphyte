"""Native first-page alignment with character-level provenance (no model calls).

Canonical agreement is a location aid, not proof of scientific notation fidelity.
No OCR coordinate is invented. Source text, offsets and boxes remain inspectable.
"""
from __future__ import annotations

import difflib
import hashlib
import json
import math
import re
import unicodedata
from collections import defaultdict
from typing import Iterable, Mapping, Sequence
from .pdf_geometry_parallel_v4 import logical_rows, transition_evidence, _horizontal

VERSION = "page-one-parallel-source-v4"
SLICE_VERSION = "native-requested-leading-prefix-v1"
CHAIN_VERSION = "native-terminal-wrap-chain-v1"


def canonical(text: str) -> str:
    return "".join(c for c in unicodedata.normalize("NFKD", text).casefold() if c.isalnum())


def normalize(text: str) -> str:
    return re.sub(r"\s+", " ", text).strip()


def json_bytes(value: object) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("utf-8")


def digest_value(value: object) -> str:
    return hashlib.sha256(json_bytes(value)).hexdigest()


def compare(predicted: str, reference: str) -> dict:
    """Exactly the ordered-character/boundary definition of the frozen report."""
    a, b = canonical(predicted), canonical(reference)
    matches = sum(m.size for m in difflib.SequenceMatcher(None, a, b, autojunk=False).get_matching_blocks())
    precision = matches / len(a) if a else float(not b)
    recall = matches / len(b) if b else 1.0
    boundary = a.startswith(b[:48]) and a.endswith(b[-48:]) if b else not bool(a)
    return {"precision": precision, "recall": recall, "boundary_match": boundary,
            "text_match_98": precision >= .98 and recall >= .98,
            "boundary_and_98_match": precision >= .98 and recall >= .98 and boundary}


def overlap(a: Sequence[float], b: Sequence[float]) -> float:
    return max(0.0, min(a[2], b[2]) - max(a[0], b[0])) / max(1.0, min(a[2]-a[0], b[2]-b[0]))


def validate_box(box: Sequence[float], page_size: Sequence[float]) -> list[float]:
    if len(box) != 4 or any(isinstance(v, bool) or not isinstance(v, (int, float)) or not math.isfinite(v) for v in box):
        raise ValueError("invalid_source_box")
    x0, y0, x1, y1 = box
    w, h = page_size
    if not 0 <= x0 < x1 <= w + 1 or not 0 <= y0 < y1 <= h + 1:
        raise ValueError("source_box_outside_first_page")
    return list(box)


def validate_lines(lines: Iterable[Mapping], page_size: Sequence[float]) -> list[dict]:
    result, seen = [], set()
    for raw in lines:
        line = dict(raw)
        key = str(line["id"])
        if key in seen:
            raise ValueError("duplicate_native_line_id")
        seen.add(key)
        if line.get("page_no", 1) != 1:
            raise ValueError("native_line_outside_first_physical_page")
        if not isinstance(line["text"], str):
            raise ValueError("native_text_not_string")
        line["bbox"] = validate_box(line["bbox"], page_size)
        for span in line.get("spans", []):
            start, end = span["start"], span["end"]
            if not isinstance(start, int) or not isinstance(end, int) or not 0 <= start <= end <= len(line["text"]):
                raise ValueError("invalid_native_span_offsets")
            if span.get("text", line["text"][start:end]) != line["text"][start:end]:
                raise ValueError("native_span_text_mismatch")
            if "size" in span and (not isinstance(span["size"], (int,float)) or not math.isfinite(span["size"]) or span["size"] < 0):
                raise ValueError("invalid_native_font_size")
            for field in ("flags", "color"):
                if field in span and (isinstance(span[field],bool) or not isinstance(span[field],int) or span[field] < 0):
                    raise ValueError("invalid_native_style")
        result.append(line)
    return result


def source_lines(page) -> list[dict]:
    """Read native spans from a verified PyMuPDF first-page object, never OCR."""
    if page.number != 0:
        raise ValueError("only_first_physical_page_is_allowed")
    result = []
    for bi, block in enumerate(page.get_text("dict", sort=True)["blocks"]):
        if block.get("type") != 0:
            continue
        for li, line in enumerate(block.get("lines", [])):
            spans, chunks, offset = [], [], 0
            for span in line.get("spans", []):
                text = span.get("text", "")
                spans.append({"start": offset, "end": offset+len(text), "text": text,
                              "font": span.get("font"), "size": span.get("size"),
                              "flags": span.get("flags", 0), "color": span.get("color", 0),
                              "bbox": list(span["bbox"])})
                chunks.append(text)
                offset += len(text)
            result.append({"id": len(result), "block_id": bi, "line_in_block": li, "page_no": 1,
                           "bbox": list(line["bbox"]), "text": "".join(chunks), "spans": spans})
    return validate_lines(result, (page.rect.width, page.rect.height))


def style(line: Mapping) -> dict:
    """Dominant visible text style, weighted by characters, not equation glyphs."""
    weights = defaultdict(int)
    for span in line.get("spans", []):
        text = span.get("text", line["text"][span["start"]:span["end"]])
        weight = len(canonical(text))
        if weight:
            bold = bool(span.get("flags", 0) & 16 or "bold" in str(span.get("font", "")).lower())
            weights[(span.get("color", 0), bold, round(float(span.get("size") or 0), 1))] += weight
    if not weights:
        return {}
    (color, bold, size), weight = max(weights.items(), key=lambda kv: kv[1])
    return {"color": color, "bold": bold, "size": size, "fraction": weight/sum(weights.values())}


def _paragraph_font(line: dict) -> tuple | None:
    weights = defaultdict(int)
    for run in line.get("spans", []):
        if (not isinstance(run.get("font"), str) or not run["font"]
                or type(run.get("size")) not in (int, float) or not math.isfinite(run["size"])
                or run["size"] <= 0 or type(run.get("flags")) is not int or type(run.get("color")) is not int):
            return None
        weights[(run["font"], float(run["size"]), run["flags"] & 18, run["color"])] += len(canonical(run.get("text", "")))
    if not weights or not sum(weights.values()):
        return None
    signature, weight = max(weights.items(), key=lambda item: item[1])
    return signature if weight/sum(weights.values()) >= .8 else None


def _terminal_wraps(source_rows: list[dict]) -> list[tuple[dict, dict]]:
    """Corroborate only a native block's short final sentence row.

    Two immediate full-width predecessors must agree on paragraph typography,
    native ownership, left edge and line spacing. Full-page context prevents a
    model crop from hiding a later owner line or a competing adjacent lane.
    """
    by_block = defaultdict(list)
    by_line = {}
    for row in source_rows:
        for line in row["lines"]:
            by_line[str(line["id"])] = row
            if type(line.get("block_id")) is int and type(line.get("line_in_block")) is int:
                by_block[line["block_id"]].append(line)
    candidates = []
    for owner, lines in by_block.items():
        indices = {line["line_in_block"]: line for line in lines}
        if len(indices) != len(lines) or len(indices) < 3:
            continue
        final_index = max(indices)
        if final_index-1 not in indices or final_index-2 not in indices:
            continue
        before, prior, final = (indices[i] for i in (final_index-2, final_index-1, final_index))
        rows = [by_line[str(line["id"])] for line in (before, prior, final)]
        if (any(len(row["lines"]) != 1 for row in rows) or not all(_horizontal(line) for line in (before, prior, final))
                or len(canonical(final["text"])) < 4 or not re.search(r"[.!?][\s\)\]\}’\"']*$", final["text"])):
            continue
        fonts = [_paragraph_font(line) for line in (before, prior, final)]
        if not fonts[0] or any(font != fonts[0] for font in fonts[1:]):
            continue
        em = fonts[0][1]
        a, b, c = (line["bbox"] for line in (before, prior, final))
        widths = [box[2]-box[0] for box in (a, b, c)]
        centers = [(box[1]+box[3])/2 for box in (a, b, c)]
        steps = [centers[1]-centers[0], centers[2]-centers[1]]
        if (min(widths[:2]) < 10*em or not 2*em <= widths[2] < min(widths[:2])/1.65
                or abs(a[0]-b[0]) > .25*em or abs(b[0]-c[0]) > .25*em
                or abs(a[2]-b[2]) > .5*em or any(not .8*em <= step <= 1.8*em for step in steps)
                or abs(steps[0]-steps[1]) > .25*em):
            continue
        # An intervening row or simultaneous neighboring column contradicts a
        # terminal wrap, even if the native extractor reused one block ID.
        if any(row not in rows and overlap(b, row["bbox"]) >= .1
               and centers[1] < (row["bbox"][1]+row["bbox"][3])/2 <= c[3]
               for row in source_rows):
            continue
        proof = {"version": CHAIN_VERSION, "reason": "source_owned_short_final_wrap",
                 "block_id": owner, "final_native_line_id": final["id"],
                 "support_native_line_ids": [before["id"], prior["id"]],
                 "native_line_indices": [final_index-2, final_index-1, final_index],
                 "source_boxes": [list(box) for box in (a, b, c)],
                 "dominant_font": {"font": fonts[0][0], "size": em, "flags": fonts[0][2], "color": fonts[0][3]},
                 "scope": "raw_reading_order_only"}
        candidates.append((rows[-1], proof))
    return candidates


def _chains(lines: list[dict], rows: list[dict] | None = None, *, source_rows=None,
            evidence: dict | None = None) -> list[list[dict]]:
    """Column-local order plus original order; never a global y-sort only.

    Requiring high horizontal overlap prevents the wrong-column projection.
    Full-width lines are not used to connect two narrow columns transitively.
    """
    rows = logical_rows(lines) if rows is None else rows
    wraps = _terminal_wraps(rows if source_rows is None else source_rows)
    eligible = {str(line["id"]) for line in lines}
    result = []
    for anchor in rows:
        a = anchor["bbox"]
        local = [x for x in rows if overlap(a, x["bbox"]) >= .8 and
                 max(a[2]-a[0], x["bbox"][2]-x["bbox"][0]) <= 1.65*max(1, min(a[2]-a[0], x["bbox"][2]-x["bbox"][0]))]
        local.sort(key=lambda x: (round(x["bbox"][1], 1), x["bbox"][0], str(x["id"])))
        local_ids = {str(line["id"]) for row in local for line in row["lines"]}
        added = [(row, proof) for row, proof in wraps if str(proof["final_native_line_id"]) in eligible-local_ids
                 and all(str(sid) in local_ids for sid in proof["support_native_line_ids"])]
        if added:
            extended = sorted(local+[row for row, _ in added], key=lambda x: (round(x["bbox"][1], 1), x["bbox"][0], str(x["id"])))
            chain = [line for row in extended for line in row["lines"]]
            result.append(chain)
            if evidence is not None:
                evidence[tuple(str(line["id"]) for line in chain)] = [proof for _, proof in added]
        result.append([line for row in local for line in row["lines"]])
    # Native original order can encode legitimate multi-column continuation.
    # Such a match is returned but held by the caller unless layout corroborates it.
    result.append(lines)
    unique, seen = [], set()
    for chain in result:
        key = tuple(str(x["id"]) for x in chain)
        if key and key not in seen:
            seen.add(key)
            unique.append(chain)
    return unique


def _mapped(chain: list[dict]) -> tuple[str, list[tuple[int, int]]]:
    chars, mapping = [], []
    for li, line in enumerate(chain):
        for ci, char in enumerate(line["text"]):
            for c in unicodedata.normalize("NFKD", char).casefold():
                if c.isalnum():
                    chars.append(c)
                    mapping.append((li, ci))
    return "".join(chars), mapping


def _slices(chain: list[dict], mapping: list[tuple[int, int]], start: int, end: int) -> list[dict]:
    first_line, first_char = mapping[start]
    last_line, last_char = mapping[end-1]
    output = []
    for i in range(first_line, last_line+1):
        line = chain[i]
        a = first_char if i == first_line else 0
        b = last_char+1 if i == last_line else len(line["text"])
        # Include source punctuation immediately adjacent to the selected range,
        # but not following alphanumeric metadata or a new sentence.
        if i == last_line:
            while b < len(line["text"]) and line["text"][b] in ".!?;,:)]}’\"'†‡*":
                b += 1
        output.append({"line_id": line["id"], "start": a, "end": b,
                       "text": line["text"][a:b], "bbox": list(line["bbox"]),
                       "box_scope": "native_line_not_character_box", "page_no": 1})
    return output


def _bind_leading_prefix(text: str, match: dict, native_lines: list[dict]) -> dict:
    """Bind a requested prefix after canonical occurrence ambiguity is resolved.

    This changes raw offsets only. It does not infer glyph mappings, attach a
    separate native line, or certify internal/trailing scientific notation.
    """
    requested = text.lstrip()
    anchor = next(i for i, char in enumerate(requested) if canonical(char))
    prefix = requested[:anchor]
    if not prefix:
        return match
    evidence = {"version": SLICE_VERSION, "scope": "requested_leading_prefix_only",
                "requested_prefix_sha256": hashlib.sha256(prefix.encode("utf-8")).hexdigest(),
                "requested_prefix_characters": len(prefix)}

    def held(reason: str) -> dict:
        return {"status": "unlocated", "reason": "requested_leading_prefix_not_source_bound", "spans": [],
                "slice_evidence": {**evidence, "status": "unresolved", "reason": reason},
                "candidate_native_extent": {"status": "canonical_extent_only", "accepted": False,
                    "spans": match["spans"], "column_change": match["column_change"],
                    "precision": match["precision"], "recall": match["recall"]}}

    # Only visible punctuation/symbols and horizontal spaces belong to this
    # repair. Controls, line breaks and combining glyph mappings need separate
    # representation evidence, even if identical raw bytes appear nearby.
    if any(unicodedata.category(char)[0] not in "PS" and unicodedata.category(char) != "Zs"
           for char in prefix):
        return held("unsupported_prefix_character")
    first = match["spans"][0]
    line = next(line for line in native_lines if str(line["id"]) == str(first["line_id"]))
    start, end = first["start"], first["end"]
    if canonical(requested[anchor]) != canonical(line["text"][start]):
        return held("requested_anchor_not_selected_native_anchor")
    extended_start = start - len(prefix)
    if extended_start < 0 or line["text"][extended_start:start] != prefix:
        return held("prefix_not_contiguous_on_selected_native_line")
    spans = [{**first, "start": extended_start, "text": line["text"][extended_start:end]},
             *match["spans"][1:]]
    return {**match, "spans": spans, "text": "\n".join(span["text"] for span in spans),
            "slice_evidence": {**evidence, "status": "exact_raw_prefix",
                               "line_id": first["line_id"], "start": extended_start,
                               "canonical_start": start, "end": end}}


def locate(text: str, native_lines: list[dict], *, region_boxes: list[list[float]] | None = None,
           threshold: float = .98) -> dict:
    """Find a unique contiguous source transcription; never relax the 98% gate.

    Geometry restricts a genuine layout region. OCR callers omit region_boxes:
    their estimated boxes must not be used as independent corroboration.
    """
    if threshold < .98 or threshold > 1:
        raise ValueError("alignment_threshold_must_not_weaken_frozen_gate")
    target = canonical(text)
    if not target:
        return {"status": "unlocated", "reason": "empty_candidate", "spans": []}
    eligible = native_lines
    if region_boxes is not None:
        eligible = [line for line in native_lines if any(
            box[1]-2 <= (line["bbox"][1]+line["bbox"][3])/2 <= box[3]+2 and
            overlap(box, line["bbox"]) >= .8 for box in region_boxes)]
    # Derive against the full native page: restricting to a model region first
    # would remove neighboring-row evidence and make geometry model-dependent.
    rows = logical_rows(native_lines)
    eligible_ids = {str(line["id"]) for line in eligible}
    eligible_rows = [{**row, "lines": [line for line in row["lines"] if str(line["id"]) in eligible_ids]}
                     for row in rows if any(str(line["id"]) in eligible_ids for line in row["lines"])]
    matches, chain_proofs = {}, {}
    for chain in _chains(eligible, eligible_rows, source_rows=rows, evidence=chain_proofs):
        haystack, mapping = _mapped(chain)
        if not haystack:
            continue
        intervals = []
        pos = haystack.find(target)
        while pos >= 0:
            intervals.append((pos, pos+len(target)))
            pos = haystack.find(target, pos+1)
        # Exact occurrences partition the source. Search other disjoint regions
        # as well: otherwise a near-duplicate elsewhere could be hidden. Avoid
        # expensive fuzzy windows over already-exact long/repetitive paragraphs.
        ranges = []
        cursor = 0
        for a, b in intervals:
            if a-cursor >= len(target)*threshold:
                ranges.append((cursor, a))
            cursor = max(cursor, b)
        if len(haystack)-cursor >= len(target)*threshold:
            ranges.append((cursor, len(haystack)))
        seed_size = min(24, max(4, len(target)//4))
        stride = max(seed_size, len(target)//8)
        slack = max(3, math.ceil(len(target)*.025))
        windows = set(ranges)
        for left, right in ranges:
            for offset in sorted(set(range(0, len(target)-seed_size+1, stride)) | {len(target)-seed_size}):
                seed = target[offset:offset+seed_size]
                pos = haystack.find(seed, left, right)
                while pos >= 0:
                    estimate = pos-offset
                    windows.add((max(left, estimate-slack), min(right, estimate+len(target)+slack)))
                    if len(windows) > 256:
                        return {"status": "unlocated", "reason": "alignment_search_budget_exceeded", "spans": []}
                    pos = haystack.find(seed, pos+1, right)
        for left, right in windows:
            blocks = [m for m in difflib.SequenceMatcher(None, target, haystack[left:right], autojunk=False).get_matching_blocks() if m.size]
            if blocks:
                intervals.append((left+blocks[0].b, left+blocks[-1].b+blocks[-1].size))
        for a, b in intervals:
            source = haystack[a:b]
            score = compare(target, source)
            if min(score["precision"], score["recall"]) < threshold:
                continue
            spans = _slices(chain, mapping, a, b)
            key = tuple((str(s["line_id"]), s["start"], s["end"]) for s in spans)
            source_text = "\n".join(s["text"] for s in spans)
            geometry = transition_evidence(spans, rows)
            column_change = bool(geometry["unsupported_transitions"])
            matches[key] = {"status": "located", "spans": spans, "text": source_text,
                            "precision": score["precision"], "recall": score["recall"],
                            "column_change": column_change, "coordinate_source": "native_pdf_lines",
                            "logical_geometry": geometry}
            selected_ids = {str(span["line_id"]) for span in spans}
            proof = [value for value in chain_proofs.get(tuple(str(line["id"]) for line in chain), [])
                     if str(value["final_native_line_id"]) in selected_ids]
            if proof:
                matches[key]["chain_evidence"] = proof
    if not matches:
        return {"status": "unlocated", "reason": "no_98_percent_source_alignment", "spans": []}
    occurrences = []
    for value in sorted(matches.values(), key=lambda v: (-min(v["precision"], v["recall"]), -len(canonical(v["text"])))):
        positions = {(str(span["line_id"]), i) for span in value["spans"] for i in range(span["start"], span["end"])}
        if not any(len(positions & prior)/max(1, min(len(positions), len(prior))) >= .9 for _, prior in occurrences):
            occurrences.append((value, positions))
    if len(occurrences) != 1:
        return {"status": "ambiguous", "reason": "multiple_source_occurrences", "spans": [], "matches": len(occurrences)}
    # Prefix punctuation must never silently select one canonical occurrence
    # over another. It is bound only after the existing ambiguity gate passes.
    return _bind_leading_prefix(text, occurrences[0][0], native_lines)


def validate_source_spans(spans: list[dict], native_lines: list[dict]) -> None:
    by_id = {str(x["id"]): x for x in native_lines}
    seen = set()
    for s in spans:
        key = (str(s["line_id"]), s["start"], s["end"])
        if key in seen:
            raise ValueError("duplicate_selected_span")
        seen.add(key)
        line = by_id[str(s["line_id"])]
        if s.get("page_no") != 1 or not 0 <= s["start"] < s["end"] <= len(line["text"]):
            raise ValueError("invalid_selected_span")
        if line["text"][s["start"]:s["end"]] != s["text"] or list(line["bbox"]) != s["bbox"]:
            raise ValueError("selected_span_does_not_match_source")
