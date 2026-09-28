"""Experimental parallel first-physical-page selector v4; never a publication authority.

Frozen v1/v2 modules are deliberately not modified. A proposal requires a unique
source location and an explainable closing boundary. Missing evidence is a hold.
"""
from __future__ import annotations

import hashlib
import math
import re
from .pdf_source_parallel_v4 import (canonical, compare, digest_value, locate, normalize, overlap,
                            style, validate_box, validate_lines, validate_source_spans)

VERSION = "page-one-parallel-structure-v4"
SECTION_OWNERSHIP_VERSION = "source-section-ownership-v1"
ABSTRACT_STRUCTURE_VERSION = "source-abstract-sections-v2"
PREFIX_RETENTION_VERSION = "source-prefix-hold-retention-v1"
ABSTRACT = re.compile(r"^\s*a\s*b\s*s\s*t\s*r\s*a\s*c\s*t\b\s*[.:—–-]?\s*", re.I)
EXCLUDED = {"page_header", "page_footer", "footnote", "caption", "picture", "table", "document_index"}
BODY_WORDS = r"(?:overview|introduction|background|preliminaries|related\s+work|methods?|materials\s+and\s+methods|results|discussion|conclusions?|references|contents|table\s+of\s+contents)"
METADATA_WORDS = r"(?:key\s*words?|additional\s+key\s+words\s+and\s+phrases|index\s+terms|(?:\d{4}\s+)?Mathematics\s+Subject\s+Classification(?:\s*\(\d{4}\))?(?=\s*[:.]|\s*$)|MSC(?:\s*\d{4})?(?=\s*[:.]|\s*$)|PACS(?:\s+(?:numbers|codes))?|CCS\s+concepts|funding|acknowledg\w*|correspondence|author\s+(?:contributions?|notes?|information|details)|data\s+availability|dedicat(?:ion|ed\s+to)|in\s+memory\s+of|to\s+the\s+memory\s+of|synopsis)"
METADATA_START = re.compile(r"^\s*(?:"+METADATA_WORDS+r"|(?:[\d,a-z*†‡]+\s+)?(?:department|university|institute|school|faculty|laboratory|college|cent(?:re|er))\b|©|copyright\b|all\s+rights\s+reserved|e-?mail\b|https?://|we\s+(?:thank|congratulate)\b|this\s+(?:work|paper|research)\s+(?:was|is)\s+(?:funded|supported)\b)", re.I)
COPYRIGHT_FOOTER = re.compile(r"^\s*(?:\\\([^)]*\\\)\s*)?(?:[©ⓒ]\s*)?(?:copyright\s*)?\d{4}\b.{0,120}\ball\s+rights\s+reserved[.\s]*$", re.I)
NON_ABSTRACT = re.compile(r"^\s*(?:graphical\s+abstract|highlights?|key\s+points|executive\s+summary|(?:Fig(?:ure)?\.?|Table)\s*\d+|author\s+(?:list|notes?|details)|dedication|contents|table\s+of\s+contents)\b", re.I)
NARRATIVE = re.compile(r"\b(?:we|this\s+(?:paper|study|work|article)|propos\w+|investigat\w+|demonstrat\w+|establish\w+|present\w+|introduc\w+|obtain\w+|develop\w+|show\w+|prove\w+)\b", re.I)
SENTENCE_END = re.compile(r"[.!?][\s\"'’”\])}†‡*\d]*$")
INTERNAL = {"context", "aim", "aims", "background", "objective", "objectives", "methods", "method", "results", "discussion", "conclusion", "conclusions", "purpose", "findings", "interpretation"}
NUMBER = r"(?:(?:\d+(?:\.\d+)*|[IVX]+)[.)]?\s+)?"


def body_items(document: dict) -> list[dict]:
    objects = {}
    for key in ("texts", "groups", "pictures", "tables"):
        for item in document.get(key, []):
            ref = item.get("self_ref")
            if not isinstance(ref, str) or ref in objects:
                raise ValueError("duplicate_or_missing_document_reference")
            objects[ref] = item
    ordered, seen = [], set()
    stack = [document["body"]]
    while stack:
        item = stack.pop()
        ref = item.get("self_ref")
        if not isinstance(ref, str) or ref in seen:
            raise ValueError("duplicate_or_cyclic_reading_order")
        seen.add(ref)
        if item.get("text") or item.get("orig"):
            ordered.append(item)
        children = item.get("children", [])
        for child in reversed(children):
            key = child.get("cref", child.get("$ref"))
            if key not in objects:
                raise ValueError("dangling_reading_order_reference")
            stack.append(objects[key])
    return ordered


def regions(document: dict, page_size: list[float]) -> list[dict]:
    result = []
    for order, raw in enumerate(body_items(document)):
        text = raw.get("text") or raw.get("orig", "")
        if not isinstance(text, str):
            raise ValueError("region_text_not_string")
        if not text.strip():
            continue
        boxes = []
        for prov in raw.get("prov", []):
            if prov.get("page_no") != 1:
                raise ValueError("region_outside_first_physical_page")
            b = prov["bbox"]
            origin = b.get("coord_origin")
            if origin == "TOPLEFT":
                box = [b["l"], b["t"], b["r"], b["b"]]
            elif origin == "BOTTOMLEFT":
                box = [b["l"], page_size[1]-b["t"], b["r"], page_size[1]-b["b"]]
            else:
                raise ValueError("unknown_coordinate_origin")
            boxes.append(validate_box(box, page_size))
        # Only OCR adapters may deliberately retain unlocated paragraphs.
        unlocated = bool(raw.get("source_location_missing"))
        if not boxes and not unlocated:
            raise ValueError("region_has_no_source_box")
        bbox = [min(b[0] for b in boxes), min(b[1] for b in boxes), max(b[2] for b in boxes), max(b[3] for b in boxes)] if boxes else None
        result.append({"ref": raw["self_ref"], "text": text, "label": raw.get("label", "text"),
                       "boxes": boxes, "bbox": bbox, "tree_order": order,
                       "coordinate_source": raw.get("coordinate_source", "layout_model"), "unlocated": unlocated})
    return result


def _author_like(text: str) -> bool:
    tokens = re.findall(r"[A-Za-z]+", text)
    if len(tokens) < 10:
        return False
    capitalized = sum(t[:1].isupper() for t in tokens)/len(tokens)
    initials = len(re.findall(r"\b[A-Z]\.", text))
    return capitalized > .72 and (initials >= 3 or text.count(",") >= 4)


def _role_rejected(text: str) -> bool:
    return bool(NON_ABSTRACT.match(text) or METADATA_START.match(text) or COPYRIGHT_FOOTER.match(text) or _author_like(text))


def _header(text: str) -> bool:
    return bool(re.fullmatch(r"\s*"+NUMBER+BODY_WORDS+r"\s*[.:—–-]?\s*", text, re.I))


def _structured(text: str) -> bool:
    return bool(re.search(r"(?:^|\n)\s*Methods?\s*:", text, re.I) and re.search(r"(?:^|\n)\s*Results\s*:", text, re.I))


def _cut(text: str, structured: bool) -> tuple[str, dict | None]:
    """Find semantic boundaries without deleting interior words like 'overview'."""
    starts = [(0, text)]
    starts.extend((m.end(), text[m.end():]) for m in re.finditer(r"\n|(?<=[.!?])\s+(?=[A-Z])", text))
    for pos, suffix in starts:
        if not suffix.strip():
            continue
        # A section word in a running sentence is not a heading. Require a
        # standalone heading, separator or a numeric structural prefix.
        meta = re.match(r"\s*("+METADATA_WORDS+r")\b\s*(?:[:.—–-]|\s|$)", suffix, re.I)
        section = re.match(r"\s*("+NUMBER+BODY_WORDS+r")\s*(?:[:.—–-]\s*|\n|$)", suffix, re.I)
        match = meta or section
        if not match:
            continue
        name = normalize(match.group(1)).lower().rstrip(": .")
        if structured and section and name in INTERNAL:
            continue
        return text[:pos].rstrip(), {"kind": "embedded_metadata" if meta else "embedded_body_section",
                                    "offset": pos, "label": match.group(1)}
    return text, None


def _style_cut(alignment: dict, native: list[dict]) -> tuple[str, dict | None]:
    if alignment.get("status") != "located":
        return alignment.get("text", ""), None
    by_id = {str(x["id"]): x for x in native}
    selected = alignment["spans"]
    pieces, previous = [], None
    for span in selected:
        line = by_id[str(span["line_id"])]
        current = style(line)
        if previous and pieces and SENTENCE_END.search("\n".join(pieces)):
            prior, prior_style = previous
            separate = (line.get("block_id") is not None and prior.get("block_id") is not None and line["block_id"] != prior["block_id"])
            block_text="\n".join(s["text"] for s in selected if by_id[str(s["line_id"])].get("block_id")==line.get("block_id"))
            if separate and _author_like(block_text):
                return "\n".join(pieces), {"kind":"native_author_metadata_block", "next_line_id":line["id"],
                                              "source_block_id":line["block_id"]}
            color_change = current and prior_style and current["color"] != prior_style["color"]
            if separate and color_change and current.get("fraction", 0) >= .8 and len(canonical(span["text"])) >= 24:
                return "\n".join(pieces), {"kind": "separate_source_style_region", "next_line_id": line["id"],
                                              "before_style": prior_style, "after_style": current}
        # Bold inline source headings can live in the very same model region.
        for run in line.get("spans", []):
            if run["start"] < span["start"] or run["end"] > span["end"]:
                continue
            value = line["text"][run["start"]:run["end"]].strip()
            bold = bool(run.get("flags", 0) & 16 or "bold" in str(run.get("font", "")).lower())
            if bold and _header(value):
                prefix = span["text"][:run["start"]-span["start"]]
                preceding = "\n".join(pieces+[prefix]).rstrip()
                if preceding and SENTENCE_END.search(preceding):
                    return preceding, {"kind": "native_styled_section_start", "line_id": line["id"],
                                       "start": run["start"], "end": run["end"], "label": value}
        pieces.append(span["text"])
        previous = line, current
    return "\n".join(pieces), None


def _source_bold(region: dict, native: list[dict]) -> bool:
    if not region["bbox"]:
        return False
    selected = [x for x in native if region["bbox"][1]-2 <= (x["bbox"][1]+x["bbox"][3])/2 <= region["bbox"][3]+2 and overlap(region["bbox"], x["bbox"]) >= .8]
    styles = [(style(x), len(canonical(x["text"]))) for x in selected]
    total = sum(n for s, n in styles if s)
    return bool(total and sum(n for s, n in styles if s.get("bold"))/total >= .8)


BLOCKING_HEADING = re.compile(r"^\s*(?:graphical\s+abstract|highlights?|key\s+points|executive\s+summary|contents|table\s+of\s+contents|dedication|authors?|author\s+(?:list|notes?|details|contributions)|affiliations?)\s*[.:]?\s*$",re.I)


def _field_context(region: dict, ordered: list[dict], native: list[dict]) -> dict | None:
    """A header-stripped scholarly field is still inside its source section.

    A Highlights paragraph can match native text perfectly without being an
    abstract. Preceding same-column source headings are decisive context.
    """
    if not region["bbox"]:return None
    before=[x for x in ordered if x["bbox"] and x["ref"]!=region["ref"] and
            x["bbox"][3] <= region["bbox"][1]+2 and overlap(region["bbox"],x["bbox"]) >= .5 and
            (BLOCKING_HEADING.fullmatch(x["text"]) or _header(x["text"]) or
             (ABSTRACT.match(x["text"]) and not ABSTRACT.sub("",x["text"]).strip()))]
    if not before:return None
    previous=max(before,key=lambda x:x["bbox"][3])
    if ABSTRACT.match(previous["text"]):return None
    alignment=locate(previous["text"],native,region_boxes=previous["boxes"])
    return {"kind":"nonabstract_source_section","ref":previous["ref"],"label":previous["text"],
            "source_location":alignment["status"],"source_spans":alignment["spans"]}


def _heading_context(alignment: dict, native: list[dict], *, abstract=False) -> bool:
    """A word match inside running prose does not establish a source heading."""
    if alignment["status"] != "located" or not alignment["spans"]:
        return False
    by_id = {str(x["id"]): x for x in native}
    first, last = alignment["spans"][0], alignment["spans"][-1]
    first_line, last_line = by_id[str(first["line_id"])], by_id[str(last["line_id"])]
    prefix = first_line["text"][:first["start"]].strip()
    suffix = last_line["text"][last["end"]:].strip()
    # Abstract starts must lead their source line. In particular, a converter
    # must not erase 'Graphical' from 'Graphical Abstract'. Outer inline sections
    # may follow a completed sentence or a separately emitted section number.
    if prefix and (abstract or not (SENTENCE_END.search(prefix) or re.fullmatch(r"(?:\d+(?:\.\d+)*|[IVX]+)[.)]?", prefix))):
        return False
    if not suffix:
        return True
    if abstract:
        # Native PDFs commonly use 'Abstract prose' without punctuation. The
        # source-leading position, including any excluded prefix, is decisive.
        return True
    if alignment["text"].rstrip().endswith(tuple(":.—–-")) or suffix[0] in ":.—–-":
        return True
    runs = last_line.get("spans", [])
    def bold(run):
        return bool(run.get("flags", 0) & 16 or "bold" in str(run.get("font", "")).lower())
    heading_runs = [r for r in runs if r["end"] > last["start"] and r["start"] < last["end"]]
    suffix_runs = [r for r in runs if r["end"] > last["end"]]
    return bool(heading_runs and suffix_runs and all(bold(r) for r in heading_runs)
                and all(not bold(r) for r in suffix_runs))


def _boundary_evidence(region: dict, native: list[dict], kind: str) -> dict:
    located = locate(region["text"], native, region_boxes=region["boxes"])
    scope = "whole_region"
    if kind in {"body_section", "embedded_body_section", "ambiguous_structured_or_body_section", "metadata_or_nonabstract_region"} and not _heading_context(located, native):
        located = {"status": "unverified_heading_context", "spans": []}
    if (located["status"] == "located" and kind in {"body_section", "ambiguous_structured_or_body_section"}
            and not _header(region["text"])):
        # A complete source paragraph can still have an incorrect model label.
        # Unknown section titles need corroborating native heading typography.
        ids = {str(s["line_id"]) for s in located["spans"]}
        selected = [n for n in native if str(n["id"]) in ids]
        box = region["bbox"]
        neighbors = [n for n in native if str(n["id"]) not in ids and overlap(box, n["bbox"]) >= .5
                     and (0 <= box[1]-n["bbox"][3] <= 72 or 0 <= n["bbox"][1]-box[3] <= 72)]
        heading_styles = [style(n) for n in selected]
        neighbor_styles = [style(n) for n in neighbors]
        corroborated = (len(ids) <= 2 and len(canonical(region["text"])) <= 120
                        and len(region["text"].split()) <= 16 and heading_styles and neighbor_styles
                        and all(s.get("fraction", 0) >= .8 for s in heading_styles)
                        and (all(s.get("bold") for s in heading_styles) and any(not s.get("bold") for s in neighbor_styles)
                             or min(s.get("size", 0) for s in heading_styles) > 1.15*max(s.get("size", 0) for s in neighbor_styles)))
        if not corroborated:
            located = {"status": "unverified_heading_role", "spans": []}
    if located["status"] != "located" and kind == "metadata_or_nonabstract_region":
        # A converter's math transcription may corrupt the values following a
        # correctly located metadata label. Verify the label's source context;
        # an interior word or 'Keywords describe ...' is not a heading.
        match = re.match(r"\s*("+METADATA_WORDS+r")\b\s*[:.—–-]", region["text"], re.I)
        label = match.group(1) if match else "All rights reserved" if COPYRIGHT_FOOTER.match(region["text"]) else None
        if label:
            candidate = locate(label, native, region_boxes=region["boxes"])
            if candidate["status"] == "located":
                by_id = {str(x["id"]): x for x in native}
                first, last = candidate["spans"][0], candidate["spans"][-1]
                prefix = by_id[str(first["line_id"])]["text"][:first["start"]].strip()
                suffix = by_id[str(last["line_id"])]["text"][last["end"]:].strip()
                separator = candidate["text"].rstrip().endswith(tuple(":.—–-")) or not suffix or suffix[0] in ":.—–-"
                if match and (not prefix or SENTENCE_END.search(prefix)) and separator:
                    located, scope = candidate, "metadata_label"
                elif not match and COPYRIGHT_FOOTER.fullmatch(by_id[str(first["line_id"])]["text"]):
                    located, scope = candidate, "legal_footer_statement"
    return {"kind": kind, "ref": region["ref"], "label": region["text"][:120],
            "source_location": located["status"], "source_spans": located["spans"],
            "source_text_scope": scope,
            "region_boxes": region["boxes"], "tree_order": region["tree_order"]}


def _section_regions(start: dict, ordered: list[dict], explicit: bool, native: list[dict]) -> tuple[list[dict], list[dict]]:
    """Derive a content lane before considering closing headings.

    Heading width does not describe section width. Geometry orders regions only
    inside this lane; transitions into multiple lanes are held by the collector.
    Tree order is retained as evidence, not silently treated as ground truth.
    """
    anchor = start
    separate_heading = explicit and not ABSTRACT.sub("", start["text"]).strip()
    heading = _abstract_heading(start, native) if separate_heading else {}
    heading_bottom = max((s["bbox"][3] for s in heading.get("spans", [])), default=start["bbox"][3])
    if separate_heading:
        following = [x for x in ordered if x["bbox"] and x["ref"] != start["ref"]
                     and x["bbox"][1] >= start["bbox"][3]-2
                     and overlap(start["bbox"], x["bbox"]) >= .5
                     and x["label"] not in EXCLUDED and not _role_rejected(x["text"])]
        if following:
            anchor = min(following, key=lambda x: (x["bbox"][1], x["tree_order"]))
    lane = anchor["bbox"]
    local, decisions, inline_followers = [], [], {}
    for x in ordered:
        if x["ref"] == start["ref"]:
            local.append(x)
        elif not x["bbox"]:
            decisions.append({"ref": x["ref"], "decision": "excluded", "reason": "unlocated_region"})
        elif x["bbox"][1] < start["bbox"][1]-1:
            decisions.append({"ref": x["ref"], "decision": "excluded", "reason": "before_abstract_start"})
        elif separate_heading and x["bbox"][1] < heading_bottom-2:
            # A model union box may begin beside the heading while its text
            # combines unrelated body columns. It cannot preempt a native
            # paragraph below that heading. Recover oversized model boxes only
            # when their native extents follow the heading, including exact
            # later offsets when a converter splits one native line.
            located = locate(x["text"], native, region_boxes=x["boxes"])
            spans = located.get("spans", [])
            heading_ends = {str(s["line_id"]): s["end"] for s in heading.get("spans", [])}
            follows = all(s["bbox"][1] >= heading_bottom-2 or
                          (str(s["line_id"]) in heading_ends and s["start"] >= heading_ends[str(s["line_id"])])
                          for s in spans)
            if (located["status"] == "located" and not located.get("column_change") and spans
                    and follows):
                boxes = [s["bbox"] for s in spans]
                box = [min(b[0] for b in boxes), min(b[1] for b in boxes),
                       max(b[2] for b in boxes), max(b[3] for b in boxes)]
                if overlap(lane, box) >= .5:
                    local.append({**x, "bbox": box, "boxes": boxes})
                    if str(spans[0]["line_id"]) in heading_ends:
                        inline_followers[x["ref"]] = spans[0]["start"]
                    decisions.append({"ref": x["ref"], "decision": "geometry", "reason": "native_extent_after_abstract_heading",
                                      "source_spans": spans, "heading_source_spans": heading.get("spans", [])})
                else:
                    decisions.append({"ref": x["ref"], "decision": "excluded", "reason": "outside_content_lane",
                                      "source_spans": spans})
            else:
                decisions.append({"ref": x["ref"], "decision": "excluded", "reason": "overlaps_abstract_heading_without_following_source_extent",
                                  "source_location": located["status"]})
        elif overlap(lane, x["bbox"]) < .5:
            decisions.append({"ref": x["ref"], "decision": "excluded", "reason": "outside_content_lane"})
        else:
            local.append(x)
    local.sort(key=lambda x: (round(x["bbox"][1], 1), x["bbox"][0], x["tree_order"]))
    # Converter tree order cannot put source-located later offsets before the
    # heading within one native line. Keep those paragraphs in offset order.
    followers = sorted((x for x in local if x["ref"] in inline_followers),
                       key=lambda x: (inline_followers[x["ref"]], x["tree_order"]))
    local = [x for x in local if x["ref"] not in inline_followers]
    index = next(i for i, x in enumerate(local) if x["ref"] == start["ref"])
    return [local[index], *followers, *local[index+1:]], decisions


def _terminal_footnote(alignment: dict, native: list[dict], ordered: list[dict]) -> tuple[str, dict | None]:
    """Remove only a source-styled terminal marker linked to a footnote region."""
    text = alignment["text"]
    if not alignment.get("spans"):
        return text, None
    last = alignment["spans"][-1]
    line = next(x for x in native if str(x["id"]) == str(last["line_id"]))
    for run in reversed(line.get("spans", [])):
        token = line["text"][run["start"]:run["end"]]
        if (run["end"] != last["end"] or run["start"] < last["start"]
                or not run.get("flags", 0) & 1 or not re.fullmatch(r"[0-9*†‡]{1,3}", token)):
            continue
        prefix = text[:-len(token)].rstrip()
        if not SENTENCE_END.search(prefix):
            continue
        notes = [x for x in ordered if x["label"] == "footnote" and x["bbox"]
                 and x["bbox"][1] > line["bbox"][3]
                 and re.match(re.escape(token)+r"(?:\s|\D)", x["text"].lstrip())]
        if len(notes) != 1:
            return text, {"kind": "unresolved_terminal_marker", "marker_span": {**last, "start": run["start"], "text": token},
                          "decision": "held", "reason": "terminal_footnote_marker_requires_source_review"}
        note = _boundary_evidence(notes[0], native, "linked_terminal_footnote")
        native_marker_matches = False
        if note["source_location"] == "located" and note["source_spans"]:
            first = note["source_spans"][0]
            note_line = next(x for x in native if str(x["id"]) == str(first["line_id"]))
            note_prefix = note_line["text"][:first["start"]].strip()
            marker = re.match(r"\s*([0-9*†‡]+)", note_line["text"])
            native_marker_matches = not note_prefix and marker is not None and marker.group(1) == token
        if not native_marker_matches:
            return text, {"kind": "unresolved_terminal_marker", "marker_span": {**last, "start": run["start"], "text": token},
                          "decision": "held", "reason": "terminal_footnote_marker_requires_source_review"}
        return prefix, {**note, "marker_span": {**last, "start": run["start"], "text": token},
                        "decision": "excluded", "reason": "source_superscript_linked_to_footnote"}
    return text, None


def _abstract_heading(start: dict, native: list[dict]) -> dict:
    """Bind an inline heading to its uniquely located paragraph, not a word hit."""
    whole = locate(start["text"], native, region_boxes=start["boxes"])
    if whole["status"] == "located" and whole["spans"]:
        first = whole["spans"][0]
        source = next(n for n in native if str(n["id"]) == str(first["line_id"]))
        match = ABSTRACT.match(source["text"])
        if match and not source["text"][:first["start"]].strip() and match.end() <= first["end"]:
            span = {**first, "start": match.start(), "end": match.end(), "text": match.group()}
            return {"status": "located", "text": match.group(), "spans": [span]}
    return locate(ABSTRACT.match(start["text"]).group(), native, region_boxes=start["boxes"])


def _subsection_scope(start: dict, local: list[dict], native: list[dict], explicit: bool) -> dict:
    """Recognize repeated source-leading inline labels inside an owned abstract.

    A later Methods/Results pair cannot create ownership. The opening prose
    itself must begin with a source label, and every later label stays within
    the same source text size and region lane. Unnumbered custom labels require
    distinct inline typography; the conventional names permit plain labels.
    """
    empty = {"labels": [], "evidence": [], "last_label_ref": None}
    if not explicit:
        return empty
    by_id = {str(n["id"]): n for n in native}
    evidence, first_content, content_size = [], True, None
    seen_lines = set()
    pattern = re.compile(r"\s*([A-Za-z][A-Za-z -]{0,48}?)\s*([:.—–-])\s*(?=\w)")
    for region in local:
        text = ABSTRACT.sub("", region["text"]) if region["ref"] == start["ref"] else region["text"]
        if not text.strip():
            continue
        if region["label"] in EXCLUDED or _role_rejected(text) or _header(text):
            break
        located = locate(text, native, region_boxes=region["boxes"])
        if located["status"] != "located" or located.get("column_change"):
            break
        for span in located["spans"]:
            key = str(span["line_id"])
            if key in seen_lines:
                continue
            seen_lines.add(key)
            line = by_id[key]
            current_size = style(line).get("size")
            if content_size and current_size and not .9 <= current_size/content_size <= 1.1:
                return _confirmed_subsections(evidence)
            if current_size and content_size is None:
                content_size = current_size
            prefix = line["text"][:span["start"]]
            if prefix.strip() and not ABSTRACT.fullmatch(prefix):
                if first_content:
                    return empty
                continue
            match = pattern.match(span["text"])
            label = normalize(match.group(1)).lower() if match else ""
            if len(label.split()) > 5 or _role_rejected(label) or (re.fullmatch(BODY_WORDS, label, re.I) and label not in INTERNAL):
                match = None
            distinctive = False
            if match:
                end = span["start"]+match.end(2)
                runs = [r for r in line.get("spans", []) if r["end"] > span["start"] and r["start"] < end]
                later = [r for r in line.get("spans", []) if r["start"] >= end and r.get("text", "").strip()]
                signatures = lambda rs: {(r.get("font"), r.get("flags", 0) & 18) for r in rs}
                distinctive = bool(runs and later and signatures(runs).isdisjoint(signatures(later)))
                if label not in INTERNAL and not distinctive:
                    match = None
            if first_content and not match:
                return empty
            first_content = False
            if match:
                label_span = {**span, "end": span["start"]+match.end(2), "text": span["text"][:match.end(2)]}
                evidence.append({"label": label, "ref": region["ref"], "source_spans": [label_span],
                                 "inline_typography_distinct": distinctive, "content_size": current_size})
    return _confirmed_subsections(evidence)


def _confirmed_subsections(evidence: list[dict]) -> dict:
    labels = list(dict.fromkeys(e["label"] for e in evidence))
    # Two isolated labels can describe an ordinary body transition. Repeated
    # subsection structure needs at least three distinct source labels.
    confirmed = len(labels) >= 3
    return {"labels": labels if confirmed else [], "evidence": evidence,
            "last_label_ref": evidence[-1]["ref"] if confirmed else None}


def _publication_footer(region: dict, ordered: list[dict], native: list[dict]) -> dict | None:
    """A proceedings block needs its source date and legal-footer context."""
    if not region["bbox"] or not re.match(r"\s*Proceedings\s+of\b", region["text"], re.I):
        return None
    event = locate(region["text"], native, region_boxes=region["boxes"])
    if event["status"] != "located" or not _heading_context(event, native):
        return None
    date_pattern = (r"\s*\d{1,2}\s*(?:[-–—]\s*\d{1,2})?\s+"
                    r"(?:January|February|March|April|May|June|July|August|September|October|November|December)"
                    r"\s*,?\s*\d{4}\s*")
    dates = [x for x in ordered if x["bbox"] and x["ref"] != region["ref"]
             and region["bbox"][3]-2 <= x["bbox"][1] <= region["bbox"][3]+48
             and overlap(region["bbox"], x["bbox"]) >= .5 and re.fullmatch(date_pattern, x["text"], re.I)]
    if len(dates) != 1:
        return None
    date = locate(dates[0]["text"], native, region_boxes=dates[0]["boxes"])
    legal = [n for n in native if n["bbox"][1] >= dates[0]["bbox"][3]
             and overlap(region["bbox"], n["bbox"]) >= .5
             and re.match(r"\s*(?:[©ⓒ]\s*)?Copyright\b", n["text"], re.I)]
    if date["status"] != "located" or len(legal) != 1:
        return None
    line = legal[0]
    legal_span = {"line_id": line["id"], "start": 0, "end": len(line["text"]), "text": line["text"],
                  "bbox": line["bbox"], "box_scope": "native_line_not_character_box", "page_no": 1}
    return {"kind": "publication_event_metadata", "ref": region["ref"], "source_location": "located",
            "source_spans": event["spans"], "date_ref": dates[0]["ref"], "date_source_spans": date["spans"],
            "legal_source_spans": [legal_span], "scope_evidence": "source_proceedings_date_and_legal_footer"}


def _prefix_hold_continuity(start: dict, region: dict, local: list[dict], ownership: list[dict],
                            alignment: dict, native: list[dict]) -> dict | None:
    """Retain review text between source witnesses, never accepted notation.

    The candidate extent proves only where canonical characters occur. A failed
    prefix stays failed, including a separate numerator or broken glyph map.
    """
    candidate = alignment.get("candidate_native_extent", {})
    spans = candidate.get("spans", [])
    if (alignment.get("reason") != "requested_leading_prefix_not_source_bound"
            or candidate.get("status") != "canonical_extent_only"
            or candidate.get("accepted") is not False or not spans):
        return None
    heading = _abstract_heading(start, native)
    if not _heading_context(heading, native, abstract=True):
        return None
    prior = [entry for entry in ownership if entry.get("decision") == "included" and entry.get("source_spans")]
    if not prior or prior[-1].get("source_alignment", {}).get("column_change"):
        return None
    tail = local[next(i for i, item in enumerate(local) if item["ref"] == region["ref"])+1:]
    following = next((item for item in tail if item["label"] not in {"page_header", "page_footer", "footnote"}), None)
    if (not following or following["label"] in EXCLUDED or following["label"] == "section_header"
            or _header(following["text"]) or _role_rejected(following["text"])):
        return None
    after = locate(following["text"], native, region_boxes=None
                   if following["coordinate_source"] == "native_alignment_estimate" else following["boxes"])
    if after["status"] != "located" or after.get("column_change") or not after["spans"]:
        return None
    closing = next((item for item in tail if item["label"] not in EXCLUDED
                    and (item["label"] == "section_header" or _header(item["text"])
                         or _role_rejected(item["text"]))), None)
    if not closing:
        return None
    proof = _boundary_evidence(closing, native, "metadata_or_nonabstract_region"
                               if _role_rejected(closing["text"]) else "body_section")
    if proof["source_location"] != "located" or not proof.get("source_spans"):
        return None
    before = [span for entry in prior for span in entry["source_spans"]]
    try:
        for group in (before, spans, after["spans"]):
            validate_source_spans(group, native)
    except (KeyError, ValueError, TypeError, IndexError):
        return None
    box = lambda group: [min(s["bbox"][0] for s in group), min(s["bbox"][1] for s in group),
                         max(s["bbox"][2] for s in group), max(s["bbox"][3] for s in group)]
    before_box, current_box, after_box = box(before), box(spans), box(after["spans"])
    widths = [b[2]-b[0] for b in (before_box, after_box)]
    if overlap(before_box, after_box) < .8 or min(widths) < max(widths)*.75:
        return None
    left, right = min(before_box[0], after_box[0]), max(before_box[2], after_box[2])
    if any(s["bbox"][0] < left-2 or s["bbox"][2] > right+2 for s in spans):
        return None
    centers = lambda group: [(s["bbox"][1]+s["bbox"][3])/2 for s in group]
    if (min(centers(spans)) <= max(centers(prior[-1]["source_spans"]))
            or min(centers(after["spans"])) <= max(centers(spans))
            or current_box[1]-before_box[3] > 48 or after_box[1]-current_box[3] > 48
            or min(centers(proof["source_spans"])) <= max(centers(after["spans"]))):
        return None
    return {"version": PREFIX_RETENTION_VERSION, "accepted": False,
            "scope": "uncertain_candidate_continuation_only",
            "heading_source_spans": heading["spans"], "prior_ref": prior[-1]["ref"],
            "prior_source_spans": prior[-1]["source_spans"], "following_ref": following["ref"],
            "following_source_spans": after["spans"], "closing_boundary": proof}


def _collect(start: dict, ordered: list[dict], native: list[dict], explicit: bool) -> dict:
    if start["unlocated"]:
        return {"text": ABSTRACT.sub("", start["text"]), "boundary": None, "refs": [start["ref"]], "alignment_failure": "unlocated_ocr_paragraph"}
    local, ownership = _section_regions(start, ordered, explicit, native)
    initial_text=ABSTRACT.sub("",start["text"]).strip() if explicit else start["text"]
    if explicit and not initial_text:
        initial_text=next((x["text"] for x in local[1:] if x["text"].strip()),"")
    # A Methods/Results pair in the later body must not retroactively turn the
    # opening abstract into a structured abstract.
    subsection_scope = _subsection_scope(start, local, native, explicit)
    structured = bool(subsection_scope["labels"]) or (_structured(initial_text) if explicit else False)
    internal_refs = {e["ref"] for e in subsection_scope["evidence"]} if structured else set()
    pieces, refs, boundary, failure = [], [], None, None
    prefix_hold = False
    if explicit:
        heading = _abstract_heading(start, native)
        ownership.append({"ref": start["ref"], "decision": "heading", "reason": "explicit_abstract_start",
                          "source_location": heading["status"], "source_spans": heading["spans"]})
        if not _heading_context(heading, native, abstract=True):
            failure = "unverified_abstract_start_heading"
    previous_style, previous_region = {}, None
    for x in local:
        text = x["text"]
        if x["ref"] == start["ref"] and explicit:
            text = ABSTRACT.sub("", text)
        if not text.strip():
            continue
        if pieces and previous_region:
            # A staggered right-column paragraph may begin slightly above its
            # left-column section heading. Inspect all plausible headings first.
            headings = [h for h in local if h["ref"] not in refs and h["ref"] != start["ref"]
                        and h["bbox"][1] >= previous_region["bbox"][3]-2
                        and (h["bbox"][1] <= x["bbox"][1]+3 or
                             (x["bbox"][1] < previous_region["bbox"][3]-2
                              and h["tree_order"] < x["tree_order"]
                              and h["bbox"][1] <= previous_region["bbox"][3]+48))
                        and h["label"] not in EXCLUDED
                        and (h["label"] == "section_header" or _header(h["text"]) or _role_rejected(h["text"]))
                        and not (h["ref"] in internal_refs or structured and normalize(h["text"]).lower().rstrip(": .") in INTERNAL)]
            if headings:
                h = min(headings, key=lambda h: (h["bbox"][1], h["tree_order"]))
                ambiguous = explicit and normalize(h["text"]).lower().rstrip(": .") in INTERNAL
                kind = "metadata_or_nonabstract_region" if _role_rejected(h["text"]) else "body_section"
                boundary = _boundary_evidence(h, native, "ambiguous_structured_or_body_section" if ambiguous else kind)
                if boundary["source_location"] != "located":
                    failure = "unverified_section_boundary"
                ownership.append({"ref": h["ref"], "decision": "excluded", "reason": "closing_section"})
                break
        internal = x["ref"] in internal_refs or normalize(text).lower().rstrip(": .") in INTERNAL and structured
        if pieces and not internal and (x["label"] == "section_header" or _header(text)):
            ambiguous = explicit and normalize(text).lower().rstrip(": .") in INTERNAL
            boundary = _boundary_evidence(x, native, "ambiguous_structured_or_body_section" if ambiguous else "body_section")
            if boundary["source_location"] != "located":
                failure = "unverified_section_boundary"
            break
        if x["label"] in {"page_header", "page_footer", "footnote"}:
            continue
        if pieces and x["label"] in EXCLUDED:
            boundary = {"kind": "nontext_region_requires_source_review", "ref": x["ref"], "label": x["label"]}
            break
        if pieces and _role_rejected(text):
            boundary = _boundary_evidence(x, native, "metadata_or_nonabstract_region")
            if boundary["source_location"] != "located":
                failure = "unverified_section_boundary"
            break
        if x["label"] in EXCLUDED or _role_rejected(text):
            failure = "nonabstract_start_region"
            break
        if pieces:
            publication = _publication_footer(x, ordered, native)
            if publication:
                boundary = publication
                break
            prefix, embedded = _cut(text, structured)
            if embedded and not prefix.strip():
                # The beginning of a model paragraph may already be an outer
                # heading. Resolve it before a width/gap transition can hold it.
                header_region = {**x, "text": embedded["label"]}
                boundary = _boundary_evidence(header_region, native, embedded["kind"])
                if boundary["source_location"] != "located":
                    failure = "unverified_section_boundary"
                break
        if pieces and previous_region:
            prior_box, box = previous_region["bbox"], x["bbox"]
            width = prior_box[2]-prior_box[0]
            narrowed = box[2]-box[0] < width*.75
            peers = [p for p in local if p["bbox"][1] >= prior_box[3]-2
                     and p["bbox"][1] < box[3] and p["label"] not in EXCLUDED
                     and len(canonical(p["text"])) >= 50 and overlap(box, p["bbox"]) < .1]
            gap = box[1]-prior_box[3]
            overlapping = box[1] < prior_box[3]-2 and x["coordinate_source"] != "native_alignment_estimate"
            if (narrowed and peers) or overlapping or gap > max(48, (prior_box[3]-prior_box[1])*.7):
                boundary = {"kind": "unresolved_section_ownership", "ref": x["ref"],
                            "reason": "multiple_body_lanes" if narrowed and peers else "overlapping_source_regions" if overlapping else "large_source_gap",
                            "region_boxes": x["boxes"], "peer_refs": [p["ref"] for p in peers]}
                ownership.append({"ref": x["ref"], "decision": "held", "reason": boundary["reason"]})
                break
        boxes = None if x["coordinate_source"] == "native_alignment_estimate" else x["boxes"]
        alignment = locate(text, native, region_boxes=boxes)
        if alignment["status"] != "located":
            # Keep the attempted text for inspection, but never trust its boxes.
            pieces.append(text)
            refs.append(x["ref"])
            failure = alignment.get("reason", "unlocated_source")
            continuity = (_prefix_hold_continuity(start, x, local, ownership, alignment, native)
                          if explicit and not structured else None)
            if continuity:
                prefix_hold = True
                ownership.append({"ref": x["ref"], "decision": "held", "reason": failure,
                                  "candidate_native_extent": alignment["candidate_native_extent"],
                                  "slice_evidence": alignment["slice_evidence"], "continuity": continuity})
                previous_region = x
                continue
            break
        if alignment.get("column_change"):
            failure = "unverified_multi_column_continuation"
        source_text = alignment["text"]
        selected_lines = [s["line_id"] for s in alignment["spans"]]
        by_id = {str(n["id"]): n for n in native}
        first_style = style(by_id[str(selected_lines[0])]) if selected_lines else {}
        if pieces and previous_region and previous_style and first_style:
            before_size, after_size = previous_style.get("size"), first_style.get("size")
            if (explicit and before_size and after_size and after_size > before_size*1.15
                    and (not structured or subsection_scope["last_label_ref"] in refs)):
                # A narrow abstract can end above a wider two-column body.
                # A different lane's numbered heading is evidence only after
                # native-owned abstract content and a source size change.
                # Structured scope additionally needs its subsection sequence.
                outer = [h for h in ordered if h["bbox"] and h["ref"] not in refs
                         and previous_region["bbox"][3]-2 <= h["bbox"][1] <= x["bbox"][1]+3
                         and re.fullmatch(r"\s*(?:\d+(?:\.\d+)*|[IVX]+)[.)]?\s+"+BODY_WORDS+r"\s*", h["text"], re.I)]
                proof = [_boundary_evidence(h, native, "body_section") for h in outer]
                verified = [p for p in proof if p["source_location"] == "located"]
                if len(verified) == 1:
                    if structured:
                        boundary = {**verified[0], "scope_evidence": "numbered_outer_heading_after_subsections_and_native_size_change",
                                    "before_style": previous_style, "after_style": first_style}
                    else:
                        # A neighboring column may already contain body text
                        # while this abstract continues. Preserve the bounded
                        # prefix for review, never certify this transition from
                        # font size and a foreign-lane heading alone.
                        boundary = {"kind": "unresolved_section_ownership", "ref": x["ref"],
                                    "reason": "cross_lane_heading_after_native_size_change_requires_review",
                                    "candidate_boundary": verified[0], "source_spans": alignment["spans"],
                                    "before_style": previous_style, "after_style": first_style}
                    break
                elif structured:
                    boundary = {"kind": "unresolved_section_ownership", "ref": x["ref"],
                                "reason": "larger_source_region_after_subsections", "source_spans": alignment["spans"]}
                    break
                # Ordinary abstracts can change math/text font size without
                # ending. With no located outer heading, retain that content
                # and leave closure and geometry to their existing checks.
            if (not explicit and previous_style.get("bold") and not first_style.get("bold")
                    and previous_style.get("fraction", 0) >= .8 and first_style.get("fraction", 0) >= .8
                    and SENTENCE_END.search("\n".join(pieces))):
                boundary = {"kind": "unresolved_section_ownership", "ref": x["ref"],
                            "reason": "unlabelled_group_typography_transition", "source_spans": alignment["spans"],
                            "before_style": previous_style, "after_style": first_style}
                break
            if (before_size and after_size and (after_size < before_size*.85 or
                    (previous_style.get("bold") and not first_style.get("bold") and after_size < before_size))
                    and SENTENCE_END.search("\n".join(pieces))):
                boundary = {"kind": "unresolved_section_ownership", "ref": x["ref"],
                            "reason": "smaller_separate_source_region", "source_spans": alignment["spans"],
                            "before_style": previous_style, "after_style": first_style}
                break
            color_change = first_style["color"] != previous_style["color"]
            if color_change and first_style.get("fraction", 0) >= .8 and SENTENCE_END.search("\n".join(pieces)):
                boundary = {"kind": "separate_source_style_region", "ref": x["ref"],
                            "before_style": previous_style, "after_style": first_style}
                break
        trimmed_text, note = _terminal_footnote(alignment, native, ordered)
        if note:
            source_text = trimmed_text
            ownership.append(note)
            if note["kind"] == "unresolved_terminal_marker":
                failure = note["reason"]
        source_text, semantic = _cut(source_text, structured)
        styled_text, styled = _style_cut(alignment, native) if not structured else (alignment["text"], None)
        if styled and (not semantic or len(styled_text) < len(source_text)):
            source_text, semantic = styled_text, styled
        if source_text.strip():
            pieces.append(source_text)
            refs.append(x["ref"])
            ownership.append({"ref": x["ref"], "decision": "included", "reason": "source_located_section_content",
                              "source_spans": locate(source_text, native)["spans"] if note or semantic else alignment["spans"],
                              "source_alignment": {k: v for k, v in alignment.items() if k not in {"text", "spans"}},
                              "tree_order": x["tree_order"]})
        if note and note["kind"] == "unresolved_terminal_marker":
            break
        if semantic:
            boundary = {**semantic, "ref": x["ref"]}
            break
        previous_region = x
        if selected_lines:
            previous_style = style(by_id[str(selected_lines[-1])])
    if not pieces:
        # Excluding an unverified union box must not turn an observed model
        # candidate into a claim that no prose exists. Retain one such candidate
        # for inspection, with no located spans or complete proposal.
        held_refs = {o.get("ref") for o in ownership if o.get("reason") ==
                     "overlaps_abstract_heading_without_following_source_extent"}
        attempted = [x for x in ordered if x["ref"] in held_refs and x["label"] not in EXCLUDED
                     and not _role_rejected(x["text"]) and not _header(x["text"])
                     and len(canonical(x["text"])) >= 100]
        if len(attempted) == 1:
            pieces.append(attempted[0]["text"])
            refs.append(attempted[0]["ref"])
            failure = failure or "unverified_region_overlaps_abstract_heading"
            ownership.append({"ref": attempted[0]["ref"], "decision": "held",
                              "reason": "unlocated_candidate_retained_for_review"})
    recorded = {entry.get("ref") for entry in ownership}
    for region in local:
        if region["ref"] not in recorded:
            ownership.append({"ref": region["ref"], "decision": "deferred",
                              "reason": "outside_verified_abstract_content"})
    return {"text": "\n".join(pieces), "boundary": boundary, "refs": refs,
            "alignment_failure": "requested_leading_prefix_not_source_bound" if prefix_hold else failure,
            "structured": structured, "ownership": ownership,
            "subsection_scope": subsection_scope}


def seal(result: dict) -> dict:
    result.pop("assessment_sha256", None)
    result["text_sha256"] = hashlib.sha256(result["text"].encode()).hexdigest()
    result["evidence_sha256"] = digest_value({k: result.get(k) for k in (
        "source_sha256", "page_sha256", "physical_page", "text_sha256", "spans", "closing_boundary")})
    result["assessment_sha256"] = digest_value(result)
    return result


def verify_assessment(result: dict) -> None:
    copy = dict(result)
    actual = copy.pop("assessment_sha256", None)
    if digest_value(copy) != actual:
        raise ValueError("assessment_digest_mismatch")
    resealed = seal(copy)
    for key in ("text_sha256", "evidence_sha256", "assessment_sha256"):
        if resealed[key] != result.get(key):
            raise ValueError(key+"_mismatch")
    if result.get("eligible_for_jev") or result.get("verified_admission"):
        raise ValueError("selector_is_not_publication_authority")


def _adjacent_group(first: dict, later: dict, selected: dict, ordered: list[dict], native: list[dict]) -> bool:
    """Collapse paragraph candidates only inside a contiguous source-style group."""
    if later["ref"] not in selected["refs"] or first["ref"] == later["ref"]:
        return False
    by_ref = {r["ref"]: r for r in ordered}
    by_id = {str(n["id"]): n for n in native}
    refs = selected["refs"][:selected["refs"].index(later["ref"])+1]
    previous = None
    for ref in refs:
        region = by_ref[ref]
        located = locate(region["text"], native, region_boxes=region["boxes"])
        if located["status"] != "located" or located.get("column_change"):
            return False
        current = style(by_id[str(located["spans"][0]["line_id"])])
        if previous:
            prior_region, prior = previous
            a, b = prior.get("size"), current.get("size")
            if (not a or not b or not .9 <= b/a <= 1.1 or prior.get("bold") != current.get("bold")
                    or prior.get("color") != current.get("color")
                    or overlap(prior_region["bbox"], region["bbox"]) < .8
                    or not -2 <= region["bbox"][1]-prior_region["bbox"][3] <= max(18, 2*a)):
                return False
        previous = region, style(by_id[str(located["spans"][-1]["line_id"])])
    return True


def _title_context(region: dict, ordered: list[dict], native: list[dict]) -> dict | None:
    """A source-matching bibliographic title cannot supply an abstract role."""
    if region["label"] == "title":
        return {"kind": "title_candidate_requires_source_review", "ref": region["ref"]}
    alignment = locate(region["text"], native, region_boxes=region["boxes"])
    if alignment["status"] != "located" or not region["bbox"]:
        return None
    by_id = {str(n["id"]): n for n in native}
    first = alignment["spans"][0]
    prefix = by_id[str(first["line_id"])]["text"][:first["start"]]
    if prefix.strip() and not ABSTRACT.fullmatch(prefix):
        return {"kind": "unverified_native_candidate_start", "ref": region["ref"],
                "source_spans": alignment["spans"]}
    sizes = [style(by_id[str(s["line_id"])]).get("size", 0) for s in alignment["spans"]]
    neighbors = [n for n in native if region["bbox"][3] <= n["bbox"][1] <= region["bbox"][3]+96
                 and overlap(region["bbox"], n["bbox"]) >= .5]
    neighbor_sizes = [style(n).get("size", 0) for n in neighbors]
    if sizes and neighbor_sizes and min(sizes) > 1.25*max(neighbor_sizes):
        return {"kind": "larger_native_title_typography_requires_review", "ref": region["ref"],
                "source_spans": alignment["spans"], "following_native_line_ids": [n["id"] for n in neighbors]}
    return None


def _frontmatter_candidate(region: dict, ordered: list[dict], native: list[dict]) -> dict | None:
    """Retain an unlabelled source paragraph for attributed ownership review.

    A scholarly field can be empty even when the source has an inset abstract.
    Title, author and affiliation evidence identifies a candidate; it does not
    make typography or page position an automatic section-ownership proof.
    """
    if not region["bbox"] or not NARRATIVE.search(region["text"]):
        return None
    located = locate(region["text"], native, region_boxes=region["boxes"])
    if located["status"] != "located" or located.get("column_change") or not located["spans"]:
        return None
    by_id = {str(n["id"]): n for n in native}
    first = located["spans"][0]
    first_line = by_id[str(first["line_id"])]
    content_size = style(first_line).get("size")
    if not content_size or first_line["text"][:first["start"]].strip():
        return None
    box = [min(s["bbox"][0] for s in located["spans"]), min(s["bbox"][1] for s in located["spans"]),
           max(s["bbox"][2] for s in located["spans"]), max(s["bbox"][3] for s in located["spans"])]
    affiliation_pattern = re.compile(r"\b(?:universit\w*|institut\w*|department|departamento|dipartimento|faculty|school|laborator\w*)\b", re.I)
    affiliations = []
    for prior in ordered:
        if (not prior["bbox"] or prior["bbox"][3] > box[1]+2 or box[1]-prior["bbox"][3] > 48
                or overlap(box, prior["bbox"]) < .5 or len(prior["text"]) > 600
                or not affiliation_pattern.search(prior["text"]) or NARRATIVE.search(prior["text"])):
            continue
        proof = locate(prior["text"], native, region_boxes=prior["boxes"])
        if proof["status"] == "located" and proof["spans"]:
            affiliations.append((prior, proof))
    if not affiliations:
        return None
    affiliation, affiliation_proof = max(affiliations, key=lambda pair: pair[0]["bbox"][3])
    authors, titles = [], []
    for prior in ordered:
        if (not prior["bbox"] or prior["bbox"][3] > affiliation["bbox"][1]+2
                or overlap(box, prior["bbox"]) < .5 or NON_ABSTRACT.match(prior["text"])
                or METADATA_START.match(prior["text"]) or COPYRIGHT_FOOTER.match(prior["text"])):
            continue
        tokens = re.findall(r"[^\W\d_]+", prior["text"], re.UNICODE)
        if not 2 <= len(tokens) <= 60 or NARRATIVE.search(prior["text"]):
            continue
        proof = locate(prior["text"], native, region_boxes=prior["boxes"])
        if proof["status"] != "located" or not proof["spans"]:
            continue
        size = style(by_id[str(proof["spans"][0]["line_id"])]).get("size")
        if size and size > content_size*1.25:
            titles.append((prior, proof))
        elif sum(word[0].isupper() for word in tokens)/len(tokens) >= .65:
            authors.append((prior, proof))
    pairs = [(title, author) for title in titles for author in authors if title[0]["bbox"][3] <= author[0]["bbox"][1]+2]
    if len(pairs) != 1:
        return None
    title, author = pairs[0]
    return {"kind": "unlabelled_frontmatter_candidate_requires_source_review",
            "candidate_ref": region["ref"], "source_spans": located["spans"],
            "title_ref": title[0]["ref"], "title_source_spans": title[1]["spans"],
            "author_ref": author[0]["ref"], "author_source_spans": author[1]["spans"],
            "affiliation_ref": affiliation["ref"], "affiliation_source_spans": affiliation_proof["spans"]}


def _compose_section_spans(selected: dict, native: list[dict]) -> dict | None:
    """Compose located paragraphs when unrelated native lanes interleave them.

    This does not override an ambiguous global occurrence or any per-paragraph
    alignment/column failure. Paragraph extents, not their last short lines,
    establish a monotone lane; every exact native character remains unchanged.
    """
    if selected.get("alignment_failure") or len(selected["refs"]) < 2:
        return None
    entries = [o for o in selected["ownership"] if o.get("decision") == "included"]
    if [e["ref"] for e in entries] != selected["refs"]:
        return None
    spans, occupied, groups = [], set(), []
    previous = None
    for entry in entries:
        current = entry.get("source_spans", [])
        proof = entry.get("source_alignment", {})
        if not current or proof.get("status") != "located" or proof.get("column_change"):
            return None
        validate_source_spans(current, native)
        boxes = [s["bbox"] for s in current]
        box = [min(b[0] for b in boxes), min(b[1] for b in boxes), max(b[2] for b in boxes), max(b[3] for b in boxes)]
        if previous and (box[1] < previous[3]-2 or overlap(box, previous) < .8
                         or max(box[2]-box[0], previous[2]-previous[0]) > 1.65*min(box[2]-box[0], previous[2]-previous[0])):
            return None
        for span in current:
            keys = {(str(span["line_id"]), i) for i in range(span["start"], span["end"])}
            if occupied & keys:
                return None
            occupied |= keys
        spans.extend(current)
        groups.append({"ref": entry["ref"], "bbox": box, "source_alignment": proof})
        previous = box
    extent = [min(g["bbox"][0] for g in groups), groups[0]["bbox"][1],
              max(g["bbox"][2] for g in groups), groups[-1]["bbox"][3]]
    for line in native:
        if (line["bbox"][1] >= extent[1]-2 and line["bbox"][3] <= extent[3]+2
                and overlap(extent, line["bbox"]) >= .8):
            omitted = "".join(ch for i,ch in enumerate(line["text"]) if (str(line["id"]), i) not in occupied)
            if omitted.strip():
                # Same-lane omissions need an explicit exclusion review. An
                # unrelated other column may interleave native object order,
                # but an unselected middle sentence must never disappear.
                return None
    text = "\n".join(s["text"] for s in spans)
    if normalize(text) != normalize(selected["text"]):
        return None
    return {"status": "located", "text": text, "spans": spans, "column_change": False,
            "method": "source_owned_monotone_paragraph_groups", "paragraph_groups": groups}


def assess_document(document: dict, *, page_size, source_sha256, page_sha256,
                    native_lines=None, scholarly_abstract="", max_input_chars=4000,
                    conversion_status="success") -> dict:
    result = {"schema_version": 3, "extractor_version": VERSION, "physical_page": 1,
              "source_sha256": source_sha256 if isinstance(source_sha256, str) else None,
              "page_sha256": page_sha256 if isinstance(page_sha256, str) else None,
              "page_size": [x if isinstance(x, (int, float)) and math.isfinite(x) else None for x in page_size] if isinstance(page_size, (list, tuple)) else None,
              "status": "uncertain", "text": "", "proposal": False, "complete_candidate": False,
              "eligible_for_jev": False, "verified_admission": False,
              "admission": "source_review_required", "reasons": [], "spans": [], "closing_boundary": None,
              "conversion_status": str(conversion_status).lower().split(".")[-1],
              "source_hash_verification": "caller_must_verify_bytes"}
    try:
        if len(page_size) != 2 or any(isinstance(x, bool) or not isinstance(x, (int, float)) or not math.isfinite(x) or x <= 0 for x in page_size):
            raise ValueError("invalid_page_size")
        if not isinstance(max_input_chars, int) or isinstance(max_input_chars, bool) or max_input_chars <= 0:
            raise ValueError("invalid_request_character_budget")
        if any(not isinstance(h, str) or not re.fullmatch(r"[a-f0-9]{64}", h) for h in (source_sha256, page_sha256)):
            raise ValueError("invalid_source_sha256")
        status = result["conversion_status"]
        if status in {"truncated", "length", "max_tokens"}:
            result.update(status="truncated", reasons=["generation_token_limit_reached"])
            return seal(result)
        if status != "success":
            result.update(status="error", reasons=["isolated_conversion_error"])
            return seal(result)
        native = validate_lines(native_lines or [], page_size)
        result["native_sha256"] = digest_value(native)
        ordered = regions(document, list(page_size))
        candidates, collected, frontmatter = [], {}, {}
        for x in ordered:
            if x["label"] in EXCLUDED:
                continue
            if ABSTRACT.match(x["text"]):
                candidates.append((3, x, True, "explicit_abstract_heading"))
            elif not _role_rejected(x["text"]) and len(canonical(x["text"])) >= 100:
                context=_field_context(x,ordered,native) or _title_context(x,ordered,native)
                if context:
                    result.setdefault("rejected_candidate_contexts",[]).append({"candidate_ref":x["ref"],**context})
                    continue
                field = compare(x["text"], scholarly_abstract) if scholarly_abstract else {}
                bold = _source_bold(x, native) and NARRATIVE.search(x["text"])
                if not bold and field.get("precision", 0) < .98:
                    proof = _frontmatter_candidate(x, ordered, native)
                    if proof:
                        candidates.append((0, x, False, "source_frontmatter_paragraph_requires_review"))
                        frontmatter[x["ref"]] = proof
                        collected[x["ref"]] = _collect(x, ordered, native, False)
                    continue
                selected = _collect(x, ordered, native, False)
                collected[x["ref"]] = selected
                group_field = compare(selected["text"], scholarly_abstract) if scholarly_abstract else {}
                if bold:
                    candidates.append((2, x, False, "source_bold_narrative_region"))
                elif field.get("text_match_98") or group_field.get("text_match_98"):
                    candidates.append((1, x, False, "source_paragraph_group_corroborated_by_scholarly_field"))
        if not candidates:
            has_rejected_field = bool(scholarly_abstract and _role_rejected(scholarly_abstract))
            status = "absent" if native and (not scholarly_abstract or has_rejected_field) else "uncertain"
            result.update(status=status, reasons=["no_identified_first_page_abstract" if native else "no_native_source_text_review_image"])
            return seal(result)
        best = max(c[0] for c in candidates)
        candidates = [c for c in candidates if c[0] == best]
        if best < 3 and len(candidates) > 1:
            grouped = []
            for candidate in sorted(candidates, key=lambda c: (c[1]["bbox"][1], c[1]["bbox"][0]) if c[1]["bbox"] else (float("inf"), 0)):
                if not any(_adjacent_group(old[1], candidate[1], collected[old[1]["ref"]], ordered, native) for old in grouped):
                    grouped.append(candidate)
            candidates = grouped
        # Collapse pure repeated headings only when adjacent in the same column.
        if len(candidates) > 1:
            substantive = [c for c in candidates if ABSTRACT.sub("", c[1]["text"]).strip()]
            if len(substantive) == 1 and all(overlap(c[1]["bbox"], substantive[0][1]["bbox"]) >= .8 for c in candidates if c[1]["bbox"]):
                candidates = substantive
        if len(candidates) != 1:
            result["reasons"] = ["multiple_plausible_abstract_regions"]
            result["candidate_refs"] = [c[1]["ref"] for c in candidates]
            return seal(result)
        _, start, explicit, basis = candidates[0]
        selected = collected.get(start["ref"]) or _collect(start, ordered, native, explicit)
        if start["ref"] in frontmatter:
            result["candidate_scope"] = frontmatter[start["ref"]]
        text = selected["text"]
        result.update(text=text, closing_boundary=selected["boundary"], region_refs=selected["refs"],
                      explicit_heading=explicit, proposal_basis=basis, structured=selected.get("structured", False),
                      section_ownership_version=SECTION_OWNERSHIP_VERSION, region_ownership=selected.get("ownership", []),
                      abstract_structure_version=ABSTRACT_STRUCTURE_VERSION, subsection_scope=selected.get("subsection_scope", {}))
        if not text:
            result.update(status="absent", reasons=["heading_without_abstract_prose"])
            return seal(result)
        alignment = locate(text, native)
        if alignment["status"] == "unlocated":
            alignment = _compose_section_spans(selected, native) or alignment
        elif alignment["status"] == "located" and not selected["alignment_failure"]:
            # A 98% global match can omit an entire short native wrap line.
            # Every non-whitespace position selected by the located paragraphs
            # must survive in order, including scientific punctuation. A set
            # comparison alone would accept a permutation of the same glyphs.
            positions = lambda spans: [(str(s["line_id"]), s["start"]+i)
                for s in spans for i, ch in enumerate(s["text"]) if not ch.isspace()]
            expected = positions([s for entry in selected["ownership"]
                if entry.get("decision") == "included" for s in entry.get("source_spans", [])])
            if expected and positions(alignment["spans"]) != expected:
                composed = _compose_section_spans(selected, native)
                if composed:
                    alignment = composed
                else:
                    selected["alignment_failure"] = "global_alignment_changes_owned_source_extent"
        result["source_alignment"] = {k: v for k, v in alignment.items() if k not in {"text", "spans"}}
        if selected["alignment_failure"] or alignment["status"] != "located":
            result.update(status="uncertain", reasons=[selected["alignment_failure"] or alignment.get("reason", "source_alignment_failure")])
        else:
            validate_source_spans(alignment["spans"], native)
            result.update(text=alignment["text"], spans=alignment["spans"], transcription="native_pdf")
            bottom = max(s["bbox"][3] for s in result["spans"])
            if alignment.get("column_change"):
                result.update(status="uncertain", reasons=["unverified_multi_column_continuation"])
            elif not selected["boundary"]:
                partial = bottom >= page_size[1]*.9 and not SENTENCE_END.search(result["text"])
                result.update(status="partial" if partial else "uncertain", reasons=["page_one_continues_without_closure" if partial else "no_explainable_closing_boundary"])
            elif selected["boundary"]["kind"] == "ambiguous_structured_or_body_section":
                result.update(status="uncertain", reasons=["structured_abstract_boundary_requires_review"])
            elif selected["boundary"]["kind"] == "unresolved_section_ownership":
                result.update(status="uncertain", reasons=["section_ownership_requires_source_review"])
            elif (selected["boundary"]["kind"] == "embedded_body_section" and explicit and
                  not selected["structured"] and
                  normalize(selected["boundary"].get("label", "")).lower().rstrip(": .") in INTERNAL):
                # An inline Methods/Results label can be an abstract subsection.
                # Without a witnessed closing section, the prefix is not safe.
                result.update(status="uncertain", reasons=["embedded_structured_section_requires_review"])
            elif selected["boundary"]["kind"] in {"separate_source_style_region", "nontext_region_requires_source_review"}:
                reason="style_transition_requires_source_review" if selected["boundary"]["kind"] == "separate_source_style_region" else "nontext_boundary_requires_source_review"
                result.update(status="uncertain", reasons=[reason])
            elif not SENTENCE_END.search(result["text"]):
                # A formula or unusual punctuation can be complete: hold, do not
                # claim a page break based on punctuation alone.
                result.update(status="uncertain", reasons=["closing_boundary_with_unresolved_terminal_notation"])
            else:
                result.update(status="complete", complete_candidate=True, reasons=["bounded_source_located_proposal"])
        if basis == "source_frontmatter_paragraph_requires_review" and result["status"] == "complete":
            result.update(status="uncertain", complete_candidate=False,
                          reasons=["unlabelled_frontmatter_ownership_requires_source_review"])
        text = result["text"]
        within_budget = len(text) <= max_input_chars
        result["request_budget"] = {"limit_characters": max_input_chars, "characters": len(text),
                                    "status": "within_budget" if within_budget else "exceeded", "text_truncated": False}
        if not within_budget:
            result["reasons"].append("exceeds_request_character_budget")
        result["proposal"] = result["status"] == "complete" and within_budget
        result["section_owner"] = "abstract" if result["status"] == "complete" and result["complete_candidate"] else None
        result["math_review_required"] = bool(re.search(r"[√∫∑∏≤≥∞]|\\(?:frac|sqrt|sum)|\$", text) or
            any(x["label"] == "formula" and x["ref"] in selected["refs"] for x in ordered))
        result["scholarly_alignment"] = compare(text, scholarly_abstract) if scholarly_abstract else None
    except (KeyError, ValueError, TypeError, OverflowError, IndexError) as exc:
        # Do not echo arbitrary upstream exception strings containing private paths.
        result.update(status="error", proposal=False, complete_candidate=False, reasons=["invalid_evidence:"+type(exc).__name__], error_code=str(exc) if isinstance(exc, ValueError) else type(exc).__name__)
    return seal(result)
