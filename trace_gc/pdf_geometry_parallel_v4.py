"""Derived logical rows; native lines, offsets and rectangles are never rewritten.

The native DICT line is a text extraction unit, not necessarily a visual row.
This conservative view requires nearby owned-row support plus two-sided
continuation, block-start ownership, or a corroborated flanking script. It is
geometry evidence, not a semantic section boundary or a recovered text direction.
"""
from __future__ import annotations

import math
import unicodedata

VERSION = "native-logical-rows-v2"


def _size(line: dict) -> float:
    spans = line.get("spans", [])
    values = [(float(s.get("size") or 0), max(1, s.get("end", 0)-s.get("start", 0))) for s in spans]
    values = [(size, weight) for size, weight in values if size > 0]
    return max(values, key=lambda pair: pair[1])[0] if values else max(1., (line["bbox"][3]-line["bbox"][1])/1.2)


def _horizontal(line: dict) -> bool:
    direction = line.get("dir", (1, 0))
    return (len(direction) == 2 and direction[0] > .95 and abs(direction[1]) < .1
            and line["bbox"][3]-line["bbox"][1] <= 1.8*_size(line))


def _same_row(a: dict, b: dict) -> bool:
    if not _horizontal(a) or not _horizontal(b):
        return False
    x, y = a["bbox"], b["bbox"]
    em = max(_size(a), _size(b))
    vertical = min(x[3], y[3])-max(x[1], y[1])
    if vertical <= 0:
        return False
    ordinary = vertical/min(x[3]-x[1], y[3]-y[1]) >= .7 and abs((x[1]+x[3]-y[1]-y[3])/2) <= .45*em
    compact = min((a, b), key=lambda line: line["bbox"][2]-line["bbox"][0])
    script = (compact["bbox"][2]-compact["bbox"][0] <= 2*em and vertical >= .15*em
              and abs((x[1]+x[3]-y[1]-y[3])/2) >= .2*em)
    return ordinary or script


def _mid(line: dict) -> float:
    return (line["bbox"][1]+line["bbox"][3])/2


def _similar_extent(a: dict, b: dict) -> bool:
    x, y = a["bbox"], b["bbox"]
    widths = (x[2]-x[0], y[2]-y[0])
    return (max(0., min(x[2], y[2])-max(x[0], y[0])) >= .8*min(widths)
            and max(widths) <= 1.65*max(1., min(widths)))


def _source_evidence(lines: list[dict]) -> list[dict]:
    return [{"line_id": line["id"], "block_id": line.get("block_id"), "bbox": list(line["bbox"])}
            for line in lines]


def _script_flank(compact: dict, baseline: dict, lines: list[dict], em: float) -> dict | None:
    """Require another baseline fragment on the opposite side of a raised run.

    A small raised word is not inherently a script. Flanking text, comparable
    baseline typography and a shared owning block provide separate evidence.
    """
    c, base = compact["bbox"], baseline["bbox"]
    for other in lines:
        if other is compact or other is baseline or not _horizontal(other):
            continue
        box = other["bbox"]
        if (abs(_mid(baseline)-_mid(other)) > .3*em
                or min(_size(baseline), _size(other)) < .85*max(_size(baseline), _size(other))):
            continue
        left_flank = c[2] <= base[0]+.3*em and -.9*em <= c[0]-box[2] <= .3*em
        right_flank = c[0] >= base[2]-.3*em and -.9*em <= box[0]-c[2] <= .3*em
        if (left_flank or right_flank) and compact.get("block_id") is not None and compact.get("block_id") in {baseline.get("block_id"), other.get("block_id")}:
            return other
    return None


def _gutter(left: dict, right: dict, nearby: list[dict], em: float) -> bool:
    """One paired neighboring row is counterevidence to a math seam."""
    x, y = left["bbox"], right["bbox"]
    left_rows = [line for line in nearby if line["bbox"][2] <= y[0]
                 and line["bbox"][0] < x[2]-em]
    right_rows = [line for line in nearby if line["bbox"][0] >= x[2]
                  and line["bbox"][2] > y[0]+em]
    return any(_same_row(a, b) for a in left_rows for b in right_rows)


def _math_operator_join(a: dict, b: dict, lines: list[dict], em: float) -> dict | None:
    """Place a separately extracted symbol between two source-owned flanks.

    This establishes raw reading order only. In particular, a radical's scope
    or a fraction's semantic representation still needs notation review.
    """
    compact = min((a, b), key=lambda line: line["bbox"][2]-line["bbox"][0])
    text, c = compact["text"], compact["bbox"]
    baseline = b if compact is a else a
    if (len(text) != 1 or unicodedata.category(text) != "Sm" or len(_exact_runs(compact)) != 1
            or c[2]-c[0] > 1.2*em
            or _size(compact) < .8*_size(baseline)
            or not .2*em <= _mid(baseline)-_mid(compact) <= em):
        return None
    candidates = []
    for other in lines:
        if other is compact or other is baseline or not _same_row(other, baseline):
            continue
        left, right = sorted((baseline, other), key=lambda line: line["bbox"][0])
        x, y = left["bbox"], right["bbox"]
        owners = {left.get("block_id"), right.get("block_id")}
        if (None in owners or min(x[2]-x[0], y[2]-y[0]) < 4*em
                or abs(_mid(left)-_mid(right)) > .3*em
                or min(_size(left), _size(right)) < .85*max(_size(left), _size(right))
                or abs(c[0]-x[2]) > .15*em or abs(y[0]-c[2]) > .15*em):
            continue
        center = (_mid(left)+_mid(right))/2
        nearby = [line for line in lines if line is not compact and line is not left and line is not right
                  and _horizontal(line) and .7*em < abs(_mid(line)-center) <= 3.2*em]
        if _gutter(left, right, nearby, em):
            continue
        extent = {"bbox": [x[0], min(x[1], y[1]), y[2], max(x[3], y[3])]}
        support = [line for line in nearby if line.get("block_id") in owners and _similar_extent(line, extent)
                   and line["bbox"][0] <= c[0]-em and line["bbox"][2] >= c[2]+em]
        if not any(_mid(line) < center for line in support) or not any(_mid(line) > center for line in support):
            continue
        candidates.append({"reason": "source_flanked_math_operator", "ownership_cue": "two_sided_owned_paragraph_rows",
                           "operator": _source_evidence([compact])[0], "flanks": _source_evidence([left, right]),
                           "support": _source_evidence(support), "notation_review_required": True})
    return candidates[0] if len(candidates) == 1 else None


def _exact_runs(line: dict) -> list[dict]:
    """Use only a complete, ordered native font-run partition with finite boxes."""
    runs, cursor = line.get("spans", []), 0
    for run in runs:
        box, size = run.get("bbox"), run.get("size")
        if (type(run.get("start")) is not int or type(run.get("end")) is not int
                or run["start"] != cursor or not cursor < run["end"] <= len(line["text"])
                or run.get("text") != line["text"][cursor:run["end"]]
                or not isinstance(box, (list, tuple)) or len(box) != 4
                or any(type(v) not in (int, float) or not math.isfinite(v) for v in box)
                or not box[0] < box[2] or not box[1] < box[3]
                or type(size) not in (int, float) or not math.isfinite(size) or size <= 0
                or type(run.get("flags")) is not int or run["flags"] < 0):
            return []
        if any(box[i] < line["bbox"][i]-.05 for i in (0, 1)) or any(box[i] > line["bbox"][i]+.05 for i in (2, 3)):
            return []
        cursor = run["end"]
    return runs if cursor == len(line["text"]) else []


def _stacked_math_join(left: dict, right: dict, lines: list[dict], em: float) -> dict | None:
    """Resolve a block split through an upper/lower script column at row start.

    No Unicode script relation or transcription is inferred from these runs.
    Both native blocks start here and two following owned rows must corroborate
    the combined paragraph extent; a lone title or short fraction cannot do so.
    """
    if (left.get("line_in_block") != 0 or right.get("line_in_block") != 0
            or None in (left.get("block_id"), right.get("block_id"))
            or left.get("block_id") == right.get("block_id")):
        return None
    lr, rr = _exact_runs(left), _exact_runs(right)
    if len(lr) < 3 or len(rr) < 2:
        return None
    base, upper, lower, tail = lr[-2], lr[-1], rr[0], rr[1]
    if (len(base["text"]) != 1 or not base["text"].isalpha() or not base["flags"] & 2
            or len(upper["text"]) != 1 or not upper["text"].isalnum() or not upper["flags"] & 1
            or len(lower["text"]) != 1 or not lower["text"].isalnum()
            or not .5*base["size"] <= upper["size"] <= .8*base["size"]
            or not .5*base["size"] <= lower["size"] <= .8*base["size"]
            or abs(upper["size"]-lower["size"]) > .1*em
            or min(base["size"], tail["size"]) < .9*max(base["size"], tail["size"])):
        return None
    b, u, lo, t = (run["bbox"] for run in (base, upper, lower, tail))
    mid = lambda box: (box[1]+box[3])/2
    if (abs(b[2]-u[0]) > .15*em or abs(u[0]-lo[0]) > .15*em
            or abs(t[0]-max(u[2], lo[2])) > .35*em or abs(mid(t)-mid(b)) > .15*em
            or not .15*em <= mid(b)-mid(u) <= .6*em
            or not .15*em <= mid(lo)-mid(b) <= .6*em):
        return None
    center = mid(b)
    nearby = [line for line in lines if line is not left and line is not right and _horizontal(line)
              and .7*em < abs(_mid(line)-center) <= 3.2*em]
    if _gutter(left, right, nearby, em):
        return None
    extent = {"bbox": [left["bbox"][0], left["bbox"][1], right["bbox"][2], right["bbox"][3]]}
    support = [line for line in nearby if _mid(line) > center and line.get("block_id") == right.get("block_id")
               and type(line.get("line_in_block")) is int and line["line_in_block"] > 0 and _similar_extent(line, extent)]
    levels = []
    for line in sorted(support, key=_mid):
        if not levels or _mid(line)-levels[-1] > .5*em:
            levels.append(_mid(line))
    if len(levels) < 2:
        return None
    return {"reason": "source_stacked_script_seam", "ownership_cue": "two_native_block_starts_and_following_rows",
            "support": _source_evidence(support), "notation_review_required": True,
            "native_runs": [{"line_id": line["id"], "start": run["start"], "end": run["end"],
                             "bbox": list(run["bbox"])}
                            for line, run in ((left, base), (left, upper), (right, lower), (right, tail))]}


def _join_reason(a: dict, b: dict, lines: list[dict], *, context: list[dict] | tuple[dict, ...] = ()) -> dict | None:
    if not _same_row(a, b):
        return None
    left, right = sorted((a, b), key=lambda line: line["bbox"][0])
    x, y = left["bbox"], right["bbox"]
    em = max(_size(a), _size(b))
    gap = y[0]-x[2]
    # Large overlaps are separate overprints/occurrences, not inline fragments.
    if gap < -.9*em or gap > 1.25*em:
        return None
    math_reason = _math_operator_join(a, b, lines, em) or _stacked_math_join(left, right, lines, em)
    if math_reason:
        return math_reason
    center = (max(x[1], y[1])+min(x[3], y[3]))/2
    nearby = [line for line in lines if line is not a and line is not b and _horizontal(line)
              and .7*em < abs(_mid(line)-center) <= 3.2*em]
    # A nearby row spanning this small gap supports one continuous prose region.
    # Full-width titles far above two columns cannot supply this evidence.
    pair_owners = {a.get("block_id"), b.get("block_id")} - {None}
    # Already corroborated fragments of this same anchored visual row can
    # explain an overlapping font run at a native-block split. This evidence
    # cannot authorize a positive whitespace gap across two native blocks.
    owners = pair_owners | ({line.get("block_id") for line in context}-{None} if gap <= 0 else set())
    owner_context = [line["id"] for line in context] if owners != pair_owners else []
    bridges = [line for line in nearby if line.get("block_id") in owners
               and line["bbox"][0] <= x[2]-em and line["bbox"][2] >= y[0]+em]
    # Opposite sides of a repeated vertical gap are columns even when a broken
    # PDF puts them in the same block. One paired row is already counterevidence.
    left_rows = [line for line in nearby if line["bbox"][2] <= y[0] and line["bbox"][0] < x[2]-em]
    right_rows = [line for line in nearby if line["bbox"][0] >= x[2] and line["bbox"][2] > y[0]+em]
    paired = [line for line in left_rows if any(_same_row(line, other) for other in right_rows)]
    if gap >= 0 and paired:
        return None
    compact = min((a, b), key=lambda line: line["bbox"][2]-line["bbox"][0])
    baseline = b if compact is a else a
    displacement = abs((x[1]+x[3]-y[1]-y[3])/2)
    if (bridges and compact["bbox"][2]-compact["bbox"][0] <= 2*em
            and displacement >= .2*em and gap <= .3*em):
        flank = _script_flank(compact, baseline, lines, em)
        if flank:
            return {"reason": "attached_script", "ownership_cue": "flanking_baseline_fragments",
                    "support": _source_evidence(bridges), "flank": _source_evidence([flank])[0],
                    "corroborated_row_context": owner_context}
    if gap > 0 and (len(pair_owners) != 1 or a.get("block_id") is None or b.get("block_id") is None):
        return None
    # Neighboring paragraph-width rows can corroborate a short wrap as well as a
    # full-width row. An above-only header/abstract cannot establish continuation
    # into new columns, even when native extraction merges their block IDs.
    supporting = [line for line in nearby if line.get("block_id") in owners
                  and any(_similar_extent(line, bridge) for bridge in bridges)]
    above = [line for line in supporting if _mid(line) < center]
    below = [line for line in supporting if _mid(line) > center]
    if above and below:
        return {"reason": "nearby_continuous_row", "ownership_cue": "owned_rows_above_and_below",
                "support": _source_evidence(supporting), "corroborated_row_context": owner_context}
    # The first visual row of one native block may have no preceding prose row.
    # Require its real line_in_block=0 anchor and two following row levels.
    first = next((line for line in lines if len(owners) == 1 and line.get("block_id") in owners
                  and line.get("line_in_block") == 0 and _same_row(line, a) and _same_row(line, b)), None)
    levels = []
    for line in sorted(below, key=_mid):
        if not levels or _mid(line)-levels[-1] > .5*em:
            levels.append(_mid(line))
    if first and len(levels) >= 2:
        return {"reason": "nearby_continuous_row", "ownership_cue": "native_block_start_with_two_following_rows",
                "block_start": _source_evidence([first])[0], "support": _source_evidence(below)}
    return None


def logical_rows(lines: list[dict]) -> list[dict]:
    """Build a reversible geometry view without changing any source object.

    A wide anchor prevents a small script from joining consecutive text rows by
    transitivity. Physical x order is used only inside a corroborated visual row.
    """
    pending = sorted(lines, key=lambda line: (-(line["bbox"][2]-line["bbox"][0]), str(line["id"])))
    groups = []
    while pending:
        anchor = pending.pop(0)
        members, joins = [anchor], []
        changed = True
        while changed:
            changed = False
            for candidate in pending[:]:
                if not _same_row(anchor, candidate):
                    continue
                connected = next(((member, reason) for member in members
                                  if (reason := _join_reason(member, candidate, lines, context=members))), None)
                if connected:
                    member, reason = connected
                    members.append(candidate)
                    pending.remove(candidate)
                    joins.append({"native_line_ids": [member["id"], candidate["id"]], **reason})
                    changed = True
        members.sort(key=lambda line: (line["bbox"][0], str(line["id"])))
        boxes = [line["bbox"] for line in members]
        groups.append({"bbox": [min(b[0] for b in boxes), min(b[1] for b in boxes),
                                max(b[2] for b in boxes), max(b[3] for b in boxes)],
                       "lines": members, "joins": joins})
    groups.sort(key=lambda row: (round(row["bbox"][1], 1), row["bbox"][0], str(row["lines"][0]["id"])))
    for index, row in enumerate(groups):
        row["id"] = index
    return groups


def transition_evidence(spans: list[dict], rows: list[dict]) -> dict:
    """Explain unsupported jumps using whole logical rows, never glyph boxes."""
    by_line = {str(line["id"]): row for row in rows for line in row["lines"]}
    selected = []
    for span in spans:
        row = by_line[str(span["line_id"])]
        if not selected or selected[-1]["id"] != row["id"]:
            selected.append(row)
    jumps = []
    for a, b in zip(selected, selected[1:]):
        x, y = a["bbox"], b["bbox"]
        shared = max(0., min(x[2], y[2])-max(x[0], y[0])) / max(1., min(x[2]-x[0], y[2]-y[0]))
        if shared < .5:
            jumps.append({"from_row": a["id"], "to_row": b["id"], "reason": "unsupported_horizontal_transition"})
    return {"version": VERSION, "rows": [{"id": row["id"], "bbox": row["bbox"],
             "native_line_ids": [line["id"] for line in row["lines"]], "joins": row["joins"]}
            for row in selected], "unsupported_transitions": jumps,
            "notation_review_required": any(join.get("notation_review_required", False)
                                            for row in selected for join in row["joins"])}
