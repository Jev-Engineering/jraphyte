# Source-bound abstract boundary follow-up

The v4 collector now checks one narrow case in which a figure label starts a
few points before an inline body heading in another lane. It may use the
heading as closure only when the intervening region is a small one-token label,
the heading lies to its left, the heading prefix is uniquely source-located,
and no source prose precedes that prefix on its native line. The body paragraph
after the heading is never copied into the abstract. The original native lines,
offsets, and boxes are unchanged.

Before a complete proposal is emitted, uniquely located sentence-shaped prose
that the lane model excluded between the accepted abstract and its source
boundary now forces an ownership hold. This protects a short continuation that
would otherwise disappear when a narrow converter box falls outside the
inferred lane. It is a bounded omission check, not proof that every excluded
region is unrelated to the abstract. Cases lacking unique source location or
clear sentence form still need source review.

Derived logical-row joins that explicitly require notation review also set the
assessment's `math_review_required` flag. This applies to both direct global
alignment and composition from source-owned paragraphs. A raw row join does
not resolve radical scope, scripts, fractions, or full-text transcription.

The authored counterexamples cover a source-leading inline heading obscured by
a figure label, converter-stripped preceding source prose, a real sentence in
the other lane, and a narrow off-lane sentence excluded by layout. Exact cached
f142 replay changes its closing-boundary witness to native line 18, offsets
0:12, while preserving its geometry hold. Full 200-paper quality, notation,
and promotion gates must be rerun on the integrated source tree.
