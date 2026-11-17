# Authored verifier closure fixtures

Synthetic, authored verifier sources for `tests/test_verifier_closure_loader.py`
(issue #97). They model the shape of an external qualification verifier: a
top-level entry whose decision lives in an imported helper. They are not the
private V6 evaluator, not the real issue20, issue22 or recovery verifiers, and a
PASS from them is never qualification evidence. Tests copy them to a temporary
root before mutating anything.
