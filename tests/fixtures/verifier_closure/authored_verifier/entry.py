"""Top-level authored verifier. Its decision lives entirely in the helper."""
from . import helper


def evaluate(inputs):
    return helper.decide(inputs)
