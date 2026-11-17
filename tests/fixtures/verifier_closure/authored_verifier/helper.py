"""Authored decision helper. Only this file changes in the HOLD-to-PASS case."""
import json

from .criteria import THRESHOLD


def decide(inputs):
    observed = json.loads(json.dumps(inputs))["observed"]
    return "PASS" if observed >= THRESHOLD else "HOLD"
