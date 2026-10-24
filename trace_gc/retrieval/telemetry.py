"""Opt-in, thread-local measurements; never scientific evidence or access policy.

Counters stay outside canonical records and do not affect cache identities.
No query text, source text, credentials, or signing material is recorded here.
"""
from __future__ import annotations

from collections import Counter
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass, field
from functools import wraps
from time import perf_counter_ns
from typing import Any, Iterator


@dataclass
class RetrievalMeasurements:
    acl_calls: Counter = field(default_factory=Counter)
    acl_elapsed_ns: int = 0
    domain_hops: Counter = field(default_factory=Counter)
    _acl_depth: int = 0

    def as_dict(self) -> dict[str, Any]:
        return {"acl_calls": dict(sorted(self.acl_calls.items())),
                "acl_elapsed_ms": self.acl_elapsed_ns / 1_000_000,
                "domain_hops": dict(sorted(self.domain_hops.items())),
                "acl_timing": "outermost ACL call wall time; nested calls counted but not double-timed"}


_ACTIVE: ContextVar[RetrievalMeasurements | None] = ContextVar("trace_retrieval_measurements", default=None)


def active() -> bool:
    return _ACTIVE.get() is not None


@contextmanager
def measure_retrieval() -> Iterator[RetrievalMeasurements]:
    measurement = RetrievalMeasurements()
    token = _ACTIVE.set(measurement)
    try:
        yield measurement
    finally:
        _ACTIVE.reset(token)


def measured_acl(name: str):
    """Measure a guard without changing its return, exception, or deny behavior."""
    def decorate(function):
        @wraps(function)
        def measured(*args, **kwargs):
            measurement = _ACTIVE.get()
            if measurement is None:
                return function(*args, **kwargs)
            outer = measurement._acl_depth == 0
            start = perf_counter_ns() if outer else 0
            measurement.acl_calls[name] += 1
            measurement._acl_depth += 1
            try:
                return function(*args, **kwargs)
            finally:
                measurement._acl_depth -= 1
                if outer:
                    measurement.acl_elapsed_ns += perf_counter_ns() - start
        return measured
    return decorate


def domain_hop(left: set[tuple[str, str]], right: set[tuple[str, str]], *, channel: str) -> None:
    """Call only after both edges and their sources have passed current ACLs.

    Each pair is (immutable taxonomy hash, stable domain ID). Unknown membership
    is counted separately, never called a cross-domain or same-domain success.
    Counts are executed transitions, not unique edges or distributed RPCs.
    """
    measurement = _ACTIVE.get()
    if measurement is None:
        return
    measurement.domain_hops[channel + ":transitions"] += 1
    if not left or not right:
        measurement.domain_hops[channel + ":unclassified_transitions"] += 1
    else:
        if left != right:
            measurement.domain_hops[channel + ":membership_changing_transitions"] += 1
        if not left.intersection(right):
            measurement.domain_hops[channel + ":disjoint_domain_transitions"] += 1
