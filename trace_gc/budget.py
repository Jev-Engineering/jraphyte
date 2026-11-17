"""Shared, persistent, monotonic per-run budgets across services and retries."""
from __future__ import annotations
from contextlib import nullcontext
import sqlite3
from pathlib import Path
from typing import Any, Mapping
from .canonical import dumps, loads
from .errors import ContractError, require

RESOURCES = {"retrieval_requests","model_calls","retries","solver_expansions","review_actions","request_bytes"}

class RunBudget:
    def __init__(self, path: str | Path, run_id: str, limits: Mapping[str,int], *, phase_authority=None):
        require(bool(run_id) and set(limits) == RESOURCES,"BUDGET_CONFIG","all resource limits required")
        require(all(type(x) is int and x >= 0 for x in limits.values()),"BUDGET_CONFIG","nonnegative integer limits")
        self.path, self.run_id = str(path), run_id
        self._phase_authority = phase_authority
        self._phase_guard = phase_authority.write if phase_authority is not None else None
        if phase_authority is None:
            self.db = sqlite3.connect(self.path, isolation_level=None, timeout=10, check_same_thread=False)
        else:
            self.db = sqlite3.connect(f"file:{Path(self.path).as_posix()}?mode=rw", uri=True,
                                      isolation_level=None, timeout=10, check_same_thread=False)
        import threading
        self._lock = threading.RLock()
        phase_scope = None
        phase_entered = False
        try:
            marker_exists = self.db.execute("SELECT 1 FROM sqlite_master WHERE type='table' "
                                            "AND name='trace_phase_binding'").fetchone() is not None
            if marker_exists:
                from .phase_authority import PhaseAuthority, binding_sha256
                marker = self.db.execute("SELECT binding_sha256 FROM trace_phase_binding WHERE id=1").fetchone()
                require(type(phase_authority) is PhaseAuthority and marker is not None and
                        marker[0] == binding_sha256(phase_authority.binding),
                        "PHASE_GUARD", "persisted budget phase requires exact authority")
            else:
                require(phase_authority is None, "PHASE_GUARD", "budget phase marker absent")
            if phase_authority is not None:
                binding = phase_authority.binding
                require(run_id == binding["run_id"], "PHASE_BUDGET",
                        "budget run differs from the phase binding")
                active = Path(binding["activation_path"]).exists()
                phase_scope = phase_authority.write() if active else phase_authority.staging()
                phase_scope.__enter__()
                phase_entered = True
                current = self.snapshot()
                require(current["limits"] == dict(limits), "BUDGET_CONFIG_CHANGED",
                        "cannot reset an existing run's limits")
                if active:
                    from .phase_transition import _read_once
                    capsule = loads(_read_once(binding["capsule_path"], binding["capsule_sha256"]))
                    self._verify_phase_floor(capsule["budget_snapshot"])
            else:
                self.db.execute("CREATE TABLE IF NOT EXISTS trace_budgets (run_id TEXT PRIMARY KEY, limits TEXT NOT NULL, used TEXT NOT NULL)")
                with self._lock:
                    self.db.execute("BEGIN IMMEDIATE")
                    self.db.execute("INSERT OR IGNORE INTO trace_budgets VALUES (?,?,?)",(run_id,dumps(dict(limits)),dumps({k:0 for k in limits})))
                    current = self.db.execute("SELECT limits FROM trace_budgets WHERE run_id=?",(run_id,)).fetchone()
                    require(loads(current[0]) == dict(limits),"BUDGET_CONFIG_CHANGED","cannot reset an existing run's limits")
                    self.db.execute("COMMIT")
        except BaseException:
            try:
                if self.db.in_transaction:self.db.execute("ROLLBACK")
            finally:
                self.db.close()
            raise
        finally:
            if phase_entered:
                phase_scope.__exit__(None, None, None)

    def consume(self, resource: str, amount: int = 1) -> dict[str,int]:
        return self.consume_many({resource:amount})

    def bind_phase_guard(self, guard) -> None:
        require(self._phase_authority is not None and guard == self._phase_authority.write,
                "PHASE_GUARD", "budget authority must be installed at database open")

    def consume_many(self, requests: Mapping[str,int]) -> dict[str,int]:
        require(set(requests) <= RESOURCES and all(type(v) is int and v >= 0 for v in requests.values()),
                "BUDGET_REQUEST","invalid resource or amount")
        with (self._phase_guard() if self._phase_guard is not None else nullcontext()):
            return self._consume_many_locked(requests)

    def _consume_many_locked(self, requests: Mapping[str,int]) -> dict[str,int]:
        with self._lock:
            self.db.execute("BEGIN IMMEDIATE")
            try:
                limit_text, used_text = self.db.execute("SELECT limits,used FROM trace_budgets WHERE run_id=?",(self.run_id,)).fetchone()
                limits, used = loads(limit_text), loads(used_text)
                require(all(used[k]+v <= limits[k] for k,v in requests.items()),"RUN_BUDGET_EXHAUSTED","shared run cap reached")
                for key,value in requests.items():used[key] += value
                self.db.execute("UPDATE trace_budgets SET used=? WHERE run_id=?",(dumps(used),self.run_id))
                self.db.execute("COMMIT")
                return dict(used)
            except BaseException:
                if self.db.in_transaction:self.db.execute("ROLLBACK")
                raise

    def snapshot(self) -> dict[str,Any]:
        with self._lock:
            row=self.db.execute("SELECT limits,used FROM trace_budgets WHERE run_id=?",(self.run_id,)).fetchone()
            require(row is not None, "PHASE_BUDGET", "restored run budget row is missing")
            return {"run_id":self.run_id,"limits":loads(row[0]),"used":loads(row[1])}

    def _verify_phase_floor(self, historical):
        current = self.snapshot()
        floor, used, limits = historical["used"], current["used"], current["limits"]
        require(historical["run_id"] == current["run_id"] and limits == historical["limits"] and
                set(floor) == set(used) == set(limits) == RESOURCES and
                all(type(used[key]) is int and 0 <= floor[key] <= used[key] <= limits[key]
                    for key in RESOURCES),
                "PHASE_BUDGET", "current budget differs from its inherited allocation or counters")
        return current

    def close(self) -> None:
        self.db.close()

    def __enter__(self):return self
    def __exit__(self,*args):self.close()
