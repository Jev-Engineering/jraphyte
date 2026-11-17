# Mixed prefix and sealed conversion recovery

`src.parallel_source_v4.assessment_migration_v3` is a new, fail-closed migration for a stopped full-corpus assessment run with an exact row prefix and one authenticated converter result at the next ID. It preserves the stopped output and starts a new output/protocol. It does not call the converter for imported rows or the pending sealed result.

`prepare` checks the stopped executing checkout and interpreter against its own HEAD/code/runtime, replays every sealed row through the frozen original implementation (including nested V2 imports), checks an exact prefix and one next intent/conversion/document, and writes only a new external migration plan. An absent/partial/extra pending attempt blocks. `run` repeats those checks, requires a fresh source-verified gate for the new method closure, and reassesses all prefix rows plus the pending cached document under the current source-verifier code before creating a converter session. The pending row records the old call and `new_model_call:false`. The ordinary producer begins at the next ID only after these imported rows are sealed and verified.

The existing `assessment_migration_v2` requires an empty pre-intent next directory and cannot handle this boundary; V1 assumes every prior row has an attempt directory and cannot handle nested V2 imports. Neither existing CLI can safely replace V3.

For issue53's stopped d06308 boundary, the old output has 2,333 contiguous receipts, a sealed successful d06308 conversion, and no d06308 assessment or row. The original cutoff and all source, model, graph, review and owner gates still apply. A new plan is not launch authority; exact final code, source gate, tree/lock state, plan, supervisor, deadline and resource readback are required before any live `run`. Do not retry the old converter or edit its origin artifacts.

CLI shape (paths and SHA placeholders require exact external pins after final code review):

```powershell
& $Eval -B -s -m src.parallel_source_v4.assessment_migration_v3 prepare --data-root $DataRoot --origin-output $OldOutput --new-output $NewOutput --origin-checkout $StoppedD908Checkout --origin-interpreter $Eval --origin-head $StoppedHead --origin-protocol-sha256 $StoppedProtocolSha --expected-prefix-count 2333 --max-documents-per-session 64
& $Eval -B -s -m src.parallel_source_v4.assessment_migration_v3 run --data-root $DataRoot --origin-output $OldOutput --new-output $NewOutput --origin-checkout $StoppedD908Checkout --origin-interpreter $Eval --origin-head $StoppedHead --origin-protocol-sha256 $StoppedProtocolSha --expected-prefix-count 2333 --max-documents-per-session 64 --gate-receipt $NewGateReceipt --gate-receipt-sha256 $NewGateSha --gate-policy $NewGatePolicy --gate-policy-sha256 $NewPolicySha --gate-configuration $Configuration --gate-source-map $SourceMap
```

The `run` command is illustrative and remains held until exact external approval and original-window resource safeguards. The source gate must be genuinely remeasured after the final source repair and bind its complete method/image closures, original 91 IDs and source-fidelity criterion.

Offline tests cover resume refusals for a changed plan, changed origin,
code/runtime drift, a gate that is not PASS or has a different method closure,
owner-lock collision, and changed native inputs. These are synthetic-fixture
tests, not a recovered run.
