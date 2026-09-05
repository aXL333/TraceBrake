# TraceBrake Hang-Likelihood Model — Beta Specification

Status: **Beta specification; instrumentation implemented, trained model not yet admitted**

Repository baseline: `72209c7` (`Add shadow telemetry for hang learning`)

Runtime posture: local, CPU-only, advisory, shadow-first

## 1. Outcome

TraceBrake will estimate whether a process already selected by the deterministic hang detector is genuinely stuck or merely quiet. The score helps the operator prioritise review. It does not establish maliciousness and must not terminate, mute, acknowledge, suppress, or change an alert by itself.

The deterministic detector remains the candidate generator and safety floor. Beta inference runs only after that detector raises a `HangDetectedEvent`.

## 2. Non-negotiable boundary

- Human labels and decisions remain authoritative.
- No automatic process termination, suspension, muting, acknowledgement, threshold change, or alert suppression.
- A score is advisory evidence, never permission or proof.
- Missing, incompatible, stale, or corrupt model data fails to the existing deterministic behaviour.
- Training and inference use no command line, executable path, file content, prompt, credential, or network payload.
- All raw telemetry and labels remain local unless the operator explicitly exports them.
- No GPU work starts without an operator-approved runtime estimate. The expected beta models are CPU-only.

## 3. Implemented beta foundation

Commit `72209c7` adds:

- a versioned `HangFeatureSnapshot` on each new hang candidate;
- append-only `HangOutcomeEvent` records for I/O recovery and process exit;
- explicit `Actually hung`, `Expected idle`, and `Unsure` operator labels in Alert Detail;
- a deterministic join from candidates and outcomes to `HangTrainingRow` values;
- the rule that only explicit binary operator labels become gold supervised labels;
- persistence and regression tests for feature/outcome round trips.

This foundation collects data only. It does not contain a trained model or alter runtime policy.

## 4. Feature schema v1

Each candidate records the following bounded, non-content features:

| Feature | Meaning |
| --- | --- |
| `SilentMinutes` | Whole-process I/O silence at detection |
| `UptimeMinutes` | Process age at detection |
| `SilentFraction` | Silence divided by uptime, clamped to 0–1 |
| `ReadOperations`, `WriteOperations` | Cumulative OS I/O operation counters |
| `TreeProcessCount` | Live processes in the attributed harness tree |
| `RecentlyActiveTreeProcesses` | Tree members with recent I/O |
| `TreeIdleMinutes` | Time since the most recent tree I/O |
| `OperatorIdleMinutes` | Time since local keyboard/mouse input |
| `HarnessActivity` | `Active`, `AtRest`, or `Unknown` |
| `EffectiveThresholdMinutes` | Context-scaled threshold which fired |
| `ThresholdMultiplier` | Applied threshold relaxation |
| `DirectHarnessChild` | Whether the candidate is directly parented by the harness |

`SchemaVersion` is mandatory. A trainer or runtime must reject unknown versions rather than guess.

Process name may be used as a coarse categorical evaluation field, but beta acceptance must include a holdout by process family so memorising `node.exe` or `powershell.exe` cannot pass the gate.

## 5. Outcomes and labels

| Outcome | Source | Supervised label |
| --- | --- | --- |
| `OperatorConfirmedHung` | Human in TraceBrake UI | `1` — gold positive |
| `OperatorExpectedIdle` | Human in TraceBrake UI | `0` — gold negative |
| `OperatorUnsure` | Human in TraceBrake UI | none; abstention |
| `IoResumed` | Automatic observation | none; weak outcome only |
| `ProcessExited` | Automatic observation | none; weak outcome only |

Recovery is deliberately not treated as a negative label: a genuinely stuck process can recover. Natural exit is also ambiguous. Agent assertions, MCP acknowledgements, and model self-reports never become training labels.

Repeated labels for one alert remain auditable. The latest explicit binary operator label is the active gold label; earlier records are not deleted.

## 6. Data and split requirements

### Beta-entry data gate

- Minimum smoke-training gate: 30 gold positives and 30 gold negatives.
- Preferred beta gate: at least 100 of each class across at least three process families and two harness types.
- No single process family may contribute more than 50% of either class without a separately reported stratified result.
- Synthetic examples are tracked separately and never counted as sufficient real-world coverage.

### Evaluation splits

- Group all rows from one process episode together.
- Keep the newest 20% of real labels as a temporal holdout.
- Add a process-family holdout in which at least one common executable family is unseen during training.
- Report real, synthetic, per-harness, and per-process-family results separately.
- Deduplicate repeated alert episodes before training.

## 7. Candidate models

Train and compare, in this order:

1. constant class-prior baseline;
2. regularised logistic regression;
3. one small gradient-boosted tree model.

The smallest model that clears the gates wins. A neural network or language model is out of scope unless these baselines demonstrably fail and the operator approves a new plan.

The shipped artifact must be deterministic, versioned, hash-addressed, under 1 MiB, and load without Python. Prefer a tiny native/managed representation or ONNX only if the runtime dependency is already justified.

## 8. Beta acceptance gates

### B0 — instrumentation

- Feature schema and outcome round trips pass.
- Operator labels do not acknowledge, mute, kill, or modify monitoring.
- Missing telemetry does not change existing detection.

### B1 — dataset

- Data gate in section 6 is met.
- Every gold label traces to an operator UI action and candidate ID.
- Dataset export contains no command line, path, prompt, secret, or payload text.
- Class/process-family counts are reviewed before training.

### B2 — offline model

- Confirmed-hang recall is at least 95% on the real temporal holdout, with the raw numerator/denominator shown.
- False-priority rate on `Expected idle` is at least 40% lower than treating every deterministic candidate as hung.
- Brier score beats the constant class-prior baseline.
- Process-family holdout degradation is reported and does not reduce confirmed-hang recall below 90%.
- Model size is below 1 MiB and single-row CPU inference p95 is below 2 ms on this machine.

Small holdouts can make percentages misleading; raw counts and confidence intervals are required. A numerically passing but obviously underpowered result does not clear the gate.

### B3 — shadow runtime

- Scores are recorded for at least seven days without influencing alerts or actions.
- UI identifies the value as `BETA · advisory` and names the model version.
- Score failures, unknown schemas, or artifact mismatch leave existing behaviour unchanged.
- Operator labels remain available regardless of score.

### B4 — operator review

- Review false-high and false-low examples by process family.
- Confirm latency, log growth, CPU, memory, and popup usability.
- Any proposal to rank notifications or adjust thresholds requires a new explicit operator approval. Automatic enforcement remains out of scope.

## 9. Safe synthetic fixture set

Synthetic fixtures may validate the pipeline and broaden edge cases. They must be local, disposable children contained in a job object with a hard timeout and cleanup proof.

Positive fixtures:

- two fixture threads deadlocked on test-only locks;
- a child waiting forever on a never-signalled local event;
- a worker deliberately blocked after a finite setup phase.

Negative fixtures:

- a sleeping child;
- a child waiting for stdin;
- an idle local server with no external listener;
- a bursty worker or file watcher;
- a CPU-bound child with no I/O.

Fixtures must not use persistence, elevation, credential access, security-control changes, external networking, destructive commands, or uncontrolled process spawning. Stop immediately if a child escapes containment, cleanup fails, system load becomes disruptive, or unrelated alerts appear.

## 10. Beta implementation sequence

1. Deploy/restart the instrumentation build and collect real operator labels.
2. Add a local exporter that consumes `HangLearning.BuildRows` and emits a schema-versioned, content-free dataset plus a class/process-family summary.
3. Add the contained synthetic fixture runner and mark every row `synthetic=true`.
4. Train/evaluate the three baselines after B1 is met; do not tune on the temporal holdout.
5. Package the winning artifact with manifest, feature schema, metrics, hash, and reproducible training command.
6. Integrate score computation in shadow mode only and complete B3/B4.

## 11. Handoff scope

The receiving implementation agent should begin with steps 2 and 3 only: exporter, summaries, safe fixture runner, tests, and documentation. It must not train or integrate a score until the real-label gate is met or the operator explicitly authorises an earlier experiment. It must preserve the current dirty checkout and stage/commit only its scoped files.
