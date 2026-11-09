module cargo_audit {
  // One audit invocation. Filesystem/process/parser internals are abstracted as
  // inputs; trusted binary, isolated cwd/config and copied lockfile are required.
  type State = { phase: str, isolated: bool, launched: bool, valid: bool,
    accepted: bool, saved: bool, count: int, reported: int }
  var s: State
  action init = s' = { phase: "new", isolated: false, launched: false,
    valid: false, accepted: false, saved: false, count: 0, reported: 0 }
  pure def prepared(st: State): State = { ...st, phase: "ready", isolated: true }
  action prepare = all { s.phase == "new", s' = prepared(s) }
  action reject = all { s.phase == "new", s' = { ...s, phase: "error" } }
  action launch = all { s.phase == "ready", s.isolated,
    s' = { ...s, phase: "running", launched: true } }
  pure def acceptable(valid: bool, code: int, findings: int): bool =
    valid and (code == 0 or (code == 1 and findings > 0))
  action finish(valid: bool, code: int, findings: int): bool = all {
    s.phase == "running",
    s' = { ...s, phase: "received", valid: valid,
      accepted: acceptable(valid, code, findings), count: findings }
  }
  action save(ok: bool): bool = all { s.phase == "received",
    s' = { ...s, phase: if (ok and s.accepted) "complete" else "error",
      saved: ok, reported: if (ok and s.accepted) s.count else 0 } }
  action step = {
    nondet valid = Set(true, false).oneOf()
    nondet code = Set(0, 1, 2).oneOf()
    nondet findings = Set(0, 1, 3).oneOf()
    nondet ok = Set(true, false).oneOf()
    any { prepare, reject, launch, finish(valid, code, findings), save(ok) }
  }
  val safety = (s.launched implies s.isolated) and
    (s.phase == "complete" implies (s.valid and s.accepted and s.saved and s.reported == s.count))
  val preparedWitness = s.phase == "ready"
  val launchedWitness = s.launched
  val receivedWitness = s.phase == "received"
  val successWitness = s.phase == "complete" and s.reported > 0
  val failureWitness = s.phase == "error"
}
