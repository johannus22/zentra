module cargo_audit_test {
  import cargo_audit.* from "./cargo_audit"
  run findingsTest = init.then(prepare).then(launch)
    .then(finish(true, 1, 3)).then(save(true))
    .expect(s.phase == "complete" and s.reported == 3 and safety)
  run warningsTest = init.then(prepare).then(launch)
    .then(finish(true, 0, 1)).then(save(true))
    .expect(s.phase == "complete" and s.reported == 1)
  run invalidTest = init.then(prepare).then(launch)
    .then(finish(false, 0, 0)).then(save(true)).expect(s.phase == "error")
  run failedProcessTest = init.then(prepare).then(launch)
    .then(finish(true, 2, 3)).then(save(true)).expect(s.phase == "error")
  run failedSaveTest = init.then(prepare).then(launch)
    .then(finish(true, 0, 0)).then(save(false)).expect(s.phase == "error")
  run missingLockTest = init.then(reject).expect(not(s.launched))
}
