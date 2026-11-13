module dast_verification_test {
  import dast_verification.* from "./dast_verification"
  run reproducedTest = init.then(replay).then(propose("runtime_verified"))
    .then(check).then(persist).then(publish).expect(safety and runtimeWitness)
  run unresolvedTest = init.then(propose("needs_validation")).then(check)
    .then(persist).then(publish).expect(safety and unresolvedWitness)
  run rejectedTest = init.then(replay).then(propose("rejected")).then(check)
    .then(persist).then(publish).expect(safety and rejectedWitness)
  run replacedTest = init.then(replay).then(propose("runtime_verified"))
    .then(replace("needs_validation")).then(check).then(persist).then(publish)
    .expect(safety and replacementWitness and unresolvedWitness)
  run failureTest = init.then(abortReview).expect(incompleteNeverGates and incompleteWitness)
  run staleTest = init.then(replay).then(propose("runtime_verified")).then(check)
    .then(invalidate).expect(incompleteNeverGates and staleWitness)
  run saveFailureTest = init.then(replay).then(propose("runtime_verified"))
    .then(check).then(abortReview).expect(incompleteNeverGates and incompleteWitness)
}
