module finding_verification_test {
  import finding_verification.* from "./finding_verification"
  run verifiedTest = init.then(review("source_verified")).then(check)
    .then(persist).then(publish).expect(safety and sourceVerifiedWitness)
  run rejectedTest = init.then(review("rejected")).then(check)
    .then(persist).then(publish).expect(safety and rejectedWitness)
  run unresolvedTest = init.then(review("needs_validation")).then(check)
    .then(persist).then(publish).expect(safety and unresolvedWitness)
  run replacementTest = init.then(review("rejected")).then(replace("source_verified"))
    .expect(not(s.published) and s.reviewed != s.revision).then(check)
    .then(persist).then(publish).expect(safety and s.finalReviewer == 3)
  run providerFailureTest = init.then(abortReview).expect(incompleteNeverGates and incompleteWitness)
  run finalReviewFailureTest = init.then(review("source_verified")).then(abortReview)
    .expect(incompleteNeverGates and incompleteWitness)
  run persistenceFailureTest = init.then(review("source_verified")).then(check).then(abortReview)
    .expect(incompleteNeverGates and not(s.saved))
  run staleEvidenceTest = init.then(review("source_verified")).then(check).then(invalidate)
    .expect(incompleteNeverGates and staleWitness)
}
