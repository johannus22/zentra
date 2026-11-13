module dast_verification {
  // Reuse the source-review lifecycle, extending its evidence prerequisite for
  // DAST. One coordinator owns state; provider sessions return records, not messages.
  import finding_verification as Review from "./finding_verification"
  var observed: bool
  action init = all { Review::init, observed' = false }
  action replay = all { Review::s.phase == "candidate", not(observed),
    Review::s' = Review::s, observed' = true }
  action propose(verdict: str): bool = all {
    verdict != "runtime_verified" or observed,
    Review::review(verdict), observed' = observed }
  action check = all { Review::check, observed' = observed }
  action replace(verdict: str): bool = all {
    verdict != "runtime_verified" or observed,
    Review::replace(verdict), observed' = observed }
  action invalidate = all { Review::invalidate, observed' = observed }
  action abortReview = all { Review::abortReview, observed' = observed }
  action persist = all { Review::persist, observed' = observed }
  action publish = all { Review::publish, observed' = observed }
  action step = {
    nondet verdict = Set("runtime_verified", "needs_validation", "rejected").oneOf()
    any { replay, propose(verdict), check, replace(verdict), invalidate,
      abortReview, persist, publish }
  }
  val safety = Review::safety and (Review::s.published and
    Review::s.verdict == "runtime_verified" implies observed)
  val incompleteNeverGates = Review::incompleteNeverGates
  val replayWitness = observed
  val reviewWitness = Review::reviewWitness
  val replacementWitness = Review::replacementWitness
  val checkedWitness = Review::checkedWitness
  val savedWitness = Review::savedWitness
  val runtimeWitness = Review::s.published and Review::s.verdict == "runtime_verified"
  val rejectedWitness = Review::rejectedWitness
  val unresolvedWitness = Review::unresolvedWitness
  val staleWitness = Review::staleWitness
  val incompleteWitness = Review::incompleteWitness
}
