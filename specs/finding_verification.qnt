module finding_verification {
  // One candidate, owned by a coordinator. Review sessions are independent
  // provider conversations, not concurrent processes; plain shared state suffices.
  // Schema/source checks and persistence are abstract success/failure inputs.
  type State = { phase: str, revision: int, reviewed: int, reviewer: int,
    finalReviewer: int, verdict: str, saved: bool, published: bool, stale: bool }
  var s: State
  action init = s' = { phase: "candidate", revision: 0, reviewed: -1,
    reviewer: 0, finalReviewer: 0, verdict: "unverified", saved: false,
    published: false, stale: false }
  pure def canReview(st: State): bool = st.phase == "candidate"
  pure def reviewed(st: State, verdict: str): State = { ...st,
    phase: "reviewed", revision: 1, reviewer: 1, verdict: verdict }
  action review(verdict: str): bool = all { canReview(s), s' = reviewed(s, verdict) }
  pure def canCheck(st: State): bool = st.phase == "reviewed" and not(st.stale)
  pure def checked(st: State): State = { ...st, phase: "checked",
    reviewed: st.revision, finalReviewer: st.reviewer + 1 }
  action check = all { canCheck(s), s' = checked(s) }
  // At most one replacement; a second disagreement is incomplete, not accepted.
  pure def replaced(st: State, verdict: str): State = { ...st,
    revision: st.revision + 1, reviewer: st.reviewer + 1, verdict: verdict }
  action replace(verdict: str): bool = all { canCheck(s), s.revision == 1,
    s' = replaced(s, verdict) }
  action invalidate = all { Set("reviewed", "checked").contains(s.phase),
    s' = { ...s, phase: "incomplete", stale: true } }
  action abortReview = all { Set("candidate", "reviewed", "checked").contains(s.phase),
    s' = { ...s, phase: "incomplete" } }
  action persist = all { s.phase == "checked", not(s.stale),
    s' = { ...s, phase: "saved", saved: true } }
  action publish = all { s.phase == "saved", s' = { ...s, phase: "done", published: true } }
  action step = {
    nondet verdict = Set("source_verified", "needs_validation", "rejected").oneOf()
    any { review(verdict), check, replace(verdict), invalidate, abortReview, persist, publish }
  }
  val safety = s.published implies (s.saved and not(s.stale) and
    s.reviewed == s.revision and s.finalReviewer != s.reviewer and s.finalReviewer > 0)
  val reviewWitness = s.phase == "reviewed"
  val replacementWitness = s.revision == 2
  val checkedWitness = s.phase == "checked"
  val savedWitness = s.saved
  val sourceVerifiedWitness = s.published and s.verdict == "source_verified"
  val rejectedWitness = s.published and s.verdict == "rejected"
  val unresolvedWitness = s.published and s.verdict == "needs_validation"
  val staleWitness = s.stale
  val incompleteWitness = s.phase == "incomplete"
  val incompleteNeverGates = s.phase == "incomplete" implies not(s.published)
}
