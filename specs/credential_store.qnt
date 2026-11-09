module credential_store {
  // One sequential client; store calls are atomic outcomes. No concurrent first
  // DEK creation, OS compromise, crypto internals, or filesystem-write failures.
  // DEKs: -1 malformed, 0 missing, 1 existing, 2 newly persisted.
  type Outcome = Pending | Encrypted | Plaintext | ReadOk | ReadError
  type State = {
    phase: str, dek: int, originalDek: int, fileKey: int,
    accessible: bool, legacy: bool, creates: int, outcome: Outcome,
  }
  var s: State
  action start(dek: int, fileKey: int, accessible: bool): bool =
    s' = { phase: "old", dek: dek, originalDek: dek, fileKey: fileKey,
           accessible: accessible, legacy: true, creates: 0, outcome: Pending }
  action init: bool = {
    nondet dek = Set(-1, 0, 1).oneOf()
    nondet fileKey = Set(0, 1).oneOf()
    nondet accessible = Set(false, true).oneOf()
    start(dek, fileKey, accessible)
  }
  pure def canUpgrade(state: State): bool = state.phase == "old"
  pure def upgraded(state: State): State = { ...state, phase: "ready" }
  action upgrade: bool = all { canUpgrade(s), s' = upgraded(s) }
  pure def canOperate(state: State): bool = state.phase == "ready"
  pure def afterRead(state: State): State = {
    val readable = state.fileKey == 0 or
      (state.accessible and state.dek > 0 and state.dek == state.fileKey)
    { ...state, phase: "read", outcome: if (readable) ReadOk else ReadError }
  }
  action read: bool = all { canOperate(s), s' = afterRead(s) }
  pure def afterWrite(state: State, persist: bool): State = {
    val reuse = state.accessible and state.dek > 0
    val create = state.accessible and state.dek == 0 and persist
    val key = if (create) 2 else state.dek
    { ...state, phase: "write", dek: key,
      creates: if (create) 1 else 0,
      fileKey: if (reuse or create) key else 0,
      outcome: if (reuse or create) Encrypted else Plaintext }
  }
  action write(persist: bool): bool = all { canOperate(s), s' = afterWrite(s, persist) }
  pure def canCleanup(state: State): bool = canOperate(state) and state.legacy
  pure def afterCleanup(state: State): State = { ...state, legacy: false }
  action cleanupLegacy: bool = all { canCleanup(s), s' = afterCleanup(s) }
  val upgradedWitness = s.phase == "ready"
  val readWitness = s.phase == "read"
  val writeWitness = s.phase == "write" and s.outcome == Encrypted
  val createWitness = s.creates == 1
  val fallbackWitness = s.phase == "write" and s.outcome == Plaintext
  val cleanupWitness = not(s.legacy)
  val safety = and {
    s.originalDek != 0 implies s.dek == s.originalDek,
    s.phase == "read" implies s.creates == 0,
    (s.phase == "read" and s.fileKey > 0 and s.outcome == ReadOk)
      implies (s.accessible and s.dek == s.fileKey),
    s.outcome == Encrypted implies (s.dek > 0 and s.fileKey == s.dek),
    s.creates == 1 implies (s.originalDek == 0 and s.dek == 2),
  }
  action step: bool = any { upgrade, cleanupLegacy, read, write(false), write(true) }
}
