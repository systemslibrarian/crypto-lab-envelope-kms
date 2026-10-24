# Key-evolving audit-log teaching brief

This extension compares the existing unkeyed hash-chain lesson with two keyed
logging modes: a deliberately unsafe static-key control and a key-evolving
forward-integrity adaptation. It is a **Schneier–Kelsey-shaped teaching model**:
each period uses fresh authentication material derived from evolving secret
state, and the logger is assumed to erase old state. It is not an
implementation of the full Schneier–Kelsey protocol, not the exact
Bellare–Yee construction, and not a security proof.

## 1. Claim and compromise boundary

The narrow claim is:

> If the logger is compromised immediately before period `c`, disclosure of
> its current state `S_c` lets an attacker authenticate period `c` and later
> records, but does not supply the erased state or tag keys for periods before
> `c`.

The boundary is literal. A record at period `c - 1` is earlier and a record at
period `c` is exposed. The implementation and tests exercise both sides of
that boundary. This claim assumes HMAC-SHA-256 and the one-way evolution step
remain secure, the verifier's initial state remains secret, and every owned
copy of each old state and tag key is erased before compromise.

JavaScript does not provide a reliable memory-erasure primitive. The module
overwrites the `Uint8Array` copies it owns, but a browser engine, debugger,
extension, copied buffer, crash image, or garbage collector may retain other
copies. Erasure is therefore an explicit teaching-model assumption, not a
browser guarantee.

## 2. Executable construction

The verifier and logger begin with an independently provisioned random 32-byte
state `S_0` and a non-empty log identifier. Periods are zero-based. For the
key-evolving mode, period `i` computes separate HMAC branches:

```text
tagKey_i = HMAC-SHA-256(
  S_i,
  FRAME(TAG_KEY_DOMAIN, "FORWARD_SECURE", logId, u64be(i))
)

S_(i+1) = HMAC-SHA-256(
  S_i,
  FRAME(UPDATE_DOMAIN, "FORWARD_SECURE", logId, u64be(i))
)
```

The record authenticator is:

```text
tag_i = HMAC-SHA-256(
  tagKey_i,
  FRAME(
    RECORD_DOMAIN,
    version,
    scheme,
    logId,
    u64be(i),
    kind,
    message,
    previousTag
  )
)
```

`previousTag` is 32 zero bytes at genesis and the preceding record's tag
afterward. The period and link make internal deletion, insertion and
reordering fail verification; deleting a tail can still leave a valid prefix.
`kind` is either `EVENT` or terminal `CLOSE`.

`FRAME` starts with a four-byte big-endian field count. Every field is then a
four-byte big-endian byte length followed by exactly those bytes. Numbers use
fixed-width unsigned big-endian encoding. Strings must be well-formed UTF-16
and use their exact UTF-8 encoding. These rules make boundaries unambiguous:
for example, fields `("ab", "c")` cannot collide with `("a", "bc")`. The exact
ASCII domain strings are:

- `crypto-lab/envelope-kms/log/v1/tag-key`
- `crypto-lab/envelope-kms/log/v1/update`
- `crypto-lab/envelope-kms/log/v1/record`

The logger derives `tagKey_i` and `S_(i+1)` as separate PRF branches. It never
uses raw `S_i` directly as the record HMAC key. After the computations it
best-effort zeroizes its owned `tagKey_i` and `S_i` arrays.

The static comparison retains one state for the life of the log. It still
derives a domain-separated, period-specific tag key, but compromise of the
unchanged master state allows the attacker to derive every earlier and later
tag key. It is a control, not a recommended logging design.

## 3. Threat model and executable attacks

The attacker controls the stored log after compromise and receives exactly
the state present immediately before the selected period. The attacker may
edit, delete, reorder, truncate or replace records and may compute HMAC and
state-evolution functions. The attacker does not receive the verifier's
separate `S_0`, recover an erased prior state, break HMAC-SHA-256, or violate
the modeled erasure assumption.

`rewriteFromCompromise` demonstrates the exact boundary:

- in key-evolving mode, rewriting `c - 1` changes bytes without a usable new
  tag and verification rejects it;
- rewriting `c` or a later period recomputes the affected suffix and verifies
  unless independent retained evidence covers the changed record;
- in static mode, disclosure at `c` permits a valid rewrite even before `c`.

`forgeSuffixFromCompromise` replaces the entire suffix beginning at `c`. This
is used to show that a compromised logger can truncate later honest activity
and emit a valid new suffix, including an early `CLOSE`.

This model authenticates log contents; it does not encrypt them, identify a
human principal, establish that logged events really happened, resist denial
of service, or protect a verifier whose initial state is compromised.

## 4. Four separate verification results

The verifier intentionally does not collapse different properties into one
green badge.

### Forward integrity

`VALID` means the supplied records are well formed, have contiguous periods,
match the trusted scheme and log identifier, have an intact previous-tag
chain, and have valid HMACs under states derived from trusted `S_0`. `INVALID`
names the first malformed record, identifier mismatch, gap, broken link, bad
tag, or record after `CLOSE`.

A valid HMAC after compromise does not establish that the logger was honest:
the attacker can authenticate period `c` and its suffix.

### Retained-checkpoint consistency

A checkpoint is `(version, scheme, logId, recordCount, lastTag)` copied to a
store outside the compromised logger. A candidate log is `CONSISTENT` with it
only if the record at `recordCount - 1` still has the retained tag. Because
each tag authenticates the prior link, that comparison anchors the exact
prefix represented by the checkpoint. A candidate that is shorter than the
checkpoint or differs at or before its anchored record is `INCONSISTENT`.
Changes strictly after that record remain `CONSISTENT` with this checkpoint.

This small retained anchor is not a signed tree head, a Merkle consistency
proof, a gossip system, or evidence that two verifiers saw the same view. It
also says nothing about records after the checkpoint. RFC 9162 is cited as a
production-oriented comparison for explicit Merkle append-only proofs, not as
a protocol implemented here.

### Completeness

A logger-authenticated `CLOSE` by itself does **not** prove completeness. A
pre-close compromise can forge one. Without an independently trusted expected
close period, even a valid log ending in `CLOSE` is reported `UNKNOWN`.

If an external workflow says the log must contain a `CLOSE` at period `e`, an
intact close at exactly `e` is `COMPLETE`; no close is `TRUNCATED`, and a close
on the wrong side is `EARLY_CLOSE` or `LATE_CLOSE`. This detects deletion of an
honest expected close. It does not stop an attacker holding `S_c` from
fabricating events through period `e` and forging a close there.

### Freshness

Neither a checkpoint nor an expected-close rule proves that the presented log
is the latest view. Freshness is evaluated only when the verifier receives a
trusted external lower bound such as a heartbeat or receipt saying that at
least `n > 0` records must now exist. Fewer records are `STALE`; an intact log
meeting that bound is `CURRENT_TO_TRUSTED_BOUND`.

Without that independent input, replaying an older, internally valid log is
`UNKNOWN` for freshness. A `CLOSE` does not change that result.

## 5. Test evidence

The focused unit suite covers:

- RFC 4231 HMAC-SHA-256 test case 1, checked both with `@noble/hashes` and an
  independent WebCrypto HMAC computation;
- fixed state-evolution and five-record tag vectors;
- scheme-domain and length-boundary separation;
- exact `c - 1`, `c`, and later compromise cases;
- earlier rewrites under the static-key control;
- retained checkpoints before and through a forged suffix;
- wrong compromise material;
- message, tag and previous-link mutations;
- malformed encodings, gaps, deletion, reordering and records after close;
- honest-close truncation with and without an external expected period;
- forged early close after compromise; and
- stale closed-log replay with and without a trusted freshness bound.

The fixed fixture starts with `S_0 = 00 01 ... 1f`, uses log identifier
`college-kms/audit/2026-10-24`, four documented event strings, and an honest
close. Its expected `S_3` and all record tags are constants in the tests rather
than values copied back from the implementation at assertion time.

## 6. Scope and retained limitations

- This is a bounded single-process lesson, not a durable logging service, HSM,
  remote-attestation system, consensus protocol, or proof of secure deletion.
- HMAC tags are symmetric evidence. A verifier holding authentication state
  can also produce tags; this is not public verifiability or non-repudiation.
- The separate verifier can derive period states from `S_0`; a deployed design
  must isolate that verifier secret from the logging machine.
- One record is used per period for a crisp compromise boundary. Production
  batching, crashes, concurrency, recovery, key backup and rollback need their
  own protocol.
- A retained checkpoint anchors one prefix but does not establish freshness,
  availability, global consistency or split-view resistance.
- An expected close can expose truncation only because the expectation came
  from outside the compromised log. It is not a general liveness oracle.

## Primary sources

- Bruce Schneier and John Kelsey,
  [Cryptographic Support for Secure Logs on Untrusted Machines](https://www.schneier.com/wp-content/uploads/2016/02/paper-secure-logs.pdf),
  for the evolve-and-erase logging shape and the distinction between records
  created before and after machine compromise. The lab omits substantial parts
  of their protocol, including confidentiality and remote verifier exchanges.
- Mihir Bellare and Bennet Yee,
  [Forward-Security in Private-Key Cryptography](https://eprint.iacr.org/2001/035),
  for the formal treatment of forward-secure symmetric primitives and their
  audit-log application. The lab's two-branch HMAC schedule is an adaptation,
  not their exact proven construction.
- [RFC 2104, HMAC: Keyed-Hashing for Message Authentication](https://www.rfc-editor.org/rfc/rfc2104.html),
  for the MAC construction.
- [RFC 4231, HMAC-SHA Test Vectors](https://www.rfc-editor.org/rfc/rfc4231.html),
  section 4.2, for the independently checked HMAC-SHA-256 known-answer test.
- [RFC 9162, Certificate Transparency Version 2.0](https://www.rfc-editor.org/rfc/rfc9162.html),
  section 2.1.4, for the comparison with explicit Merkle consistency proofs.
