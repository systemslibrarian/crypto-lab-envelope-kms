# Extension brief: allowed calls, forbidden key disclosure

This first E-K-01 extension adds a small stateful API experiment to Envelope KMS.
It complements the existing caller-grant exercise. It does not change the normal
KMS API, whose `GenerateDataKey` and `Decrypt` deliberately return raw DEKs.

## 1. Scope

**The lesson:** hiding a key's value from direct reads does not preserve its
confidentiality if separately permitted API operations can be composed to reveal it.

The exhibit executes one concrete trace using fresh, internally generated AES-256
keys: refuse a direct read, wrap a sensitive target, add a byte-returning decrypt
permission to the wrapping key, and decrypt the wrapped blob with the same mechanism.
A real AES-GCM challenge tests whether the recovered bytes are useful outside the
handle API. The fixed-role policy refuses the permission transition; legitimate
unwrap-to-handle use still works.

The default target is **sensitive and wrappable** (`sensitive=true`,
`extractable=true`). A second setting makes it nonextractable and refuses wrapping
under either policy. These are distinct protections. A wrappable target must never
be described as nonextractable.

**Real cryptography:** the existing RFC 3394 implementation wraps and decrypts the
32-byte target; the existing WebCrypto AES-256-GCM implementation seals and opens
the challenge. A wrapped 32-byte target is 40 bytes. The model does not decrypt an
RFC 3394 blob with AES-GCM.

**Non-goals:** no hardware token, authenticated caller, deployed HSM test, full
PKCS #11 emulator, exhaustive state search, security proof, general key import,
copy, derive, restore, multi-session sharing, replay defense, or side-channel claim.
This is not production crypto; it is a browser teaching model with real primitives.

## 2. Security and correctness invariants

1. Fixed roles are the default. Mutable usage permissions are an explicit,
   intentionally unsafe comparison setting.
2. Every key is sensitive. Direct reads of its value fail under both policies.
3. The wrapping key is generated internally, is nonextractable, and initially has
   only wrapping/unwrapping permissions. Data and wrapping roles use distinct bytes.
4. Wrapping requires an extractable target. The nonextractable setting rejects
   wrapping before encryption, including in mutable mode.
5. Fixed roles cannot acquire byte-returning decrypt permission. A refusal leaves
   the previous state unchanged. Unknown handles and wrong mechanisms fail closed.
6. Successful unwrap returns a fresh, sensitive, nonextractable **data handle**.
   It never returns target bytes or accepts a caller-supplied role template.
7. Only the explicitly permitted mutable decrypt operation returns recovered key
   bytes. Its result is checked against actual challenge decryption, not an asserted
   success flag. RFC 3394 integrity and AES-GCM authentication remain active.
8. Metadata is a defensive frozen snapshot, with no live references to policy or
   key material. Caller-owned buffers are copied where retained or used across awaits.
9. No key material is persisted or sent over the network. This model cannot protect
   against same-origin script execution, developer tools, or runtime compromise.

The optional deterministic constructor factory exists only for unit fixtures. The
browser uses internal randomness. Supplying a known wrapping key to a larger API
would require a separate provenance/trust policy: immutable roles alone do not stop
someone who already knows a wrapping key from decrypting outside the API.

## 3. Architecture

- `src/kms/key-handles.ts`: isolated `HandleToken`, key records, named policy
  errors, the one mutable transition, RFC 3394 operations, and GCM challenge use.
- `src/kms/key-handles.test.ts`: one RFC 3394 section 4.6 known-answer fixture,
  independent native WebCrypto AES-KW comparison, actual external challenge
  decryption, and permission/input/ownership/atomicity tests.
- The UI owns the visible trace and calls this API. It must not fabricate a result
  from the selected policy, expose raw keys through metadata, or treat an unexpected
  exception as evidence that a defense worked.

All handle operations are synchronous except `sealChallenge` and `openChallenge`,
which return Promises from the existing WebCrypto path. Every token has its own
random handle names and key store. No new cryptographic dependency is required.

## 4. UI

Introduce the exhibit as **What may this key do?**, alongside the existing **Who
may use this key?** lesson in the advanced disclosure. Explain handle, sensitive,
and wrappable in plain language before showing attribute names.

Show the two key roles and the operation sequence. The central interaction is to
run the same requests under mutable usages and fixed roles, then change target
extractability. Display the actual refusal point or returned-byte outcome. A
separate legitimate unwrap demonstrates that fixed roles preserve intended use.

Keep the completed trace's limitation visible: valid cryptographic checks do not
prevent key disclosure when this API permits conflicting operations. Only the
executed trace is tested; there is no claim that all API sequences were explored.
Changing an input retires the prior verdict; selecting its current value is a no-op.
Reset starts a new session. The layout stacks below 640px and all actions are
keyboard operable, labelled, and announced through a live result region.

## 5. Visual semantics

The confidentiality result determines the outcome styling. A successful extraction
is an **exposure alarm**, even though the wrap and decrypt calls succeeded.
Distinguish an expected policy refusal, a cryptographic integrity failure, a
successful intended operation, and an experiment that failed to run.

Use text and a non-color cue with existing theme tokens. Show the mechanism through
the changing permissions and resulting call sequence, not decorative animation or
an unexplained wall of hex. Any animation follows the learner's action and honors
reduced motion. Evidence is computed from real returned bytes.

## 6. Edge cases and acceptance

Unknown or foreign-token handles fail without looking up another token's keys.
AES-GCM handles cannot perform AES-KW operations, and wrapping handles cannot open
data challenges. A malformed wrap is rejected; corrupt or wrongly keyed wraps fail
RFC 3394 integrity without allocating an output handle. The model accepts only
40-byte wraps of 256-bit targets. GCM challenges require a 12-byte IV, 16-byte tag,
and byte-array fields; wrong key, changed tag, ciphertext, IV, or AAD fails
authentication. Empty authenticated plaintext remains valid.

Before publication, run the existing complete gates, including `npm run ci`,
coverage thresholds, the production-build browser/claims/accessibility suite, and
the existing Pages workflow's high-severity dependency audit. Add new result states
to the accessibility exercise rather than scanning hidden or fabricated DOM states.

Decisive browser evidence independently opens the printed challenge using recovered
bytes. The negative fixture verifies that primitive checks succeed while the target
becomes known, with its limitation visible. Focused source mutations must show that
allowing the fixed-role transition, allowing a nonextractable wrap, fabricating
recovery, or removing the limitation fails the owning test after a successful build.
Preserve the master template's commit-before-mutation and immediate restore rules.

## 7. Extension seams

- The fixed unwrap template is the future seam for import/restore and authenticated
  role preservation. A general import feature needs trusted-wrapper provenance and
  alias/copy policy; do not add a raw-key import merely to create another handle.
- The explicit `HandlePolicy` and `allowDecrypt` transition could later supply a
  bounded state explorer. Such an explorer must publish its operation alphabet,
  initial state, search limits, and witness, and cannot claim an unbounded proof.
- A later trusted-wrap lesson can add a distinct policy without replacing the
  current narrow claim with a blanket assertion that PKCS #11 or HSMs are broken.

## Sources and precise scope

- [RFC 3394, sections 2.2 and 4.6](https://www.rfc-editor.org/rfc/rfc3394.html):
  the actual wrapping/integrity algorithm and 256/256 known-answer fixture.
- [PKCS #11 v3.0 Current Mechanisms, Table 91 and section 2.16.3](https://docs.oasis-open.org/pkcs11/pkcs11-curr/v3.0/os/pkcs11-curr-v3.0-os.html):
  AES Key Wrap supports single-part encrypt/decrypt as well as wrap/unwrap.
- [PKCS #11 v3.0 Base, section 4.10 and C_WrapKey](https://docs.oasis-open.org/pkcs11/pkcs11-base/v3.0/os/pkcs11-base-v3.0-os.html):
  sensitive and extractable attributes have different meanings; the wrapper needs
  wrapping permission and the target must be extractable. Attribute modifiability
  is also subject to token policy. This exhibit chooses one permissive policy and
  one restrictive policy; it does not assess any particular vendor or device.
- Encyclopedia entry **Formal Analysis of Cryptographic APIs**, original PDF
  positions 2438–2440; split Part 2 positions 590–592. This motivates the
  stateful-composition lesson, not a claim that every described attack is implemented.
