# Decision: image signatures made without a kept key (T-0463)

Status: accepted, 2026-11-16. Reviewed before any code (see "Review" at the end).

## What is asked

`cosign sign IMAGE` with no key, which is cosign's default, signs with a key it throws away.
An authority (Fulcio) gives that key a certificate of ten minutes that names who asked
for it: an issuer (the sign-in service, such as `https://token.actions.githubusercontent.com`)
and a subject (an email address or a URI, such as a workflow's). A transparency log (Rekor)
records the signature and promises, under its own key, the time it saw it. cosign 3 keeps
all of this as one JSON file, a bundle (`application/vnd.dev.sigstore.bundle.v0.3+json`),
among the image's referrers. Older cosigns, and cosign 3 with `--new-bundle-format=false`,
keep it under the tag `sha256-HEX.sig` with the certificate and the log's promise in the
layer's annotations.

kith today takes keys only, and reads only the tag (`crates/kith-runtime/src/signed.rs`).

## The rule

`signedBy` (a container's, and a Cluster's `spec.images[].signedBy`) holds keys as it does
today, and now also identities:

```yaml
signedBy:
- { issuer: https://token.actions.githubusercontent.com,
    subject: https://github.com/acme/tool/.github/workflows/release.yml@refs/heads/main,
    authority: [<PEM certificate>, ...],   # the authority's root, and its intermediates
    log: <PEM public key>,                 # the log's key
    tsa: [<PEM certificate>, ...] }        # optional: the timestamp authority's root(s), 1 to 4
```

- `issuer` and `subject` are matched whole, byte for byte. There are no patterns, which
  are a common way to accept more than was meant.
- `authority` lists the certificates a signer's certificate must lead to: 1 to 4 of them.
  Those that sign themselves are the roots a chain ends at. The rest are intermediates,
  each held to its own validity at the log's time as the leaf is, so an intermediate that
  has been retired no longer passes. A root's own dates are not read.
- `log` is an ECDSA P-256 key, the same as Rekor's.
- `tsa` is optional (a rule stored without it reads as before, and is the same identity with
  the same id). It gives the root certificates, 1 to 4, of the RFC 3161 timestamp authority
  that timed the signature. Without it a bundle of Rekor v2 (a timestamp, no promise) is
  refused, naming `tsa`; a bundle with a log's promise is taken as it was. With it,
  `keyless::verify` runs `timestamp` before `check`: every RFC 3161 timestamp in the bundle
  (at most 4) must verify against one of the roots, or the bundle is refused. A Rekor v2
  bundle is then timed by the earliest of their genTimes. A v1 bundle needs its timestamp too
  (it must be there and be the authority's; the time the certificate is held to is still the
  log's promise). A signature kept under the tag has no timestamp, so under a rule with `tsa`
  it is refused.
- Nothing is built in and nothing is fetched (no TUF). A wrong root or key refuses every
  signature. It never widens what runs.
- A template's identities narrow a rule's in the same way its keys do. An identity is the
  same identity when all four of its fields are equal.
- **An older kithd** reads `signedBy` as `Vec<String>`, so it refuses to apply a rule or
  template that holds an object. A rule written by a newer control node and read by an
  older worker (`controller.rs` takes the strings of `signedBy`) keeps only its keys. A
  rule of identities alone then has no key, and nothing it covers is run. Neither case runs
  an image unsigned.

## Where signatures are looked for

For each digest (the image's manifest, and the list it was picked from), the two places
are searched in turn, and the first signature that passes wins:

1. **Referrers.** `oci_client::Client::pull_referrers(digest, artifactType=bundle v0.3)`
   is read. That client falls back to the tag `sha256-HEX` when the registry has no
   referrers API. At most 32 manifests are read. For each one:
   - its `subject.digest` must be the digest being checked;
   - its first layer must be the bundle type;
   - that layer is read up to 64 KiB, with its digest checked as it comes.
2. **The tag** `sha256-HEX.sig`, as today. A layer with `dev.sigstore.cosign/certificate`
   is checked as a keyless signature. A layer without it is checked against keys, as
   before.

## Exactly what is checked

These are the same for both places. The only difference is where the certificate,
signature, payload and log entry are read from. Each refusal names its reason.

1. **The certificate.**
   - In the bundle, it is `verificationMaterial.certificate.rawBytes`, DER in base64. In
     the tag, it is `dev.sigstore.cosign/certificate`, PEM.
   - Only one certificate is taken. A bundle's `x509CertificateChain` is read only for its
     first certificate, and the chain annotation is ignored: only the rule's `authority`
     certificates are trusted.
2. **The log's promise (SET).**
   - The bundle's first `tlogEntries[0]` is read. Its kind is read from the body the log
     signed, not from `kindVersion`, and must be `dsse 0.0.1` or `hashedrekord 0.0.1`.
     Its `logId.keyId` must equal SHA-256 of the DER of the rule's `log` key.
   - The tag has `dev.sigstore.cosign/bundle` = `{SignedEntryTimestamp,
     Payload{body, integratedTime, logIndex, logID}}`.
   - The bytes checked are the JCS form (keys sorted, no spaces) of
     `{"body":"<canonicalizedBody, base64>","integratedTime":N,"logID":"<keyId, hex>","logIndex":N}`.
     The signature over them, `signedEntryTimestamp` (ASN.1 ECDSA, P-256, SHA-256), must
     verify with the rule's `log` key.
   - Two cases are refused, each naming what it is:
     - an entry with no promise, under a rule with no `tsa` (Rekor v2 gives an inclusion
       proof and a time from a separate timestamp service: the rule must name that
       service's root as `tsa`);
     - any other kind.
3. **The time** is the promise's `integratedTime` when the entry has a promise, never the
   node's clock. For an entry with no promise (Rekor v2), under a rule with `tsa`, it is the
   earliest genTime of its RFC 3161 timestamps, once every one verifies against the rule's
   `tsa`. Under a rule
   with `tsa`, a v1 bundle needs the timestamp to be present and to verify, but its time
   is not used: the check still takes the promise's time (presence-only for v1). The ten-minute
   certificate is good only then.
4. **The chain.**
   - `webpki::EndEntityCert::verify_for_usage` is called with:
     - the `authority` certificates as anchors;
     - ECDSA P-256/SHA-256 and P-384/SHA-384 (Fulcio's leaf and intermediate signatures)
       as the algorithms;
     - the time from step 3;
     - `KeyUsage::required(id-kp-codeSigning 1.3.6.1.5.5.7.3.3)`;
     - no revocation list.
   - webpki refuses a certificate outside its validity at that time, one not for code
     signing, one not signed by an anchor, and an unknown extension marked critical.
     Unknown extensions that are not critical (Fulcio's 57264.1.* and the SCT) are
     ignored.
5. **The identity.**
   - Neither field is read by webpki, so a small DER reader in `keyless.rs` reads them from
     the leaf's extensions:
     - The subject is `subjectAltName` (2.5.29.17): its one rfc822Name `[1]` or URI `[6]`,
       as UTF-8.
     - The issuer is 1.3.6.1.4.1.57264.1.8, a DER UTF8String. If that is missing, the
       deprecated 1.3.6.1.4.1.57264.1.1, whose bytes are the string itself, is used.
   - Both must equal the rule's. A certificate with more than one name, or with neither
     extension, is refused.
   - The reader checks every length against what is left, uses no index without a check,
     and is fed cut and altered certificates in a test.
6. **The signature.**
   - **Bundle.** `dsseEnvelope` has a payloadType of `application/vnd.in-toto+json`,
     `payload` (base64) and one `signatures[0].sig`. The bytes checked are the DSSE PAE:
     `"DSSEv1 " len(type) " " type " " len(payload) " " payload`, with the lengths in
     decimal ASCII.
   - **Tag.** The bytes checked are the layer's bytes, cosign's simple-signing JSON. The
     signature is `dev.cosignproject.cosign/signature`.
   - Either signature is checked with the leaf's key: `EndEntityCert::verify_signature`
     with ECDSA P-256/SHA-256 ASN.1, or P-384/SHA-384.
7. **The digest.**
   - **Bundle.** The payload is an in-toto Statement whose `_type` is
     `https://in-toto.io/Statement/v1` and whose `predicateType` is
     `https://sigstore.dev/cosign/sign/v1`. One of its `subject[].digest.sha256` must be
     the digest's hex. (The referrer's `subject` was checked too, under "Where signatures
     are looked for".)
   - **Tag.** The payload is `critical.image.docker-manifest-digest`, the same check as
     today.
8. **That the log's entry is this signature's.** The promise covers `canonicalizedBody`,
   so that body is read and compared:
   - `dsse 0.0.1`: `spec.signatures[0].signature` must equal the envelope's signature,
     `spec.signatures[0].verifier` (base64 PEM) must equal the leaf's DER, and
     `spec.payloadHash.value` must be SHA-256 of the payload.
   - `hashedrekord 0.0.1`: `spec.signature.content` must equal the signature,
     `spec.signature.publicKey.content` must equal the leaf's DER, and
     `spec.data.hash` (`sha256`) must be SHA-256 of what was signed: the payload for the
     tag, and the PAE for a bundle.
   - A mismatch is refused as "the log's entry is of another signature".

A signature that passes is remembered with the image as `<subject> (<issuer>) #<hash>`,
the hash covering all four fields, the way a key is remembered by its id.

## What is not checked, and why

- **The log's inclusion proof and checkpoint.** These are signed by the same log key as
  the promise. With no witness and no monitor to compare against, a proof against that
  key's own checkpoint proves nothing more offline than its promise. If a witness is ever
  named, this is where it goes.
- **The authority's own log proof (the SCT in the certificate).** It would need the
  certificate-transparency log's key, a second key to give. The promise already shows the
  log saw the certificate within its validity.
- **Revocation.** There is none for a ten-minute certificate. The time from the log is
  what bounds it.
- **Rekor v2 (no promise; a timestamp authority's RFC 3161 token instead).** Without a
  timestamp, or under a rule with no `tsa`, it is refused, naming it. `keyless::timestamp`
  reads each token in the bundle (`timestampVerificationData`, at most 4) and takes the
  earliest genTime as the signing time when, for every token, the TSA's signature over the
  signed attributes, their messageDigest, the SHA-256 imprint of the signature, and a chain
  to one of the TSA roots given (EKU timeStamping, valid at genTime) all hold; the signer's
  certificate must then be valid at that time. The log's inclusion proof is not read. The rule field that carries the TSA root is
  the identity's `tsa`: `keyless::verify` is what calls `timestamp`, per identity, and
  forgets what it found before the next identity is asked. The token is read as DER only, of
  at most 16 KiB, nested at most 10 deep (not counting what a certificate or an attribute's
  values hold; 10 because the signer's issuer Name, in a real TSA's SignerInfo, reaches
  depth 9), with at most 4 certificates; past a limit, in BER, or with a length written
  longer than DER needs, it is refused naming which. cosign 3 still logs to Rekor v1 by default on the public instance (sigstore
  blog, "Rekor v2 GA", Oct 2025).
- **A log that lies along with the authority.** This is not caught: who runs them is the
  owner's choice of trust, and README and SECURITY.md say so.

## Rivals

- **The sigstore crate** (sigstore-rs) has a verifier, but it pulls in
  openssl-free-but-large crates (x509-cert, p256, tough's TUF) and a cosign client with
  its own HTTP stack. Against kithd's 13.00 MB budget, the few hundred lines here are
  cheaper. It also fetches its trust roots through TUF by default, which this design
  rules out.
- **A full x509 parser** (`x509-parser` or `x509-cert`) to read the two fields. It is not
  in the tree, and webpki already checks the chain. A reader for two extensions is about
  60 lines.
- **Trusting the public instance by a root built in.** Ruled out in the brief: it can't be
  rotated by the owner, and every kith would trust a service nobody chose.
- **Identities as a new field beside `signedBy`.** An older kithd ignores an unknown field
  and would run the image on keys alone, or unsigned. Keeping them inside `signedBy` makes
  an older kithd refuse instead.

## Review (adversary lens, before code)

Each question below was asked of the design above.

- *A signature from someone else's certificate under the same authority?* The identity is
  checked from the certificate that verified the signature (step 5 on the step-4 leaf, and
  step 6 with that leaf's key). Both fields are matched whole.
- *A valid old certificate replayed?* The time comes from a promise signed by the log's
  key over a body that holds this signature and this certificate (step 8). Taking a real
  promise for another signature fails step 8.
- *An expired certificate with a forged time?* The time is inside bytes signed by the log
  key, and a time cannot be chosen without that key.
- *A bundle for another image?* Steps 7 and the referrer's subject both bind the digest.
  The tag's payload binds it as today.
- *An intermediate that is not a CA, or that has path constraints?* webpki enforces
  basicConstraints and path length.
- *A certificate whose SAN holds a DNS name and an email?* Exactly one name of the two
  kinds is allowed, so anything else is refused.
- *Resource use?* The bundle is capped at 64 KiB, there are at most 32 referrers and 32
  layers, as now, and every DER length is checked before it is used.
- *Two kinds of entry with the same promise?* The kind is inside the signed body
  (`kind`/`apiVersion` of `canonicalizedBody`), so it is read from the body, not from the
  bundle's `kindVersion` alone.
- *Found:* JCS needs no general canonicalizer. The four keys are known, and the values are
  a base64 string, two integers and a hex string, so the bytes are built by `format!` and
  are exact for these. That is enough only while the body is a base64 string, which it is
  in both formats. Kept as written.

### The independent review, and what came of it

A second reviewer read this record and the first code. They found no way to run an image
the rule refuses. They did find the following, and each is now in the code:

- **Referrers.** Only descriptors of the bundle's kind and of a bundle's size are taken,
  and the cap of 32 applies after that filter. A registry that answers with something
  else, or that has no referrers API, counts as having none, and the tag is looked at
  next. The whole search for signatures stops at 60 s.
- **A rule of identities alone** goes to the node in the same list as keys, so it is never
  an empty list that runs unsigned. A test pulls an unsigned image under such a rule and
  sees it refused.
- **Envelopes.** A `payloadType` other than `application/vnd.in-toto+json` is refused. A
  statement of any kind other than `https://sigstore.dev/cosign/sign/v1`, such as an
  attestation, is refused as "no signature".
- **Repeated extensions.** A certificate that holds the same extension twice is not read.
- **Registry text in refusals.** Any text a registry gave that a refusal repeats is cut
  to 80 characters, with control characters removed.
- **Left for its own task:** manifests and the referrers index are read whole by
  oci-client, and an outside registry has no timeout of its own. Both were true for
  every pull before this change.

Checked against a real bundle: `keyless_real_bundle_from_cosign_verifies_against_its_own_roots`
reads an attestation that cosign wrote with the public instance. It checks it against
that instance's trusted root. The log's promise (the JCS bytes), the `dsse` entry's
binding, the certificate's chain to Fulcio at the log's time, and the issuer and subject
all hold. Only its statement, which is an attestation, is refused.
