# krl

[![Go Reference](https://pkg.go.dev/badge/github.com/go-authn/krl.svg)](https://pkg.go.dev/github.com/go-authn/krl)
[![License](https://img.shields.io/badge/license-BSD--3--Clause-0A6E96?style=flat-square)](LICENSE)
[![CI](https://github.com/go-authn/krl/actions/workflows/ci.yml/badge.svg)](https://github.com/go-authn/krl/actions/workflows/ci.yml)

**OpenSSH key revocation lists (KRLs) in Go**: parse, build and check the
binary format of OpenSSH's
[PROTOCOL.krl](https://github.com/openssh/openssh-portable/blob/master/PROTOCOL.krl),
the one sshd loads through `RevokedKeys` and `ssh-keygen -k` writes.
[`golang.org/x/crypto/ssh`](https://pkg.go.dev/golang.org/x/crypto/ssh) has no
support for them. Pure Go, `CGO_ENABLED=0`.

```go
// A server refusing revoked certificates.
k, err := krl.Parse(data)
if err != nil { ... }
if k.IsRevoked(cert) { /* refuse */ }

// An issuer publishing what it revoked.
b := krl.NewBuilder(version, "revoked certificates")
b.RevokeSerial(caKey, 42)
b.RevokeSerialRange(caKey, 100, 199)
b.RevokeKeyID(nil, "alice") // nil: under any CA
b.RevokeKey(compromisedKey)
data, err := b.Marshal(time.Now())
```

`IsRevoked` follows `ssh_krl_check_key` in OpenSSH's `krl.c`: a certificate is
revoked when its serial or key ID is revoked under the CA that signed it or
under any CA, when its CA key is revoked, or when its own key is revoked by
blob or by SHA-1 / SHA-256 fingerprint.

## Judged by ssh-keygen

The tests do not let the package agree with itself. On the linux and macOS CI
lanes, `ssh-keygen` is the oracle (a missing one fails those lanes):

| test | what ssh-keygen judges |
| --- | --- |
| `TestOracleSshKeygenKRL` | a KRL written by `ssh-keygen -k` with serials (list, range, bitmap, up to 2^64-1), key IDs, three CAs plus "any CA" (`-s none`), explicit keys and a revoked CA key: `IsRevoked` answers like `ssh-keygen -Q` for 250 certificates (made by `ssh-keygen -s`) and keys. `Builder` given the same revocations writes the **same bytes**. |
| `TestOracleFingerprints` | `sha1:`, `sha256:` and `hash:` revocations, for keys and their certificates |
| `TestOracleRandomSerials` | 40 random serial sets written by both: byte-identical, same `ssh-keygen -Q -l` listing, and the same answers for ~9000 certificates on both sides of every edge |
| `TestOracleMutations` | every truncation and ~1400 single-byte corruptions of a KRL: `Parse` refuses exactly what `ssh-keygen` refuses, and answers like it for the rest |
| `TestOracleSigned` | a KRL with a signature section: read, signature skipped |
| `TestOracleBitmapOverflow` | see below |
| `TestOracleExpiresIsLoadedBySshKeygen` | a KRL carrying the expiry extension (below) loads and revokes as before; the control, the same section marked critical, is refused |
| `TestOracleMergeIsTheUnion` | three lists written by `ssh-keygen -k` (every serial encoding, key IDs, "any CA", explicit keys, SHA1 and SHA256 fingerprints), merged by `Builder.Merge`: the merged list revokes exactly what one of them revokes, for ~180 certificates and keys |
| `TestOracleRevokingTheCARevokesEveryCertificate` | a KRL naming the CA's own key revokes every certificate it signed, and nothing else |

Windows runs the pure-Go tests only. The 100% coverage gate is measured on
the Linux lane, where ssh-keygen is there: without it the pure-Go tests leave
part of `Builder.Merge` and `Builder.MergeCA` to the oracle tests.
`FuzzParse` (seeded with KRLs written by ssh-keygen, in `testdata/`) and
`FuzzBuilder` run on CI too.

### One deliberate difference

For many sparse serials close together (1, 3, 5, … 40001), `ssh-keygen -k`
writes a bitmap wider than its own reader accepts and then refuses its own
file: `Invalid KRL file: bignum is too large` (OpenSSH 10.3p1). `Parse` refuses
that file too, as sshd would. `Builder` starts a new section before a bitmap
gets that wide, so what it writes is always readable.

## An expiry: `expires@go-authn.github.io`

A KRL has a generation date and a version, but nothing says when it stops
being current, so a stale copy is indistinguishable from a fresh one: what
TUF calls a freeze attack, and what a CRL's `nextUpdate` (RFC 5280, 5.1.2.5)
prevents. `Builder.SetExpires` writes that time in an extension section,
named `name@domain` as PROTOCOL.krl section 5 recommends and **not critical**,
so `sshd` and `ssh-keygen` load the list and ignore it (judged above). `Parse`
reads it into `KRL.Expires`, and refuses a malformed or repeated one: read as
absent, it would turn a list meant to lapse into one that never does.

The expiry is only as good as the list's authenticity: sign the list.

## Merging lists: one file for sshd

`sshd` read a single `RevokedKeys` file until OpenSSH 10.3 (Debian 13 ships
10.0, Ubuntu 24.04 9.6), so a server trusting several CAs needs their lists in
one. `Builder.Merge` adds every revocation of a parsed list (serials, key IDs,
explicit keys, SHA1 and SHA256 fingerprints, under the same CAs) to the list
being built; the header is the Builder's own. Merging the same lists in the
same order writes the same bytes. A bitmap is read back as ranges, so a merge
is bounded (4M ranges) against an alternating one.

`Builder.MergeCA(k, ca, others...)` merges `k` for `ca`, the way a
distributor merging several CAs' lists into one needs it:
- **Kept:** `ca`'s section; any-CA sections, re-scoped to `ca`; and explicit
  keys and fingerprints. A user key `ca` revokes stays revoked, and `ca`
  revoking its own key revokes every certificate it signed.
- **Left out, and counted:** sections for another CA, and keys or fingerprints
  that designate one of `others`, the other CAs the merged list serves.

So each list keeps its full effect on its own CA, and none can lock another
CA's users out. v0.3.0 also dropped explicit keys, fingerprints and any-CA
sections: a CA revoking a compromised user key, or itself, revoked nothing
once merged. A security audit found it; ssh-keygen now judges both cases
(`TestOracleMergeCA`, `TestOracleMergeCAKeepsACAsOwnKeyRevocations`).

## No signatures

OpenSSH never exposed a way to write the KRL signature section and no longer
verifies it. `Parse` reads a KRL that has one, skips it as `krl.c` does and
sets `Signed`, which says nothing about authenticity. `Builder` never writes
one. A KRL's integrity comes from its transport (HTTPS from an authenticated
server) or from a detached SSHSIG signature (`ssh-keygen -Y sign`), which this
package does not handle.

## License

BSD-3-Clause.
