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

Windows runs the pure-Go tests only, which alone cover 100% of the code.
`FuzzParse` (seeded with KRLs written by ssh-keygen, in `testdata/`) and
`FuzzBuilder` run on CI too.

### One deliberate difference

For many sparse serials close together (1, 3, 5, … 40001), `ssh-keygen -k`
writes a bitmap wider than its own reader accepts and then refuses its own
file: `Invalid KRL file: bignum is too large` (OpenSSH 10.3p1). `Parse` refuses
that file too, as sshd would. `Builder` starts a new section before a bitmap
gets that wide, so what it writes is always readable.

## No signatures

OpenSSH never exposed a way to write the KRL signature section and no longer
verifies it. `Parse` reads a KRL that has one, skips it as `krl.c` does and
sets `Signed`, which says nothing about authenticity. `Builder` never writes
one. A KRL's integrity comes from its transport (HTTPS from an authenticated
server) or from a detached SSHSIG signature (`ssh-keygen -Y sign`), which this
package does not handle.

## License

BSD-3-Clause.
