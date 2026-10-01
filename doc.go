// SPDX-License-Identifier: BSD-3-Clause

// Package krl reads, writes and checks OpenSSH key revocation lists (KRLs),
// the binary format of OpenSSH's PROTOCOL.krl that sshd loads through
// RevokedKeys and that ssh-keygen -k writes and ssh-keygen -Q queries.
// golang.org/x/crypto/ssh has no support for them.
//
// A KRL revokes certificates by serial number (as lists, ranges or bitmaps)
// or by key ID, each under one CA key or under any CA, and revokes plain keys
// by their blob or by the SHA-1 or SHA-256 hash of their blob.
//
//	k, err := krl.Parse(data)
//	if err != nil { ... }
//	if k.IsRevoked(cert) { refuse the login }
//
//	b := krl.NewBuilder(version, "revoked by the bridge")
//	b.RevokeSerial(caKey, 42)
//	data, err := b.Marshal(time.Now())
//
// # Judged by ssh-keygen
//
// Parse, IsRevoked and Builder follow krl.c, OpenSSH's own implementation,
// and the tests hold them to it: KRLs written by ssh-keygen -k are parsed
// here and every certificate and key gets the same answer from IsRevoked as
// from ssh-keygen -Q; KRLs written by Builder are accepted by ssh-keygen -Q,
// which gives the same answers again and dumps the same revocations as for
// the KRL it wrote itself.
//
// Builder chooses between list, range and bitmap encodings with krl.c's
// cost model, so its output is usually byte for byte what ssh-keygen writes
// for the same revocations. It departs from it on purpose in one place:
// ssh-keygen lets a bitmap grow past the largest integer its own reader
// accepts (2048 bytes), and then cannot read the KRL it wrote ("bignum is
// too large"), which is what happens to many sparse serials close together.
// Builder starts a new section instead.
//
// # Expiry
//
// Builder.SetExpires writes, in a non-critical extension section named
// ExtensionExpires, the time after which the list is no longer current;
// Parse reads it into KRL.Expires. sshd ignores it. It is what lets a
// reader tell a stale copy from a current one, once the list itself is
// authenticated.
//
// # Merging
//
// Builder.Merge adds every revocation of a parsed KRL to the list being
// built, for a reader that takes one file: sshd before OpenSSH 10.3.
//
// # Integrity: no signatures
//
// The format once had a signature section. OpenSSH never exposed a way to
// write it, has stopped verifying it, and recommends a detached SSHSIG
// signature (ssh-keygen -Y sign) instead. Parse still reads a KRL that has
// one, for old files, skips it as krl.c does and sets KRL.Signed; the
// signature is NOT verified, so Signed says nothing about authenticity.
// Builder never writes one. A KRL's integrity must come from how it is
// transported, such as HTTPS from a server the reader authenticates, or
// from a detached SSHSIG signature checked by the caller; this package does
// neither.
//
// # Differences from OpenSSH
//
// Keys are parsed with golang.org/x/crypto/ssh, not OpenSSH's sshkey, so a
// CA key in a certificate section is refused or accepted by that parser.
// The two agree on every key type OpenSSH supports, with small exceptions:
// x/crypto still parses ssh-dss keys, which OpenSSH 10 no longer does, and
// does not refuse RSA keys shorter than 1024 bits.
//
// Like OpenSSH, Parse allocates in proportion to what the KRL revokes, so
// a KRL should come from a source trusted not to send an enormous one.
package krl
