// SPDX-License-Identifier: BSD-3-Clause

package krl

import (
	"bytes"
	"crypto/sha1"
	"crypto/sha256"
	"errors"
	"fmt"
	"math"
	"math/bits"
	"slices"
	"time"

	"golang.org/x/crypto/ssh"
)

// The constants of PROTOCOL.krl.
const (
	magic         = "SSHKRL\n\x00"
	formatVersion = 1

	sectionCertificates      = 1
	sectionExplicitKey       = 2
	sectionFingerprintSHA1   = 3
	sectionSignature         = 4
	sectionFingerprintSHA256 = 5
	sectionExtension         = 255

	certSerialList   = 0x20
	certSerialRange  = 0x21
	certSerialBitmap = 0x22
	certKeyID        = 0x23
	certExtension    = 0x39
)

// maxSize is SSHBUF_SIZE_MAX, the largest file OpenSSH loads.
const maxSize = 0x8000000

// KRL is a parsed key revocation list. The zero value revokes nothing.
// A KRL is not modified by IsRevoked and may be shared between goroutines.
type KRL struct {
	// Version is krl_version, a number that grows each time the list
	// changes.
	Version uint64
	// GeneratedDate is when the list was generated, in UTC.
	GeneratedDate time.Time
	// Flags is the header's flags word. PROTOCOL.krl defines none.
	Flags uint64
	// Comment is the free-form comment of the header.
	Comment string
	// Expires is when the list stops being current, from the
	// ExtensionExpires extension; zero when the list does not say. sshd
	// ignores it -- the extension is not critical -- and a verifier that
	// enforces freshness reads it here.
	Expires time.Time
	// Signed reports that the list carried a signature section. The
	// signature is skipped, never verified: see the package documentation.
	Signed bool

	certs   map[string]*certRevocations // by CA key blob; "" is any CA
	keys    map[string]struct{}         // plain public key blobs
	sha1s   map[string]struct{}
	sha256s map[string]struct{}
}

// certRevocations is what one certificate section says about one CA.
type certRevocations struct {
	serials []serialRange // sorted, disjoint, never adjacent once parsed
	bitmaps []bitmapSpan  // sorted, disjoint once parsed
	ids     map[string]struct{}
}

// bitmapSpan is a serial bitmap kept as one: bit n of words (little-endian,
// 64 to a word) is serial lo+n, for serials lo through hi. Turning each run
// of set bits into a serialRange instead costs 16 bytes per run, which an
// alternating bitmap makes one run per two bits: 64 times the input.
type bitmapSpan struct {
	lo, hi uint64
	words  []uint64
}

func (b *bitmapSpan) set(n uint64) { b.words[n/64] |= 1 << (n % 64) }

func (b *bitmapSpan) has(s uint64) bool {
	n := s - b.lo
	return b.words[n/64]&(1<<(n%64)) != 0
}

// serialRange is an inclusive range of certificate serials; lo is never 0.
type serialRange struct{ lo, hi uint64 }

// Parse decodes a KRL in the format of OpenSSH's PROTOCOL.krl, refusing what
// ssh-keygen and sshd refuse: a bad magic or format version, truncated or
// trailing data, an unknown section or certificate subsection, an unknown
// extension marked critical, a CA key OpenSSH cannot parse, serial 0, an
// inverted serial range, a bitmap larger than OpenSSH reads or one that
// wraps past 2^64-1. Unknown extensions not marked critical are ignored. A
// signature section is skipped and recorded in Signed.
func Parse(b []byte) (*KRL, error) {
	if len(b) > maxSize {
		return nil, errors.New("krl: larger than OpenSSH loads")
	}
	if !bytes.HasPrefix(b, []byte(magic)) {
		return nil, errors.New("krl: not a KRL (bad magic)")
	}
	r := &reader{b: b[len(magic):]}
	if v := r.u32(); r.err == nil && v != formatVersion {
		return nil, fmt.Errorf("krl: unsupported format version %d", v)
	}
	k := &KRL{
		certs:   map[string]*certRevocations{},
		keys:    map[string]struct{}{},
		sha1s:   map[string]struct{}{},
		sha256s: map[string]struct{}{},
	}
	k.Version = r.u64()
	k.GeneratedDate = time.Unix(int64(r.u64()), 0).UTC()
	k.Flags = r.u64()
	r.str() // reserved
	k.Comment = r.cstr()
	for r.err == nil && len(r.b) > 0 {
		typ := r.u8()
		sect := &reader{b: r.str()}
		if r.err != nil {
			break
		}
		switch typ {
		case sectionCertificates:
			k.parseCertificates(sect)
		case sectionExplicitKey:
			blobSection(sect, k.keys, 0)
		case sectionFingerprintSHA1:
			blobSection(sect, k.sha1s, sha1.Size)
		case sectionFingerprintSHA256:
			blobSection(sect, k.sha256s, sha256.Size)
		case sectionExtension:
			k.extension(sect, "section")
		case sectionSignature:
			// Two strings: the signing key, read above, and the
			// signature. krl.c skips both.
			r.str()
			k.Signed = true
		default:
			sect.fail(fmt.Sprintf("unsupported section type %d", typ))
		}
		if sect.err != nil {
			r.err = sect.err
		}
	}
	if r.err != nil {
		return nil, r.err
	}
	for _, c := range k.certs {
		c.serials = mergeRanges(c.serials)
		c.bitmaps = mergeBitmaps(c.bitmaps)
	}
	return k, nil
}

// blobSection reads a list of strings, each want bytes long unless want is 0.
func blobSection(r *reader, into map[string]struct{}, want int) {
	for r.err == nil && len(r.b) > 0 {
		s := r.str()
		if want != 0 && r.err == nil && len(s) != want {
			r.fail(fmt.Sprintf("fingerprint of %d bytes, want %d", len(s), want))
		}
		into[string(s)] = struct{}{}
	}
}

// extension reads an extension section or subsection and refuses it when
// it is critical: this implementation, like OpenSSH, knows none. k is nil
// for a subsection; a section may be ExtensionExpires, read into k.Expires.
func (k *KRL) extension(r *reader, what string) {
	name := r.cstr()
	critical := r.u8()
	body := r.str()
	switch {
	case r.err != nil:
	case len(r.b) != 0:
		r.fail("trailing data in extension " + what)
	case critical != 0:
		r.fail(fmt.Sprintf("unsupported critical extension %s %q", what, name))
	case k != nil && name == ExtensionExpires:
		// Ours, so held to its format: a malformed or repeated expiry
		// read as "no expiry" would turn a list meant to lapse into one
		// that never does.
		v := &reader{b: body}
		t := v.u64()
		switch {
		case v.err != nil || len(v.b) != 0:
			r.fail(ExtensionExpires + " is not one uint64")
		case !k.Expires.IsZero():
			r.fail(ExtensionExpires + " appears twice")
		case t == 0 || t > math.MaxInt64:
			r.fail(ExtensionExpires + " is out of range")
		default:
			k.Expires = time.Unix(int64(t), 0).UTC()
		}
	}
}

// ExtensionExpires names a KRL extension section carrying, as a uint64 of
// seconds since 1970-01-01 UTC, the time after which the list is no longer
// current -- what a CRL's nextUpdate is (RFC 5280, 5.1.2.5). It is written
// not critical, so sshd, which knows no extension, loads the list and
// ignores it; PROTOCOL.krl section 5 recommends the name@domain form.
//
// It says nothing unless the list is authenticated: a list fetched over a
// channel anyone can write to carries whatever expiry the writer chose.
// Sign the list (SSHSIG, which PROTOCOL.krl recommends over its own
// signature section) and check both.
const ExtensionExpires = "expires@go-authn.github.io"

func (k *KRL) parseCertificates(r *reader) {
	caBlob := r.str()
	r.str() // reserved
	if r.err != nil {
		return
	}
	ca := ""
	if len(caBlob) > 0 {
		pub, err := ssh.ParsePublicKey(caBlob)
		if err != nil {
			r.fail("CA key: " + err.Error())
			return
		}
		ca = string(pub.Marshal())
	}
	rc := k.certs[ca]
	if rc == nil {
		rc = &certRevocations{ids: map[string]struct{}{}}
		k.certs[ca] = rc
	}
	for r.err == nil && len(r.b) > 0 {
		typ := r.u8()
		sub := &reader{b: r.str()}
		if r.err != nil {
			return
		}
		switch typ {
		case certSerialList:
			for sub.err == nil && len(sub.b) > 0 {
				s := sub.u64()
				rc.add(sub, s, s)
			}
		case certSerialRange:
			lo, hi := sub.u64(), sub.u64()
			rc.add(sub, lo, hi)
		case certSerialBitmap:
			offset := sub.u64()
			rc.addBitmap(sub, offset, sub.mpint())
		case certKeyID:
			for sub.err == nil && len(sub.b) > 0 {
				id := sub.cstr()
				if sub.err == nil {
					rc.ids[id] = struct{}{}
				}
			}
		case certExtension:
			(*KRL)(nil).extension(sub, "subsection")
		default:
			sub.fail(fmt.Sprintf("unsupported certificate subsection type %#x", typ))
		}
		if sub.err == nil && len(sub.b) > 0 {
			sub.fail("trailing data in certificate subsection")
		}
		r.err = sub.err
	}
}

// add records lo..hi, refusing what ssh_krl_revoke_cert_by_serial_range
// refuses.
func (rc *certRevocations) add(r *reader, lo, hi uint64) {
	if r.err != nil {
		return
	}
	if lo == 0 || lo > hi {
		r.fail(fmt.Sprintf("invalid serial range %d-%d", lo, hi))
		return
	}
	rc.serials = append(rc.serials, serialRange{lo, hi})
}

// addBitmap records the serials offset+N for every bit N set in bitmap, a
// big-endian magnitude, as a bitmapSpan.
func (rc *certRevocations) addBitmap(r *reader, offset uint64, bitmap []byte) {
	if r.err != nil || len(bitmap) == 0 {
		return
	}
	nbits := uint64(len(bitmap)-1)*8 + uint64(bits.Len8(bitmap[0]))
	// krl.c refuses the bitmap when some index below nbits, other than
	// 0, lands on serial 0 by wrapping.
	if offset != 0 && nbits-1 >= -offset {
		r.fail("serial bitmap wraps past 2^64-1")
		return
	}
	// Bit 0 at offset 0 is serial 0, which krl.c refuses.
	if offset == 0 && bitmap[len(bitmap)-1]&1 != 0 {
		rc.add(r, 0, 0)
		return
	}
	span := bitmapSpan{lo: offset, hi: offset + nbits - 1, words: make([]uint64, (nbits+63)/64)}
	for i, by := range slices.Backward(bitmap) {
		for bit := range 8 {
			if by&(1<<bit) != 0 {
				span.set(uint64(len(bitmap)-1-i)*8 + uint64(bit))
			}
		}
	}
	rc.bitmaps = append(rc.bitmaps, span)
}

// mergeBitmaps sorts spans and ORs together those that overlap, so that a
// serial is in at most one of them. The words of the result are no more than
// those of the input, however the spans overlap.
func mergeBitmaps(bs []bitmapSpan) []bitmapSpan {
	slices.SortFunc(bs, func(a, b bitmapSpan) int {
		switch {
		case a.lo < b.lo:
			return -1
		case a.lo > b.lo:
			return 1
		}
		return 0
	})
	out := bs[:0]
	for _, b := range bs {
		n := len(out)
		if n == 0 || b.lo > out[n-1].hi {
			out = append(out, b)
			continue
		}
		cur := &out[n-1]
		if b.hi > cur.hi {
			cur.hi = b.hi
			cur.words = append(cur.words, make([]uint64, (cur.hi-cur.lo)/64+1-uint64(len(cur.words)))...)
		}
		shift := b.lo - cur.lo
		for i, w := range b.words {
			pos := shift + uint64(i)*64
			cur.words[pos/64] |= w << (pos % 64)
			if rest := w >> (64 - pos%64); pos%64 != 0 && rest != 0 {
				cur.words[pos/64+1] |= rest
			}
		}
	}
	return out
}

// revokesBitmap reports whether serial is set in bs, which mergeBitmaps has
// sorted.
func revokesBitmap(bs []bitmapSpan, serial uint64) bool {
	i, found := slices.BinarySearchFunc(bs, serial, func(b bitmapSpan, s uint64) int {
		switch {
		case b.hi < s:
			return -1
		case b.lo > s:
			return 1
		}
		return 0
	})
	return found && bs[i].has(serial)
}

// mergeRanges sorts ranges and joins those that overlap or touch, as
// insert_serial_range does as it goes.
func mergeRanges(rs []serialRange) []serialRange {
	slices.SortFunc(rs, func(a, b serialRange) int {
		switch {
		case a.lo < b.lo:
			return -1
		case a.lo > b.lo:
			return 1
		}
		return 0
	})
	out := rs[:0]
	for _, r := range rs {
		if n := len(out); n > 0 && (out[n-1].hi == ^uint64(0) || r.lo <= out[n-1].hi+1) {
			out[n-1].hi = max(out[n-1].hi, r.hi)
			continue
		}
		out = append(out, r)
	}
	return out
}

// revokes reports whether serial falls in rs, which mergeRanges has sorted.
func revokesSerial(rs []serialRange, serial uint64) bool {
	i, _ := slices.BinarySearchFunc(rs, serial, func(r serialRange, s uint64) int {
		switch {
		case r.hi < s:
			return -1
		case r.lo > s:
			return 1
		}
		return 0
	})
	return i < len(rs) && rs[i].lo <= serial && serial <= rs[i].hi
}

// IsRevoked reports whether key is revoked by k, with the semantics of
// ssh_krl_check_key in OpenSSH's krl.c. A plain key is revoked when its
// SHA-1 or SHA-256 fingerprint or its blob is listed. A certificate
// (*ssh.Certificate) is revoked when its public key is revoked that way,
// when its key ID or its serial is revoked under the CA that signed it or
// under any CA, or when that CA key is itself revoked. Serial 0, what a CA
// writes when it names none, is never revoked by serial.
//
// Key IDs are compared as C strings, as OpenSSH does: an ID stops at its
// first NUL. OpenSSH refuses a certificate whose ID has an embedded NUL;
// golang.org/x/crypto/ssh does not, so such a certificate is judged by the
// part before the NUL.
func (k *KRL) IsRevoked(key ssh.PublicKey) bool {
	if k.keyRevoked(key) {
		return true
	}
	if cert, ok := key.(*ssh.Certificate); ok {
		return k.keyRevoked(cert.SignatureKey)
	}
	return false
}

// keyRevoked is krl.c's is_key_revoked: it does not look at the CA key.
func (k *KRL) keyRevoked(key ssh.PublicKey) bool {
	cert, isCert := key.(*ssh.Certificate)
	if isCert {
		key = cert.Key
	}
	blob := key.Marshal()
	s1, s256 := sha1.Sum(blob), sha256.Sum256(blob)
	if has(k.sha1s, string(s1[:])) || has(k.sha256s, string(s256[:])) || has(k.keys, string(blob)) {
		return true
	}
	if !isCert {
		return false
	}
	return k.certRevoked(cert, k.certs[string(cert.SignatureKey.Marshal())]) ||
		k.certRevoked(cert, k.certs[""])
}

func (k *KRL) certRevoked(cert *ssh.Certificate, rc *certRevocations) bool {
	if rc == nil {
		return false
	}
	id := cert.KeyId
	if i := bytes.IndexByte([]byte(id), 0); i >= 0 {
		id = id[:i]
	}
	if has(rc.ids, id) {
		return true
	}
	// No range holds serial 0 (Parse refuses it), so a certificate without a
	// serial is never revoked by serial, as in krl.c.
	return rc.revokesSerial(cert.Serial)
}

// revokesSerial reports whether serial is revoked by a range or a bitmap.
func (rc *certRevocations) revokesSerial(serial uint64) bool {
	return revokesSerial(rc.serials, serial) || revokesBitmap(rc.bitmaps, serial)
}

func has(m map[string]struct{}, k string) bool {
	_, ok := m[k]
	return ok
}
