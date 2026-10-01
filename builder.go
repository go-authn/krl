// SPDX-License-Identifier: BSD-3-Clause

package krl

import (
	"bytes"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
)

// Builder accumulates revocations and encodes them as a KRL that ssh-keygen
// and sshd accept. It never writes a signature section. The Revoke methods
// record the first invalid request and Marshal returns it. A Builder is not
// safe for concurrent use.
type Builder struct {
	version uint64
	comment string
	cas     []*builderCA // in the order first named, as krl.c keeps them
	keys    map[string]struct{}
	expires time.Time
	err     error
}

type builderCA struct {
	blob    []byte // nil for any CA
	serials []serialRange
	ids     map[string]struct{}
}

// NewBuilder returns a Builder for a KRL with this krl_version and comment.
func NewBuilder(version uint64, comment string) *Builder {
	return &Builder{version: version, comment: comment, keys: map[string]struct{}{}}
}

func (b *Builder) fail(err error) {
	if b.err == nil {
		b.err = err
	}
}

// ca returns the entry for a CA key, nil meaning any CA, creating it on
// first use.
func (b *Builder) ca(ca ssh.PublicKey) *builderCA {
	var blob []byte
	if ca != nil {
		if _, ok := ca.(*ssh.Certificate); ok {
			b.fail(errors.New("krl: a CA key must be a plain key, not a certificate"))
		}
		blob = ca.Marshal()
	}
	for _, c := range b.cas {
		if bytes.Equal(c.blob, blob) {
			return c
		}
	}
	c := &builderCA{blob: blob, ids: map[string]struct{}{}}
	b.cas = append(b.cas, c)
	return c
}

// RevokeSerial revokes the certificate with this serial signed by ca, or by
// any CA when ca is nil. Serial 0 cannot be revoked: it is what a CA writes
// when it names no serial, and OpenSSH refuses it.
func (b *Builder) RevokeSerial(ca ssh.PublicKey, serial uint64) {
	b.RevokeSerialRange(ca, serial, serial)
}

// RevokeSerialRange revokes the certificates with serials lo through hi,
// both included, signed by ca, or by any CA when ca is nil. lo must not be 0
// nor greater than hi.
func (b *Builder) RevokeSerialRange(ca ssh.PublicKey, lo, hi uint64) {
	if lo == 0 || lo > hi {
		b.fail(fmt.Errorf("krl: invalid serial range %d-%d", lo, hi))
		return
	}
	c := b.ca(ca)
	c.serials = append(c.serials, serialRange{lo, hi})
}

// RevokeKeyID revokes the certificates with this key ID signed by ca, or by
// any CA when ca is nil. An ID cannot contain a NUL.
func (b *Builder) RevokeKeyID(ca ssh.PublicKey, id string) {
	if strings.IndexByte(id, 0) >= 0 {
		b.fail(fmt.Errorf("krl: key ID %q contains a NUL", id))
		return
	}
	b.ca(ca).ids[id] = struct{}{}
}

// RevokeKey revokes a key the way ssh-keygen -k does for a public key line
// of its specification (ssh_krl_revoke_key): a plain key is listed as an
// explicit key, which also revokes every certificate made for it and, when
// it is a CA key, every certificate it signed; a certificate is revoked by
// its serial under the CA that signed it, or by its key ID when its serial
// is 0.
func (b *Builder) RevokeKey(key ssh.PublicKey) {
	cert, ok := key.(*ssh.Certificate)
	switch {
	case !ok:
		b.keys[string(key.Marshal())] = struct{}{}
	case cert.Serial == 0:
		b.RevokeKeyID(cert.SignatureKey, cert.KeyId)
	default:
		b.RevokeSerial(cert.SignatureKey, cert.Serial)
	}
}

// Marshal encodes the KRL with now as its generation date. The output
// depends only on the revocations and on the order in which CAs were first
// named. Serials are encoded as lists, ranges and bitmaps chosen by the cost
// model of krl.c, except that a bitmap is never let grow past what OpenSSH
// can read back (ssh-keygen itself does not stop there).
func (b *Builder) Marshal(now time.Time) ([]byte, error) {
	if b.err != nil {
		return nil, b.err
	}
	if strings.IndexByte(b.comment, 0) >= 0 {
		return nil, errors.New("krl: comment contains a NUL")
	}
	if now.Unix() < 0 {
		return nil, errors.New("krl: generation date before 1970")
	}
	w := &writer{b: []byte(magic)}
	w.u32(formatVersion)
	w.u64(b.version)
	w.u64(uint64(now.Unix()))
	w.u64(0)   // flags
	w.str(nil) // reserved
	w.str([]byte(b.comment))
	for _, c := range b.cas {
		w.u8(sectionCertificates)
		w.str(c.section())
	}
	if len(b.keys) > 0 {
		s := &writer{}
		for _, k := range sortedKeys(b.keys) {
			s.str([]byte(k))
		}
		w.u8(sectionExplicitKey)
		w.str(s.b)
	}
	if !b.expires.IsZero() {
		if !b.expires.After(now) {
			return nil, errors.New("krl: the list would expire before it was generated")
		}
		v := &writer{}
		v.u64(uint64(b.expires.Unix()))
		e := &writer{}
		e.str([]byte(ExtensionExpires))
		e.u8(0) // not critical: sshd loads the list and ignores it
		e.str(v.b)
		w.u8(sectionExtension)
		w.str(e.b)
	}
	return w.b, nil
}

// SetExpires records t, in the ExtensionExpires extension, as the time
// after which the list is no longer current. Zero, the default, writes no
// expiry. t is kept to the second.
func (b *Builder) SetExpires(t time.Time) {
	b.expires = t.Truncate(time.Second)
}

func sortedKeys(m map[string]struct{}) []string {
	ks := make([]string, 0, len(m))
	for k := range m {
		ks = append(ks, k)
	}
	slices.Sort(ks) // bytewise, as krl.c's blob_cmp and strcmp order them
	return ks
}

// maxBitmapBits is the widest bitmap OpenSSH reads back: an mpint of at
// most SSHBUF_MAX_BIGNUM bytes.
const maxBitmapBits = maxBignum * 8

// section encodes one certificate section, as revoked_certs_generate does.
func (c *builderCA) section() []byte {
	w := &writer{}
	w.str(c.blob)
	w.str(nil) // reserved
	serials := mergeRanges(c.serials)
	var (
		state       byte
		sect        *writer
		bitmap      []byte // little-endian bytes: bit n is serial start+n
		bitmapStart uint64
		last        uint64
	)
	flush := func() {
		if state == certSerialBitmap {
			slices.Reverse(bitmap)
			sect.mpint(bitmap)
		}
		w.u8(state)
		w.str(sect.b)
	}
	for i, rs := range serials {
		final := i == len(serials)-1
		var gap, lastGap uint64
		if !final {
			gap = serials[i+1].lo - rs.hi
		}
		if state != 0 {
			lastGap = rs.lo - last
		}
		contig := 1 + (rs.hi - rs.lo)
		next, restart := chooseNextState(state, contig, final, lastGap, gap)
		if next == certSerialBitmap && state == certSerialBitmap && !restart &&
			rs.hi-bitmapStart >= maxBitmapBits {
			// Growing this bitmap would make it unreadable: choose
			// as if starting afresh. A bitmap is only chosen for a
			// short run, far below maxBitmapBits.
			next, _ = chooseNextState(0, contig, final, 0, gap)
			restart = true
		}
		if state != 0 && (restart || next != state || state == certSerialRange) {
			flush()
		}
		if next != state || restart || state == certSerialRange {
			state = next
			sect = &writer{}
			if state == certSerialBitmap {
				bitmap = nil
				bitmapStart = rs.lo
				sect.u64(bitmapStart)
			}
		}
		switch state {
		case certSerialList:
			for s := rs.lo; ; s++ {
				sect.u64(s)
				if s == rs.hi {
					break
				}
			}
		case certSerialRange:
			sect.u64(rs.lo)
			sect.u64(rs.hi)
		default: // certSerialBitmap
			for n := rs.lo - bitmapStart; ; n++ {
				for uint64(len(bitmap)) <= n/8 {
					bitmap = append(bitmap, 0)
				}
				bitmap[n/8] |= 1 << (n % 8)
				if n == rs.hi-bitmapStart {
					break
				}
			}
		}
		last = rs.hi
	}
	if state != 0 {
		flush()
	}
	if len(c.ids) > 0 {
		s := &writer{}
		for _, id := range sortedKeys(c.ids) {
			s.str([]byte(id))
		}
		w.u8(certKeyID)
		w.str(s.b)
	}
	return w.b
}

// chooseNextState is krl.c's choose_next_state: it picks the encoding that
// minimises an estimate of the output size, in bits, for the next run of
// contig serials, given the current encoding and the gaps to the previous
// and next runs. restart asks for a new bitmap section.
func chooseNextState(current byte, contig uint64, final bool, lastGap, nextGap uint64) (next byte, restart bool) {
	contig = min(contig, 1<<31)
	lastGap = min(lastGap, 1<<31)
	nextGap = min(nextGap, 1<<31)

	var costList, costBitmap, costBitmapRestart uint64
	costRange := uint64(8)
	switch current {
	case certSerialList:
		costBitmapRestart, costBitmap = 8+64, 8+64
	case certSerialBitmap:
		costList = 8
		costBitmapRestart = 8 + 64
	default: // certSerialRange, or no section yet
		costBitmapRestart, costBitmap = 8+64, 8+64
		costList = 8
	}
	var more, moreBitmap uint64
	if !final {
		more, moreBitmap = 8+64, min(nextGap, 8+64)
	}
	costList += 64*contig + more
	costRange += 2*64 + more
	costBitmap += lastGap + contig + moreBitmap
	costBitmapRestart += contig + moreBitmap

	costList = (costList + 7) / 8
	costBitmap = (costBitmap + 7) / 8
	costBitmapRestart = (costBitmapRestart + 7) / 8
	costRange = (costRange + 7) / 8

	next, cost := byte(certSerialBitmap), costBitmap
	if costRange < cost {
		next, cost = certSerialRange, costRange
	}
	if costList < cost {
		next, cost = certSerialList, costList
	}
	if costBitmapRestart < cost {
		next, restart = certSerialBitmap, true
	}
	return next, restart
}
