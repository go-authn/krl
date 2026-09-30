// SPDX-License-Identifier: BSD-3-Clause

package krl

// Pure-Go tests: they run on every lane, Windows included, and reach every
// branch the ssh-keygen oracle cannot provoke on its own.

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

// testKey returns a deterministic ed25519 signer.
func testKey(t testing.TB, seed byte) ssh.Signer {
	t.Helper()
	s, err := ssh.NewSignerFromKey(ed25519.NewKeyFromSeed(bytes.Repeat([]byte{seed}, ed25519.SeedSize)))
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func testCert(t testing.TB, ca ssh.Signer, key ssh.PublicKey, serial uint64, id string) *ssh.Certificate {
	t.Helper()
	c := &ssh.Certificate{Key: key, Serial: serial, KeyId: id, CertType: ssh.UserCert, ValidBefore: ssh.CertTimeInfinity}
	if err := c.SignCert(rand.Reader, ca); err != nil {
		t.Fatal(err)
	}
	return c
}

// header returns a KRL header with no sections.
func header() *writer {
	w := &writer{b: []byte(magic)}
	w.u32(formatVersion)
	w.u64(1)
	w.u64(1_700_000_000)
	w.u64(0)
	w.str(nil)
	w.str([]byte("c"))
	return w
}

// section appends a section of type typ holding data.
func (w *writer) section(typ byte, data []byte) *writer {
	w.u8(typ)
	w.str(data)
	return w
}

// certs returns certificate section data for ca (nil: any CA) holding the
// given subsections, each a type followed by its data.
func certs(ca []byte, subs ...any) []byte {
	w := &writer{}
	w.str(ca)
	w.str(nil)
	for i := 0; i < len(subs); i += 2 {
		w.u8(subs[i].(byte))
		w.str(subs[i+1].([]byte))
	}
	return w.b
}

func u64s(vs ...uint64) []byte {
	w := &writer{}
	for _, v := range vs {
		w.u64(v)
	}
	return w.b
}

func strs(vs ...string) []byte {
	w := &writer{}
	for _, v := range vs {
		w.str([]byte(v))
	}
	return w.b
}

func bitmapSub(offset uint64, mpint []byte) []byte {
	w := &writer{}
	w.u64(offset)
	w.str(mpint)
	return w.b
}

func ext(name string, critical byte, value string, trailing ...byte) []byte {
	w := &writer{}
	w.str([]byte(name))
	w.u8(critical)
	w.str([]byte(value))
	return append(w.b, trailing...)
}

func TestParseRefuses(t *testing.T) {
	ca := testKey(t, 1).PublicKey().Marshal()
	cases := map[string][]byte{
		"empty":            nil,
		"bad magic":        []byte("SSHKRL\n\x01"),
		"format version":   append([]byte(magic), 0, 0, 0, 2),
		"truncated header": header().b[:30],
		"section length":   append(header().b, 1, 0, 0, 0, 9),
		"unknown section":  header().section(6, nil).b,
		"comment with NUL": func() []byte {
			w := &writer{b: []byte(magic)}
			w.u32(1)
			w.u64(0)
			w.u64(0)
			w.u64(0)
			w.str(nil)
			w.str([]byte("a\x00b"))
			return w.b
		}(),
		"sha1 length":             header().section(sectionFingerprintSHA1, strs("short")).b,
		"sha256 length":           header().section(sectionFingerprintSHA256, strs(strings.Repeat("x", 20))).b,
		"explicit key truncated":  header().section(sectionExplicitKey, []byte{0, 0, 0, 5, 1}).b,
		"critical extension":      header().section(sectionExtension, ext("x@y", 1, "")).b,
		"critical extension (2)":  header().section(sectionExtension, ext("x@y", 0x80, "")).b,
		"extension trailing data": header().section(sectionExtension, ext("x@y", 0, "", 7)).b,
		"extension truncated":     header().section(sectionExtension, []byte{0, 0, 0, 1, 'x'}).b,
		"signature truncated":     header().section(sectionSignature, []byte("k")).b,
		"certs truncated":         header().section(sectionCertificates, []byte{0, 0, 0, 0}).b,
		"bad CA key":              header().section(sectionCertificates, certs([]byte("\x00\x00\x00\x03abc"))).b,
		"CA key trailing data":    header().section(sectionCertificates, certs(append(ca, 0))).b,
		"subsection truncated":    header().section(sectionCertificates, append(certs(ca), certSerialList, 0, 0, 0, 1)).b,
		"unknown subsection":      header().section(sectionCertificates, certs(ca, byte(0x24), []byte{})).b,
		"list serial 0":           header().section(sectionCertificates, certs(ca, byte(certSerialList), u64s(3, 0))).b,
		"list truncated":          header().section(sectionCertificates, certs(ca, byte(certSerialList), []byte{0, 0, 1})).b,
		"range lo 0":              header().section(sectionCertificates, certs(ca, byte(certSerialRange), u64s(0, 5))).b,
		"range inverted":          header().section(sectionCertificates, certs(ca, byte(certSerialRange), u64s(6, 5))).b,
		"range trailing data":     header().section(sectionCertificates, certs(ca, byte(certSerialRange), u64s(1, 5, 9))).b,
		"range truncated":         header().section(sectionCertificates, certs(ca, byte(certSerialRange), u64s(1))).b,
		"bitmap negative":         header().section(sectionCertificates, certs(ca, byte(certSerialBitmap), bitmapSub(1, []byte{0x80}))).b,
		"bitmap too large":        header().section(sectionCertificates, certs(ca, byte(certSerialBitmap), bitmapSub(1, append([]byte{1}, make([]byte, maxBignum)...)))).b,
		"bitmap too large (2)":    header().section(sectionCertificates, certs(ca, byte(certSerialBitmap), bitmapSub(1, append([]byte{0, 0}, make([]byte, maxBignum)...)))).b,
		"bitmap serial 0":         header().section(sectionCertificates, certs(ca, byte(certSerialBitmap), bitmapSub(0, []byte{0x03}))).b,
		"bitmap wraps":            header().section(sectionCertificates, certs(ca, byte(certSerialBitmap), bitmapSub(^uint64(0), []byte{0x02}))).b,
		"bitmap wraps unset":      header().section(sectionCertificates, certs(ca, byte(certSerialBitmap), bitmapSub(^uint64(0)-1, []byte{0x05}))).b,
		"bitmap trailing data":    header().section(sectionCertificates, certs(ca, byte(certSerialBitmap), append(bitmapSub(1, []byte{1}), 0))).b,
		"key ID with NUL":         header().section(sectionCertificates, certs(ca, byte(certKeyID), strs("a\x00b"))).b,
		"key ID truncated":        header().section(sectionCertificates, certs(ca, byte(certKeyID), []byte{0, 0, 0, 2, 'a'})).b,
		"critical subsection":     header().section(sectionCertificates, certs(ca, byte(certExtension), ext("x@y", 1, "v"))).b,
	}
	for name, b := range cases {
		if _, err := Parse(b); err == nil {
			t.Errorf("%s: Parse accepted %x", name, b)
		} else if !strings.HasPrefix(err.Error(), "krl: ") {
			t.Errorf("%s: error %q lacks the package prefix", name, err)
		}
	}
	if _, err := Parse(make([]byte, maxSize+1)); err == nil || !strings.Contains(err.Error(), "larger") {
		t.Errorf("oversized: %v", err)
	}
}

func TestParseReads(t *testing.T) {
	caS, otherS := testKey(t, 1), testKey(t, 2)
	ca := caS.PublicKey().Marshal()
	user := testKey(t, 3).PublicKey()
	explicit := testKey(t, 4).PublicKey()
	by1 := testKey(t, 5).PublicKey()
	by256 := testKey(t, 6).PublicKey()
	s1 := sha1.Sum(by1.Marshal())
	s256 := sha256.Sum256(by256.Marshal())
	top := ^uint64(0)

	w := header()
	w.section(sectionCertificates, certs(ca,
		byte(certSerialList), u64s(7, 3, 9),
		byte(certSerialRange), u64s(20, 30),
		byte(certSerialRange), u64s(25, 40), // overlaps
		byte(certSerialRange), u64s(41, 41), // touches
		byte(certSerialBitmap), bitmapSub(100, []byte{0x00, 0x01, 0b1011_0001}), // 100, 104, 105, 107, 108
		byte(certSerialBitmap), bitmapSub(200, nil), // empty
		byte(certSerialRange), u64s(top-3, top),
		byte(certSerialRange), u64s(top-9, top-2), // overlaps the top
		byte(certSerialRange), u64s(top-9, top-9), // same lo
		byte(certSerialBitmap), bitmapSub(top, []byte{1}),
		byte(certKeyID), strs("alice", "bob\x00"),
		byte(certExtension), ext("x@y", 0, "ignored"),
	))
	w.section(sectionCertificates, certs(nil, byte(certKeyID), strs("carol"), byte(certSerialList), u64s(500)))
	w.section(sectionCertificates, certs(ca, byte(certSerialList), u64s(600))) // same CA again
	w.section(sectionExplicitKey, strs(string(explicit.Marshal()), "not a key"))
	w.section(sectionFingerprintSHA1, strs(string(s1[:])))
	w.section(sectionFingerprintSHA256, strs(string(s256[:])))
	w.section(sectionExtension, ext("x@y", 0, "v"))
	w.section(sectionSignature, []byte("sigkey"))
	w.str([]byte("signature"))
	w.section(sectionExplicitKey, nil) // after the signature, as krl.c allows

	k, err := Parse(w.b)
	if err != nil {
		t.Fatal(err)
	}
	if k.Version != 1 || !k.GeneratedDate.Equal(time.Unix(1_700_000_000, 0)) || k.Comment != "c" || k.Flags != 0 || !k.Signed {
		t.Fatalf("header: %+v", k)
	}
	if k.GeneratedDate.Location() != time.UTC {
		t.Errorf("GeneratedDate not in UTC")
	}
	revoked := []uint64{3, 7, 9, 20, 30, 35, 40, 41, 100, 104, 105, 107, 108, 600, top - 9, top - 5, top}
	kept := []uint64{0, 1, 2, 4, 8, 10, 19, 42, 99, 101, 102, 103, 106, 109, 200, top - 10}
	for _, s := range revoked {
		if !k.IsRevoked(testCert(t, caS, user, s, "x")) {
			t.Errorf("serial %d not revoked", s)
		}
		if k.IsRevoked(testCert(t, otherS, user, s, "x")) {
			t.Errorf("serial %d revoked under another CA", s)
		}
	}
	for _, s := range kept {
		if k.IsRevoked(testCert(t, caS, user, s, "x")) {
			t.Errorf("serial %d revoked", s)
		}
	}
	for _, c := range []struct {
		ca      ssh.Signer
		serial  uint64
		id      string
		revoked bool
	}{
		{caS, 0, "alice", true},
		{caS, 0, "bob", true}, // "bob\x00" is the C string "bob"
		{caS, 0, "alice\x00tail", true},
		{caS, 0, "dave", false},
		{otherS, 0, "alice", false},
		{otherS, 0, "carol", true},  // any CA
		{otherS, 500, "x", true},    // any CA
		{caS, 500, "x", true},       // any CA
		{otherS, 600, "x", false},   // only caS
		{caS, 0, "carol\x00", true}, // any CA, C string
	} {
		if got := k.IsRevoked(testCert(t, c.ca, user, c.serial, c.id)); got != c.revoked {
			t.Errorf("serial %d id %q: revoked = %v", c.serial, c.id, got)
		}
	}
	for _, key := range []ssh.PublicKey{explicit, by1, by256} {
		if !k.IsRevoked(key) {
			t.Errorf("plain key %s not revoked", ssh.FingerprintSHA256(key))
		}
		if !k.IsRevoked(testCert(t, otherS, key, 77, "x")) {
			t.Errorf("certificate of a revoked key not revoked")
		}
	}
	if k.IsRevoked(user) || k.IsRevoked(caS.PublicKey()) {
		t.Errorf("unrevoked plain key revoked")
	}
	// Revoking the CA key revokes all it signed.
	w2 := header().section(sectionExplicitKey, strs(string(ca)))
	k2, err := Parse(w2.b)
	if err != nil {
		t.Fatal(err)
	}
	if !k2.IsRevoked(testCert(t, caS, user, 1, "x")) || k2.IsRevoked(testCert(t, otherS, user, 1, "x")) {
		t.Errorf("CA key revocation")
	}
	var zero KRL
	if zero.IsRevoked(testCert(t, caS, user, 1, "x")) || zero.IsRevoked(user) {
		t.Errorf("the zero KRL revokes")
	}
}

func TestMergeRanges(t *testing.T) {
	top := ^uint64(0)
	got := mergeRanges([]serialRange{{50, 60}, {1, 2}, {3, 4}, {10, 20}, {10, 12}, {top, top}, {top - 5, top}, {21, 30}, {40, 45}})
	want := []serialRange{{1, 4}, {10, 30}, {40, 45}, {50, 60}, {top - 5, top}}
	if len(got) != len(want) {
		t.Fatalf("got %v", got)
	}
	for i := range got {
		if got[i] != want[i] {
			t.Fatalf("got %v, want %v", got, want)
		}
	}
	for _, s := range []uint64{1, 4, 10, 30, 45, top} {
		if !revokesSerial(got, s) {
			t.Errorf("%d", s)
		}
	}
	for _, s := range []uint64{0, 5, 9, 31, 46, top - 6} {
		if revokesSerial(got, s) {
			t.Errorf("%d", s)
		}
	}
}

func TestWire(t *testing.T) {
	r := &reader{b: []byte{1}}
	if r.u32() != 0 || r.err == nil || r.u8() != 0 || r.u64() != 0 || r.str() != nil {
		t.Fatalf("reads after a failure must return zero values")
	}
	r = &reader{b: []byte{0, 0, 0, 3, 'a', 'b', 0}}
	if s := r.cstr(); s != "ab" || r.err != nil {
		t.Fatalf("cstr with a final NUL: %q %v", s, r.err)
	}
	r = &reader{b: []byte{0, 0, 0, 3, 0, 0, 5}}
	if m := r.mpint(); !bytes.Equal(m, []byte{5}) || r.err != nil {
		t.Fatalf("mpint with leading zeros: %x %v", m, r.err)
	}
	for _, c := range []struct{ in, want []byte }{
		{nil, []byte{0, 0, 0, 0}},
		{[]byte{0, 0x7f}, []byte{0, 0, 0, 1, 0x7f}},
		{[]byte{0x80, 1}, []byte{0, 0, 0, 3, 0, 0x80, 1}},
	} {
		w := &writer{}
		w.mpint(c.in)
		if !bytes.Equal(w.b, c.want) {
			t.Errorf("mpint(%x) = %x, want %x", c.in, w.b, c.want)
		}
	}
}

func TestBuilderRoundTrip(t *testing.T) {
	caS, otherS := testKey(t, 1), testKey(t, 2)
	ca := caS.PublicKey()
	user, plain := testKey(t, 3).PublicKey(), testKey(t, 4).PublicKey()
	b := NewBuilder(9, "comment")
	b.RevokeSerial(ca, 5)
	b.RevokeSerialRange(ca, 1000, 5000)
	for s := uint64(100); s < 130; s += 3 {
		b.RevokeSerial(ca, s) // a bitmap
	}
	b.RevokeSerial(ca, 1<<40) // a list after a range
	b.RevokeSerial(ca, 1<<41)
	b.RevokeKeyID(ca, "alice")
	b.RevokeKeyID(ca, "alice")
	b.RevokeKeyID(nil, "carol")
	b.RevokeSerial(nil, 77)
	b.RevokeKey(plain)
	b.RevokeKey(testCert(t, otherS, user, 0, "by-id"))
	b.RevokeKey(testCert(t, otherS, user, 31, "by-serial"))
	out, err := b.Marshal(time.Unix(1_700_000_000, 0))
	if err != nil {
		t.Fatal(err)
	}
	again, _ := b.Marshal(time.Unix(1_700_000_000, 0))
	if !bytes.Equal(out, again) {
		t.Fatal("Marshal is not deterministic")
	}
	k, err := Parse(out)
	if err != nil {
		t.Fatal(err)
	}
	if k.Version != 9 || k.Comment != "comment" || k.Signed {
		t.Fatalf("header %+v", k)
	}
	for s, want := range map[uint64]bool{
		4: false, 5: true, 6: false, 100: true, 101: false, 127: true, 999: false, 1000: true,
		5000: true, 5001: false, 1 << 40: true, 1<<40 + 1: false, 1 << 41: true, 77: true,
	} {
		if got := k.IsRevoked(testCert(t, caS, user, s, "x")); got != want {
			t.Errorf("serial %d: %v", s, got)
		}
	}
	for _, c := range []struct {
		cert *ssh.Certificate
		want bool
	}{
		{testCert(t, caS, user, 0, "alice"), true},
		{testCert(t, otherS, user, 0, "alice"), false},
		{testCert(t, otherS, user, 0, "carol"), true},
		{testCert(t, otherS, user, 0, "by-id"), true},
		{testCert(t, otherS, user, 31, "z"), true},
		{testCert(t, otherS, user, 32, "z"), false},
		{testCert(t, otherS, plain, 32, "z"), true},
	} {
		if got := k.IsRevoked(c.cert); got != c.want {
			t.Errorf("%d %q: %v", c.cert.Serial, c.cert.KeyId, got)
		}
	}
	if !k.IsRevoked(plain) || k.IsRevoked(user) {
		t.Error("plain keys")
	}
}

// TestBuilderBitmapCap: serials 1, 3, 5, ... would make krl.c grow a single
// bitmap past what it can read back; Builder must start new sections.
func TestBuilderBitmapCap(t *testing.T) {
	ca := testKey(t, 1)
	user := testKey(t, 3).PublicKey()
	b := NewBuilder(1, "")
	for s := uint64(1); s <= 70001; s += 2 {
		b.RevokeSerial(ca.PublicKey(), s)
	}
	out, err := b.Marshal(time.Unix(0, 0))
	if err != nil {
		t.Fatal(err)
	}
	k, err := Parse(out)
	if err != nil {
		t.Fatalf("Builder wrote a KRL Parse refuses: %v", err)
	}
	for _, s := range []uint64{1, 16383, 16385, 32767, 32769, 70001} {
		if !k.IsRevoked(testCert(t, ca, user, s, "x")) || k.IsRevoked(testCert(t, ca, user, s+1, "x")) {
			t.Errorf("serial %d", s)
		}
	}
}

func TestBuilderRefuses(t *testing.T) {
	ca := testKey(t, 1)
	cert := testCert(t, ca, testKey(t, 3).PublicKey(), 1, "x")
	for name, f := range map[string]func(*Builder){
		"serial 0":          func(b *Builder) { b.RevokeSerial(nil, 0) },
		"inverted range":    func(b *Builder) { b.RevokeSerialRange(nil, 5, 4) },
		"NUL key ID":        func(b *Builder) { b.RevokeKeyID(nil, "a\x00") },
		"certificate as CA": func(b *Builder) { b.RevokeKeyID(cert, "a") },
		"first error kept": func(b *Builder) {
			b.RevokeSerial(nil, 0)
			b.RevokeKeyID(nil, "a\x00")
		},
	} {
		b := NewBuilder(1, "")
		f(b)
		if _, err := b.Marshal(time.Now()); err == nil {
			t.Errorf("%s: Marshal succeeded", name)
		}
	}
	b := NewBuilder(1, "")
	b.RevokeSerial(nil, 0)
	b.RevokeKeyID(nil, "a\x00")
	if _, err := b.Marshal(time.Now()); err == nil || !strings.Contains(err.Error(), "serial range") {
		t.Errorf("first error not kept: %v", err)
	}
	if _, err := NewBuilder(1, "a\x00").Marshal(time.Now()); err == nil {
		t.Error("NUL comment accepted")
	}
	if _, err := NewBuilder(1, "").Marshal(time.Unix(-1, 0)); err == nil {
		t.Error("date before 1970 accepted")
	}
}

func TestChooseNextState(t *testing.T) {
	for _, c := range []struct {
		current          byte
		contig           uint64
		final            bool
		lastGap, nextGap uint64
		wantNext         byte
		wantRestart      bool
	}{
		{0, 1, true, 0, 0, certSerialList, false},
		{0, 1000, false, 0, 1 << 40, certSerialRange, false},
		{0, 1, false, 0, 1 << 40, certSerialList, false},
		{certSerialList, 1, false, 1 << 40, 1 << 40, certSerialList, false},
		{certSerialList, 1, false, 1 << 40, 2, certSerialBitmap, true},
		{certSerialBitmap, 1, false, 3, 3, certSerialBitmap, false},
		{certSerialBitmap, 1, false, 1 << 40, 3, certSerialBitmap, true},
		{certSerialRange, 1 << 50, true, 1 << 50, 0, certSerialRange, false},
	} {
		next, restart := chooseNextState(c.current, c.contig, c.final, c.lastGap, c.nextGap)
		if next != c.wantNext || restart != c.wantRestart {
			t.Errorf("%+v: got %#x restart=%v", c, next, restart)
		}
	}
}
