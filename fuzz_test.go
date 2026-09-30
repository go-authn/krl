// SPDX-License-Identifier: BSD-3-Clause

package krl

// testdata/ssh-keygen-*.krl were written by OpenSSH 10.3p1's ssh-keygen -k:
// ssh-keygen-certs.krl revokes serials 5, 10-20, 100, 101, 103, 106, 1000,
// 50000 and key ID alice under an ed25519 and an ECDSA CA (a list, a range
// and a bitmap each) and serial 30 and key ID carol under any CA;
// ssh-keygen-keys.krl revokes one explicit key, one SHA-256 and one SHA-1
// fingerprint. They seed the fuzzers on every lane, including those
// without ssh-keygen.

import (
	"encoding/binary"
	"os"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

func seeds(f *testing.F) {
	files, err := filepath.Glob("testdata/*.krl")
	if err != nil || len(files) == 0 {
		f.Fatalf("no seed KRLs in testdata: %v", err)
	}
	for _, p := range files {
		b, err := os.ReadFile(p)
		if err != nil {
			f.Fatal(err)
		}
		if _, err := Parse(b); err != nil {
			f.Fatalf("%s: %v", p, err)
		}
		f.Add(b)
	}
	b := NewBuilder(1, "seed")
	for s := uint64(1); s < 400; s += 1 + s%7 {
		b.RevokeSerial(testKey(f, 1).PublicKey(), s)
	}
	b.RevokeKeyID(nil, "id")
	out, err := b.Marshal(time.Unix(1, 0))
	if err != nil {
		f.Fatal(err)
	}
	f.Add(out)
	f.Add(signKRL(f, out, testKey(f, 2)))
}

// FuzzParse: Parse never panics, and what it accepts can be queried.
func FuzzParse(f *testing.F) {
	seeds(f)
	ca := testKey(f, 1)
	probes := []ssh.PublicKey{ca.PublicKey(), testKey(f, 3).PublicKey()}
	for _, s := range []uint64{0, 1, 5, 30, 101, 102, 1 << 63} {
		probes = append(probes, testCert(f, ca, testKey(f, 3).PublicKey(), s, "alice"))
	}
	f.Fuzz(func(t *testing.T, b []byte) {
		k, err := Parse(b)
		if err != nil {
			return
		}
		for _, p := range probes {
			k.IsRevoked(p)
		}
	})
}

// FuzzBuilder turns bytes into revocations and checks that the KRL Builder
// writes is read back by Parse with every one of them, and nothing next to
// them. (The oracle tests are what hold Builder to ssh-keygen.)
func FuzzBuilder(f *testing.F) {
	f.Add([]byte{0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 9})
	f.Add([]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24})
	ca := testKey(f, 1)
	f.Fuzz(func(t *testing.T, data []byte) {
		b := NewBuilder(1, "")
		type rng struct{ lo, hi uint64 }
		var want []rng
		for len(data) >= 4 {
			lo := uint64(binary.BigEndian.Uint16(data)) + 1
			n := uint64(data[2]) % 16
			if data[3]&1 == 0 {
				n = 0
			}
			data = data[4:]
			b.RevokeSerialRange(ca.PublicKey(), lo, lo+n)
			want = append(want, rng{lo, lo + n})
		}
		out, err := b.Marshal(time.Unix(0, 0))
		if err != nil {
			t.Fatal(err)
		}
		k, err := Parse(out)
		if err != nil {
			t.Fatalf("Parse(Builder output): %v", err)
		}
		in := func(s uint64) bool {
			for _, r := range want {
				if r.lo <= s && s <= r.hi {
					return true
				}
			}
			return false
		}
		for _, r := range want {
			for _, s := range []uint64{r.lo - 1, r.lo, r.hi, r.hi + 1} {
				if got := revokesSerial(k.certs[string(ca.PublicKey().Marshal())].serials, s); got != in(s) {
					t.Fatalf("serial %d: revoked = %v, want %v", s, got, in(s))
				}
			}
		}
	})
}
