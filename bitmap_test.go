// SPDX-License-Identifier: BSD-3-Clause

package krl

import (
	"math/rand/v2"
	"runtime"
	"testing"
)

// alternatingBitmaps returns a KRL of about size bytes: one certificate
// section of 0x55 bitmaps at distinct offsets, a run of set bits every other
// bit -- the shape that made one 16-byte range per two bits.
func alternatingBitmaps(size, bitmapLen int) []byte {
	bm := make([]byte, bitmapLen)
	for i := range bm {
		bm[i] = 0x55
	}
	ca := &writer{}
	ca.str(nil)
	ca.str(nil)
	for off := uint64(1); len(ca.b) < size; off += uint64(bitmapLen)*8 + 1000 {
		sub := &writer{}
		sub.u64(off)
		sub.mpint(bm)
		ca.u8(certSerialBitmap)
		ca.str(sub.b)
	}
	return header().section(sectionCertificates, ca.b).b
}

// TestBitmapNotAmplified: 2 MiB of alternating bitmaps used to become some
// 150 MiB of live ranges (1193 MiB for 16 MiB, ~9.5 GiB at maxSize). Kept as
// bitmaps, what stays live is of the order of the input.
func TestBitmapNotAmplified(t *testing.T) {
	in := alternatingBitmaps(2<<20, 2048)
	var m0, m1 runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&m0)
	k, err := Parse(in)
	if err != nil {
		t.Fatal(err)
	}
	runtime.GC()
	runtime.ReadMemStats(&m1)
	live := int64(m1.HeapAlloc) - int64(m0.HeapAlloc)
	t.Logf("input %d KiB -> live %d KiB", len(in)>>10, live>>10)
	// The fixed code keeps about 1x; the old one 75x. 8x leaves room for
	// whatever else the runtime holds without letting the defect back.
	if live > 8*int64(len(in)) {
		t.Fatalf("a %d-byte KRL keeps %d bytes live (%.0fx)", len(in), live, float64(live)/float64(len(in)))
	}
	runtime.KeepAlive(k)
	runtime.KeepAlive(in)
}

// TestBitmapWordsBoundedByInput: structurally, however bitmaps overlap, the
// words kept never exceed the bits read.
func TestBitmapWordsBoundedByInput(t *testing.T) {
	in := alternatingBitmaps(1<<20, 1)
	k, err := Parse(in)
	if err != nil {
		t.Fatal(err)
	}
	rc := k.certs[""]
	if len(rc.serials) != 0 {
		t.Fatalf("%d ranges made from bitmaps", len(rc.serials))
	}
	words := 0
	for _, b := range rc.bitmaps {
		words += len(b.words)
	}
	if spans := len(rc.bitmaps); words != spans {
		t.Fatalf("%d one-byte bitmaps kept as %d words", spans, words)
	}
}

// TestBitmapsMatchNaive: overlapping bitmaps at unaligned offsets, merged,
// revoke exactly the serials a set built bit by bit does.
func TestBitmapsMatchNaive(t *testing.T) {
	rng := rand.New(rand.NewPCG(1, 2))
	for round := range 200 {
		want := map[uint64]bool{}
		ca := &writer{}
		ca.str(nil)
		ca.str(nil)
		for range 1 + rng.IntN(12) {
			off := 1 + uint64(rng.IntN(600))
			bm := make([]byte, 1+rng.IntN(40))
			for i := range bm {
				bm[i] = byte(rng.Uint32())
			}
			if rng.IntN(4) == 0 {
				for i := range bm {
					bm[i] = 0xff
				}
			}
			for i, by := range bm {
				for bit := range 8 {
					if by&(1<<bit) != 0 {
						want[off+uint64(len(bm)-1-i)*8+uint64(bit)] = true
					}
				}
			}
			sub := &writer{}
			sub.u64(off)
			sub.mpint(bm)
			ca.u8(certSerialBitmap)
			ca.str(sub.b)
		}
		k, err := Parse(header().section(sectionCertificates, ca.b).b)
		if err != nil {
			t.Fatalf("round %d: %v", round, err)
		}
		bs := k.certs[""].bitmaps
		for i := 1; i < len(bs); i++ {
			if bs[i].lo <= bs[i-1].hi {
				t.Fatalf("round %d: spans %d and %d overlap", round, i-1, i)
			}
		}
		for s := uint64(0); s < 1200; s++ {
			if got := revokesBitmap(bs, s); got != want[s] {
				t.Fatalf("round %d: serial %d revoked = %v, want %v", round, s, got, want[s])
			}
		}
	}
}
