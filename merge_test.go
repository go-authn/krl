// SPDX-License-Identifier: BSD-3-Clause

package krl

import (
	"bytes"
	"fmt"
	"math/rand/v2"
	"strconv"
	"strings"
	"testing"
	"time"
)

// Three lists written by ssh-keygen -k, merged: the merged list revokes,
// in ssh-keygen's own judgement, exactly what at least one of them revokes.
// Each input contributes something only it revokes, so a merge that drops a
// list, a CA or a kind of section is seen.
func TestOracleMergeIsTheUnion(t *testing.T) {
	o := newOracle(t)
	caA := o.keygen("caA", "-t", "ed25519")
	caB := o.keygen("caB", "-t", "ecdsa", "-b", "256")
	caC := o.keygen("caC", "-t", "ed25519")
	u1 := o.keygen("u1", "-t", "ed25519")
	u2 := o.keygen("u2", "-t", "ed25519")
	u3 := o.keygen("u3", "-t", "ecdsa", "-b", "256")
	u4 := o.keygen("u4", "-t", "ed25519")

	// 1: CA A, every serial encoding, a key ID; and "any CA".
	o.write("spec1", []byte(strings.Join([]string{
		"serial: 5", "serial: 10-20", "id: alice",
		"serial: 100", "serial: 101", "serial: 103", "serial: 106", "serial: 110", "serial: 115",
		"serial: 1000", "serial: 50000", "serial: 2000000-3000000",
		fmt.Sprintf("serial: %d-%d", maxU64-15, maxU64),
	}, "\n")+"\n"))
	o.mustRun("-k", "-f", "1.krl", "-s", caA, "-z", "3", "spec1")
	o.write("spec1any", []byte("id: carol\nserial: 30\n"))
	o.mustRun("-k", "-u", "-f", "1.krl", "-s", "none", "spec1any")
	// 2: fingerprints and an explicit key.
	o.write("spec2", []byte("sha1: "+string(o.read(u2))+"sha256: "+string(o.read(u3))+string(o.read(u4))))
	o.mustRun("-k", "-f", "2.krl", "spec2")
	// 3: CA B, overlapping CA A's serials in number but not in CA.
	o.write("spec3", []byte("serial: 1-3\nserial: 7\nserial: 102\nid: bob\n"))
	o.mustRun("-k", "-f", "3.krl", "-s", caB, "spec3")

	var files []string
	for _, ca := range []string{"caA", "caB", "caC"} {
		for _, s := range sweepSerials {
			files = append(files, o.sign(ca, u1, "u1-"+strconv.FormatUint(s, 10), s))
		}
		for _, id := range []string{"alice", "bob", "carol", "dave"} {
			files = append(files, o.sign(ca, u1, id, 0))
		}
		for _, u := range []string{u2, u3, u4} {
			files = append(files, o.sign(ca, u, "x", 424242))
		}
	}
	files = append(files, u1, u2, u3, u4, caA, caB, caC)

	inputs := []string{"1.krl", "2.krl", "3.krl"}
	answers := make([][]bool, len(inputs))
	b := NewBuilder(9, "merged")
	for i, f := range inputs {
		var ok bool
		if answers[i], ok = o.query(f, files); !ok {
			t.Fatalf("ssh-keygen refuses its own %s", f)
		}
		k, err := Parse(o.read(f))
		if err != nil {
			t.Fatal(err)
		}
		b.Merge(k)
	}
	data, err := b.Marshal(time.Now())
	if err != nil {
		t.Fatal(err)
	}
	o.write("merged.krl", data)
	merged, ok := o.query("merged.krl", files)
	if !ok {
		t.Fatal("ssh-keygen refuses the merged list")
	}
	only := make([]int, len(inputs))
	for j, f := range files {
		want, by := false, -1
		for i := range inputs {
			if answers[i][j] {
				if !want {
					by = i
				} else {
					by = -2
				}
				want = true
			}
		}
		if by >= 0 {
			only[by]++
		}
		if merged[j] != want {
			t.Errorf("%s: revoked by the merge = %v, by the inputs = %v", f, merged[j], want)
		}
	}
	for i, n := range only {
		if n == 0 {
			t.Errorf("the sweep has nothing only %s revokes: dropping it would go unseen", inputs[i])
		}
	}
	t.Logf("merged: %v revoked only by each input", only)
	o.judge("merged.krl", files)

	// The same inputs merged again write the same bytes: a distributor
	// compares them to know whether anything changed. (CAs keep the order
	// they are first met in, as krl.c keeps them, so the order of the
	// inputs is part of what is merged.)
	for range 5 {
		b2 := NewBuilder(9, "merged")
		for _, f := range inputs {
			k, _ := Parse(o.read(f))
			b2.Merge(k)
		}
		k, _ := Parse(data)
		if again, _ := b2.Marshal(k.GeneratedDate); !bytes.Equal(again, data) {
			t.Fatal("merging the same lists again wrote other bytes")
		}
	}
}

// Bitmaps read back as runs: random ones, merged and written again, revoke
// the same serials.
func TestMergeBitmapsMatchNaive(t *testing.T) {
	rng := rand.New(rand.NewPCG(3, 4))
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
		b := NewBuilder(1, "")
		b.Merge(k)
		data, err := b.Marshal(time.Unix(1_790_000_000, 0))
		if err != nil {
			t.Fatalf("round %d: %v", round, err)
		}
		k2, err := Parse(data)
		if err != nil {
			t.Fatalf("round %d: the merged list does not parse: %v", round, err)
		}
		rc := k2.certs[""]
		for s := uint64(1); s < 1200; s++ {
			if got := rc != nil && rc.revokesSerial(s); got != want[s] {
				t.Fatalf("round %d: serial %d revoked = %v, want %v", round, s, got, want[s])
			}
		}
	}
}

// An alternating bitmap reads back as one range per two bits; Merge stops
// before that becomes an unbounded allocation.
func TestMergeIsBounded(t *testing.T) {
	b := NewBuilder(1, "")
	b.ranges = maxMergedRanges - 1
	bm := bitmapSpan{lo: 1, hi: 128, words: []uint64{0x5555555555555555, 0x5555555555555555}}
	k := &KRL{certs: map[string]*certRevocations{"": {bitmaps: []bitmapSpan{bm}, ids: map[string]struct{}{}}}}
	b.Merge(k)
	if _, err := b.Marshal(time.Unix(1_790_000_000, 0)); err == nil {
		t.Error("a merge past the bound was written")
	}
	b.Merge(nil) // nothing to add
}
