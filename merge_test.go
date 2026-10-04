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

	"golang.org/x/crypto/ssh"
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

// One CA's list, merged for that CA: everything it says about its own
// certificates and about keys keeps its effect; what it says about another
// CA -- that CA's section, that CA's key, by blob or fingerprint -- does
// not. Judged by ssh-keygen -Q on both sides: A's own list, and the merge.
func TestOracleMergeCA(t *testing.T) {
	o := newOracle(t)
	caA := o.keygen("caA", "-t", "ed25519")
	caB := o.keygen("caB", "-t", "ed25519")
	u := o.keygen("u", "-t", "ed25519") // a user key A revokes by fingerprint
	v := o.keygen("v", "-t", "ed25519") // a user key A revokes outright
	w := o.keygen("w", "-t", "ed25519") // a user key nobody revokes
	o.write("own", []byte("serial: 1\nid: alice\n"))
	o.mustRun("-k", "-f", "a.krl", "-s", caA, "own")
	o.write("b", []byte("serial: 5\n"))
	o.mustRun("-k", "-u", "-f", "a.krl", "-s", caB, "b")
	o.write("any", []byte("serial: 6\n"))
	o.mustRun("-k", "-u", "-f", "a.krl", "-s", "none", "any")
	o.write("keys", []byte("sha256: "+string(o.read(u))+"key: "+string(o.read(v))+"key: "+string(o.read(caB))+"sha1: "+string(o.read(caB))))
	o.mustRun("-k", "-u", "-f", "a.krl", "keys")
	k, err := Parse(o.read("a.krl"))
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		file      string
		wantMerge bool
		why       string
	}{
		{o.sign("caA", w, "x", 1), true, "A's serial 1"},
		{o.sign("caA", w, "alice", 0), true, "A's key ID alice"},
		{o.sign("caA", w, "x", 6), true, "any CA's serial 6, re-scoped to A"},
		{o.sign("caA", u, "x", 2), true, "A's certificate for u, revoked by fingerprint"},
		{o.sign("caA", v, "x", 3), true, "A's certificate for v, revoked outright"},
		{o.sign("caA", w, "x", 2), false, "A's serial 2 of w: nobody revokes it"},
		{o.sign("caB", w, "x", 5), false, "B's serial 5: A's list may not say"},
		{o.sign("caB", w, "x", 6), false, "B's serial 6: any-CA is A's only here"},
		{o.sign("caB", w, "x", 7), false, "B's certificate: A revoked B's key, which is dropped"},
		{caB, false, "B's key itself"},
	}
	var files []string
	for _, c := range cases {
		files = append(files, c.file)
	}
	b := NewBuilder(1, "")
	dropped := b.MergeCA(k, o.pub(caA), o.pub(caA), o.pub(caB))
	data, err := b.Marshal(time.Now())
	if err != nil {
		t.Fatal(err)
	}
	o.write("m.krl", data)
	got, ok := o.query("m.krl", files)
	if !ok {
		t.Fatal("ssh-keygen refuses the merged list")
	}
	for i, c := range cases {
		if got[i] != c.wantMerge {
			t.Errorf("%s: revoked after MergeCA = %v, want %v", c.why, got[i], c.wantMerge)
		}
	}
	// B's section, B's key by blob and by SHA1.
	if dropped != 3 {
		t.Errorf("dropped %d, want 3", dropped)
	}
	o.judge("m.krl", files)
}

// The security audit's proof, kept: a CA revoking a user key it certified,
// or its own key, the ssh-keygen way. Merged for that CA, each revokes what
// it revoked in the CA's own list. v0.3.0 dropped both.
func TestOracleMergeCAKeepsACAsOwnKeyRevocations(t *testing.T) {
	o := newOracle(t)
	caA := o.keygen("caA", "-t", "ed25519")
	u := o.keygen("u", "-t", "ed25519")
	v := o.keygen("v", "-t", "ed25519")
	o.write("spec1", []byte("key: "+string(o.read(u))))
	o.mustRun("-k", "-f", "a1.krl", "-s", caA, "spec1")
	o.write("spec2", o.read(caA)) // a bare key line: the CA's own key revoked
	o.mustRun("-k", "-f", "a2.krl", "spec2")
	certU := o.sign("caA", u, "u", 7)
	certV := o.sign("caA", v, "v", 8)
	for _, name := range []string{"a1.krl", "a2.krl"} {
		k, err := Parse(o.read(name))
		if err != nil {
			t.Fatal(err)
		}
		own, ok := o.query(name, []string{certU, certV})
		if !ok {
			t.Fatal(name)
		}
		b := NewBuilder(1, "")
		b.MergeCA(k, o.pub(caA))
		data, err := b.Marshal(time.Now())
		if err != nil {
			t.Fatal(err)
		}
		o.write("m-"+name, data)
		got, _ := o.query("m-"+name, []string{certU, certV})
		if fmt.Sprint(got) != fmt.Sprint(own) {
			t.Errorf("%s: A's own list revokes %v, merged for A: %v", name, own, got)
		}
	}
}

func TestMergeCARefusals(t *testing.T) {
	ca := newGoCA(t)
	b := NewBuilder(1, "")
	if n := b.MergeCA(nil, ca.signer.PublicKey()); n != 0 {
		t.Error(n)
	}
	k, _ := Parse(func() []byte { d, _ := NewBuilder(1, "").Marshal(time.Now()); return d }())
	if n := b.MergeCA(k, nil); n != 0 {
		t.Error(n)
	}
	if n := b.MergeCA(k, ca.signer.PublicKey(), nil); n != 0 {
		t.Errorf("a nil among the other CAs: dropped %d", n)
	}
	b.MergeCA(k, ca.cert(t, 1, "x"))
	if _, err := b.Marshal(time.Now()); err == nil {
		t.Error("a certificate as the CA: no error")
	}
}

// DropKeys: one CA's list, merged for it, may not lock out a user another
// CA certified by naming that user's public key -- sshd checks a
// certificate's own key against the list whoever signed it. Its own key,
// which reaches only its own certificates, stays revoked; so do its serials.
// The control is MergeCA on the same list, which keeps the user key.
func TestMergeCAWithDropKeysKeepsOnlyTheCAsOwnKey(t *testing.T) {
	caA, caB, u := testKey(t, 1), testKey(t, 2), testKey(t, 3).PublicKey()
	src := NewBuilder(1, "")
	src.RevokeKey(u) // a user key: reaches B's certificate for u
	src.RevokeSerial(caA.PublicKey(), 9)
	data, err := src.Marshal(time.Unix(1, 0))
	if err != nil {
		t.Fatal(err)
	}
	k, err := Parse(data)
	if err != nil {
		t.Fatal(err)
	}
	merged := func(opt MergeOptions) (*KRL, int) {
		b := NewBuilder(1, "")
		n := b.MergeCAWith(k, caA.PublicKey(), opt)
		out, err := b.Marshal(time.Unix(1, 0))
		if err != nil {
			t.Fatal(err)
		}
		m, err := Parse(out)
		if err != nil {
			t.Fatal(err)
		}
		return m, n
	}
	bCert := testCert(t, caB, u, 5, "u")
	aCert := testCert(t, caA, testKey(t, 4).PublicKey(), 9, "w")
	if m, n := merged(MergeOptions{Others: []ssh.PublicKey{caB.PublicKey()}}); !m.IsRevoked(bCert) || n != 0 {
		t.Fatalf("control: without DropKeys, the user key is kept (revoked %v, dropped %d)", m.IsRevoked(bCert), n)
	}
	m, n := merged(MergeOptions{Others: []ssh.PublicKey{caB.PublicKey()}, DropKeys: true})
	if m.IsRevoked(bCert) || m.IsRevoked(u) {
		t.Error("DropKeys: A's list still locks out B's user by naming the user's key")
	}
	if !m.IsRevoked(aCert) {
		t.Error("DropKeys: A's own serial 9 was lost")
	}
	if n != 1 {
		t.Errorf("dropped %d, want 1 (the user key)", n)
	}
	// A revoking its own key keeps doing so: it reaches only A's users.
	own := NewBuilder(1, "")
	own.RevokeKey(caA.PublicKey())
	data, _ = own.Marshal(time.Unix(1, 0))
	k, _ = Parse(data)
	if m, n := merged(MergeOptions{DropKeys: true}); !m.IsRevoked(aCert) || n != 0 {
		t.Errorf("DropKeys: A's own key revoked: A's certificate revoked %v, dropped %d", m.IsRevoked(aCert), n)
	}
}

// The same, judged by ssh-keygen, with the fingerprint forms it writes: a
// user key named by blob, SHA1 and SHA256 is left out; the CA's own key,
// by each form, is kept.
func TestOracleMergeCAWithDropKeys(t *testing.T) {
	o := newOracle(t)
	caA := o.keygen("caA", "-t", "ed25519")
	caB := o.keygen("caB", "-t", "ed25519")
	u1 := o.keygen("u1", "-t", "ed25519")
	u2 := o.keygen("u2", "-t", "ed25519")
	u3 := o.keygen("u3", "-t", "ed25519")
	w := o.keygen("w", "-t", "ed25519")
	certs := []string{o.sign("caB", u1, "x", 1), o.sign("caB", u2, "x", 2), o.sign("caB", u3, "x", 3), o.sign("caA", w, "x", 4)}
	for i, form := range []string{"key: ", "sha1: ", "sha256: "} {
		o.write("users", []byte("key: "+string(o.read(u1))+"sha1: "+string(o.read(u2))+"sha256: "+string(o.read(u3))))
		name := fmt.Sprintf("a%d.krl", i)
		o.mustRun("-k", "-f", name, "users")
		o.write("own", []byte(form+string(o.read(caA))))
		o.mustRun("-k", "-u", "-f", name, "own")
		k, err := Parse(o.read(name))
		if err != nil {
			t.Fatal(err)
		}
		b := NewBuilder(1, "")
		dropped := b.MergeCAWith(k, o.pub(caA), MergeOptions{Others: []ssh.PublicKey{o.pub(caB)}, DropKeys: true})
		data, err := b.Marshal(time.Now())
		if err != nil {
			t.Fatal(err)
		}
		o.write("m-"+name, data)
		got, ok := o.query("m-"+name, certs)
		if !ok {
			t.Fatal("ssh-keygen refuses the merged list")
		}
		if want := "[false false false true]"; fmt.Sprint(got) != want || dropped != 3 {
			t.Errorf("%sCA A: revoked %v (want %s: B's users kept, A's own key revoked), dropped %d (want 3)", form, got, want, dropped)
		}
	}
}
