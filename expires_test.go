// SPDX-License-Identifier: BSD-3-Clause

package krl

import (
	"bytes"
	"strings"
	"testing"
	"time"
)

func TestExpiresRoundTrip(t *testing.T) {
	ca := newGoCA(t)
	now := time.Unix(1_790_000_000, 0)
	b := NewBuilder(7, "c")
	b.RevokeSerial(ca.signer.PublicKey(), 3)
	b.SetExpires(now.Add(90*time.Minute + 500*time.Millisecond))
	data, err := b.Marshal(now)
	if err != nil {
		t.Fatal(err)
	}
	k, err := Parse(data)
	if err != nil {
		t.Fatal(err)
	}
	if want := now.Add(90 * time.Minute).UTC(); !k.Expires.Equal(want) {
		t.Errorf("Expires = %v, want %v", k.Expires, want)
	}
	if !k.IsRevoked(ca.cert(t, 3, "x")) || k.IsRevoked(ca.cert(t, 4, "x")) {
		t.Error("the revocations changed with an expiry")
	}

	// Without one: zero, and the bytes carry no extension.
	plain := NewBuilder(7, "c")
	data, _ = plain.Marshal(now)
	if k, _ := Parse(data); !k.Expires.IsZero() || bytes.Contains(data, []byte(ExtensionExpires)) {
		t.Errorf("a list with no expiry: %v", k.Expires)
	}
}

func TestExpiresBeforeGenerationIsRefused(t *testing.T) {
	now := time.Unix(1_790_000_000, 0)
	for _, at := range []time.Time{now, now.Add(-time.Second)} {
		b := NewBuilder(1, "")
		b.SetExpires(at)
		if _, err := b.Marshal(now); err == nil {
			t.Errorf("a list generated at %v expiring at %v was written", now, at)
		}
	}
}

// expiresSection is an extension section with this name, criticality and
// body, in wire form.
func expiresSection(name string, critical byte, body []byte) []byte {
	e := &writer{}
	e.str([]byte(name))
	e.u8(critical)
	e.str(body)
	w := &writer{}
	w.u8(sectionExtension)
	w.str(e.b)
	return w.b
}

func u64(v uint64) []byte {
	w := &writer{}
	w.u64(v)
	return w.b
}

// Our extension is held to its format: an expiry read as absent would turn
// a list meant to lapse into one that never does.
func TestMalformedExpiresIsRefused(t *testing.T) {
	head, _ := NewBuilder(1, "").Marshal(time.Unix(1_790_000_000, 0))
	good := expiresSection(ExtensionExpires, 0, u64(1_790_003_600))
	if _, err := Parse(append(bytes.Clone(head), good...)); err != nil {
		t.Fatalf("control: a well-formed expiry is refused: %v", err)
	}
	for name, tail := range map[string][]byte{
		"short":     expiresSection(ExtensionExpires, 0, []byte{1, 2, 3}),
		"long":      expiresSection(ExtensionExpires, 0, append(u64(1_790_003_600), 0)),
		"zero":      expiresSection(ExtensionExpires, 0, u64(0)),
		"too large": expiresSection(ExtensionExpires, 0, u64(1<<63)),
		"twice":     append(bytes.Clone(good), good...),
	} {
		if k, err := Parse(append(bytes.Clone(head), tail...)); err == nil {
			t.Errorf("%s: accepted, Expires = %v", name, k.Expires)
		}
	}
	// Somebody else's extension of the same shape is not ours to read.
	other := expiresSection("expires@example.org", 0, []byte{1})
	if k, err := Parse(append(bytes.Clone(head), other...)); err != nil || !k.Expires.IsZero() {
		t.Errorf("another extension: %v, %v", k.Expires, err)
	}
}

// sshd loads a list carrying the expiry and revokes what it says -- the
// extension is not critical. The control is the same list with the flag set
// to critical, which ssh-keygen must then refuse: without it, "ignored"
// could mean "never seen".
func TestOracleExpiresIsLoadedBySshKeygen(t *testing.T) {
	o := newOracle(t)
	caPub := o.keygen("ca", "-t", "ed25519")
	user := o.keygen("user", "-t", "ed25519")
	c1 := o.sign("ca", user, "u1", 1)
	c2 := o.sign("ca", user, "u2", 2)
	now := time.Now()
	b := NewBuilder(1, "")
	b.RevokeSerial(o.pub(caPub), 1)
	b.SetExpires(now.Add(time.Hour))
	data, err := b.Marshal(now)
	if err != nil {
		t.Fatal(err)
	}
	o.write("exp.krl", data)
	if n := o.judge("exp.krl", []string{c1, c2}); n != 1 {
		t.Errorf("ssh-keygen revokes %d of 2 under a list with an expiry, want 1", n)
	}
	i := bytes.LastIndex(data, []byte(ExtensionExpires)) + len(ExtensionExpires)
	if data[i] != 0 {
		t.Fatalf("the criticality byte is %d, want 0", data[i])
	}
	data[i] = 1
	o.write("crit.krl", data)
	if _, ok := o.query("crit.krl", []string{c1}); ok {
		t.Error("control: ssh-keygen loaded the list with the extension marked critical; it never read the section")
	}
	if _, err := Parse(data); err == nil || !strings.Contains(err.Error(), "critical") {
		t.Errorf("control: Parse of the critical form: %v", err)
	}
}

// What a distributor writes when a list has lapsed and must fail closed:
// the CA's own key revoked, which sshd checks for every certificate it
// signed (krl.c ssh_krl_check_key). Measured here, not assumed.
func TestOracleRevokingTheCARevokesEveryCertificate(t *testing.T) {
	o := newOracle(t)
	caPub := o.keygen("ca", "-t", "ed25519")
	other := o.keygen("other", "-t", "ed25519")
	user := o.keygen("user", "-t", "ed25519")
	c1 := o.sign("ca", user, "u1", 1)
	c2 := o.sign("ca", user, "u2", 99)
	c3 := o.sign("other", user, "u3", 1)
	b := NewBuilder(1, "")
	b.RevokeKey(o.pub(caPub))
	data, err := b.Marshal(time.Now())
	if err != nil {
		t.Fatal(err)
	}
	o.write("ca.krl", data)
	theirs, ok := o.query("ca.krl", []string{c1, c2, c3, user})
	if !ok {
		t.Fatal("ssh-keygen refuses the list")
	}
	if !theirs[0] || !theirs[1] || theirs[2] || theirs[3] {
		t.Errorf("revoked = %v, want every certificate of ca and nothing else", theirs)
	}
	o.judge("ca.krl", []string{c1, c2, c3, user, other})
}
