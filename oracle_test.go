// SPDX-License-Identifier: BSD-3-Clause

package krl

// The oracle: OpenSSH's ssh-keygen. Every test here writes KRLs, keys and
// certificates to a temporary directory and asks ssh-keygen what it makes of
// them. None of them passes because this package agrees with itself.

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	mrand "math/rand/v2"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

// sshKeygen returns the path of ssh-keygen. When it is missing the test
// fails if KRL_REQUIRE_SSHKEYGEN=1, as it is on the CI lanes that must be
// judged, and is skipped otherwise.
func sshKeygen(t *testing.T) string {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("the ssh-keygen oracle runs on the linux and darwin lanes; " +
			"Windows ships Win32-OpenSSH, a port this suite is not calibrated for")
	}
	p, err := exec.LookPath("ssh-keygen")
	if err != nil {
		if os.Getenv("KRL_REQUIRE_SSHKEYGEN") == "1" {
			t.Fatalf("ssh-keygen is required on this lane (KRL_REQUIRE_SSHKEYGEN=1) and is missing: %v", err)
		}
		t.Skipf("ssh-keygen not found (%v); set KRL_REQUIRE_SSHKEYGEN=1 to make this a failure", err)
	}
	return p
}

var loggedVersion bool

// oracle wraps ssh-keygen in a working directory.
type oracle struct {
	t   *testing.T
	bin string
	dir string
	n   int
}

func newOracle(t *testing.T) *oracle {
	o := &oracle{t: t, bin: sshKeygen(t), dir: t.TempDir()}
	if !loggedVersion {
		loggedVersion = true
		// ssh -V names the OpenSSH release; ssh-keygen has no version flag.
		if out, err := exec.Command("ssh", "-V").CombinedOutput(); err == nil {
			t.Logf("oracle: %s (%s)", strings.TrimSpace(string(out)), o.bin)
		}
	}
	return o
}

// run runs ssh-keygen and returns its combined output and exit status.
func (o *oracle) run(args ...string) (string, int) {
	o.t.Helper()
	cmd := exec.Command(o.bin, args...)
	cmd.Dir = o.dir
	out, err := cmd.CombinedOutput()
	var ee *exec.ExitError
	switch {
	case err == nil:
		return string(out), 0
	case errors.As(err, &ee):
		return string(out), ee.ExitCode()
	}
	o.t.Fatalf("ssh-keygen %v: %v", args, err)
	return "", -1
}

func (o *oracle) mustRun(args ...string) string {
	o.t.Helper()
	out, code := o.run(args...)
	if code != 0 {
		o.t.Fatalf("ssh-keygen %v: exit %d\n%s", args, code, out)
	}
	return out
}

func (o *oracle) path(name string) string { return filepath.Join(o.dir, name) }

func (o *oracle) write(name string, data []byte) string {
	o.t.Helper()
	if err := os.WriteFile(o.path(name), data, 0o600); err != nil {
		o.t.Fatal(err)
	}
	return name
}

func (o *oracle) read(name string) []byte {
	o.t.Helper()
	b, err := os.ReadFile(o.path(name))
	if err != nil {
		o.t.Fatal(err)
	}
	return b
}

// pub parses an authorized_keys-format file.
func (o *oracle) pub(name string) ssh.PublicKey {
	o.t.Helper()
	k, _, _, _, err := ssh.ParseAuthorizedKey(o.read(name))
	if err != nil {
		o.t.Fatalf("%s: %v", name, err)
	}
	return k
}

// keygen makes a key pair with ssh-keygen and returns the public file name.
func (o *oracle) keygen(name string, typ ...string) string {
	o.t.Helper()
	o.mustRun(append([]string{"-q", "-N", "", "-C", name, "-f", name}, typ...)...)
	return name + ".pub"
}

// sign makes a certificate for userPub with ssh-keygen -s and returns its
// file name.
func (o *oracle) sign(ca, userPub, id string, serial uint64) string {
	o.t.Helper()
	o.n++
	base := fmt.Sprintf("c%d", o.n)
	o.write(base+".pub", o.read(userPub))
	o.mustRun("-q", "-s", ca, "-I", id, "-z", strconv.FormatUint(serial, 10), base+".pub")
	return base + "-cert.pub"
}

// query asks ssh-keygen -Q whether each file is revoked by the KRL. ok is
// false when ssh-keygen refuses the KRL itself.
func (o *oracle) query(krlFile string, files []string) (revoked []bool, ok bool) {
	o.t.Helper()
	out, code := o.run(append([]string{"-Q", "-f", krlFile}, files...)...)
	if code == 255 {
		return nil, false
	}
	lines := strings.Split(strings.TrimRight(out, "\n"), "\n")
	if len(lines) != len(files) {
		o.t.Fatalf("ssh-keygen -Q: %d lines for %d files (exit %d):\n%s", len(lines), len(files), code, out)
	}
	any := false
	for i, l := range lines {
		switch {
		case !strings.HasPrefix(l, files[i]):
			o.t.Fatalf("ssh-keygen -Q line %d is not about %s: %q", i, files[i], l)
		case strings.HasSuffix(l, ": REVOKED"):
			revoked = append(revoked, true)
			any = true
		case strings.HasSuffix(l, ": ok"):
			revoked = append(revoked, false)
		default:
			o.t.Fatalf("ssh-keygen -Q: unexpected line %q", l)
		}
	}
	if want := map[bool]int{true: 1, false: 0}[any]; code != want {
		o.t.Fatalf("ssh-keygen -Q exit %d, want %d for these lines", code, want)
	}
	return revoked, true
}

// dump returns ssh-keygen's own listing of a KRL without its date line.
func (o *oracle) dump(krlFile string) string {
	o.t.Helper()
	out := o.mustRun("-Q", "-l", "-f", krlFile)
	var keep []string
	for _, l := range strings.Split(out, "\n") {
		if !strings.HasPrefix(l, "# Generated at ") {
			keep = append(keep, l)
		}
	}
	return strings.Join(keep, "\n")
}

// judge compares IsRevoked with ssh-keygen -Q for every file and returns
// how many were revoked.
func (o *oracle) judge(krlFile string, files []string) int {
	o.t.Helper()
	k, err := Parse(o.read(krlFile))
	if err != nil {
		o.t.Fatalf("Parse(%s): %v", krlFile, err)
	}
	theirs, ok := o.query(krlFile, files)
	if !ok {
		o.t.Fatalf("ssh-keygen refuses %s", krlFile)
	}
	n := 0
	for i, f := range files {
		ours := k.IsRevoked(o.pub(f))
		if ours != theirs[i] {
			o.t.Errorf("%s: %s: IsRevoked = %v, ssh-keygen -Q says revoked = %v", krlFile, f, ours, theirs[i])
		}
		if theirs[i] {
			n++
		}
	}
	return n
}

const maxU64 = ^uint64(0)

// The serials every CA certifies: both sides of every edge the
// specifications below draw, and 0.
var sweepSerials = []uint64{
	0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 19, 20, 21, 29, 30, 31,
	99, 100, 101, 102, 103, 104, 105, 106, 107, 109, 110, 111, 114, 115, 116,
	999, 1000, 1001, 49999, 50000, 50001, 999999, 1000000, 1000001,
	1999999, 2000000, 2500000, 3000000, 3000001,
	maxU64 - 16, maxU64 - 15, maxU64 - 1, maxU64,
}

// TestOracleSshKeygenKRL builds a KRL with ssh-keygen -k covering every kind
// of revocation it can write, and checks that Parse reads it and IsRevoked
// agrees with ssh-keygen -Q on a sweep of certificates and keys. It then
// makes the same revocations with Builder, which must produce the same bytes
// (the date aside), and checks the answers again.
func TestOracleSshKeygenKRL(t *testing.T) {
	o := newOracle(t)
	caA := o.keygen("caA", "-t", "ed25519")
	caB := o.keygen("caB", "-t", "ecdsa", "-b", "256")
	caC := o.keygen("caC", "-t", "rsa", "-b", "2048")
	caD := o.keygen("caD", "-t", "ed25519")
	u1 := o.keygen("u1", "-t", "ed25519")
	u2 := o.keygen("u2", "-t", "ed25519")
	u3 := o.keygen("u3", "-t", "ecdsa", "-b", "384")

	o.write("specA", []byte(strings.Join([]string{
		"serial: 5",
		"serial: 10-20",
		"id: alice",
		"# a bitmap:",
		"serial: 100", "serial: 101", "serial: 103", "serial: 106", "serial: 110", "serial: 115",
		"# a list:",
		"serial: 1000", "serial: 50000", "serial: 1000000",
		"serial: 2000000-3000000",
		fmt.Sprintf("serial: %d-%d", maxU64-15, maxU64),
	}, "\n")+"\n"))
	o.write("specB", []byte("serial: 1-3\nserial: 7\nid: bob\n"))
	o.write("specAny", []byte("id: carol\nserial: 30\n"))
	o.write("specKeys", []byte(string(o.read(u2))+"key: "+string(o.read(caC))))

	o.mustRun("-k", "-f", "theirs.krl", "-s", caA, "-z", "7", "specA")
	o.mustRun("-k", "-u", "-f", "theirs.krl", "-s", caB, "specB")
	o.mustRun("-k", "-u", "-f", "theirs.krl", "-s", "none", "specAny")
	o.mustRun("-k", "-u", "-f", "theirs.krl", "specKeys")

	var files []string
	for _, ca := range []string{"caA", "caB", "caC", "caD"} {
		for _, s := range sweepSerials {
			files = append(files, o.sign(ca, u1, "u1-"+strconv.FormatUint(s, 10), s))
		}
		for _, id := range []string{"alice", "bob", "carol", "dave"} {
			files = append(files, o.sign(ca, u1, id, 0), o.sign(ca, u1, id, 12345))
		}
		files = append(files, o.sign(ca, u2, "u2", 424242), o.sign(ca, u3, "u3", 424242))
	}
	files = append(files, u1, u2, u3, caA, caB, caC, caD)

	revoked := o.judge("theirs.krl", files)
	t.Logf("ssh-keygen -k KRL: %d of %d certificates and keys revoked, IsRevoked agrees", revoked, len(files))
	if revoked < 50 || len(files)-revoked < 50 {
		t.Fatalf("the sweep does not exercise both answers: %d revoked of %d", revoked, len(files))
	}

	// The same revocations, through Builder.
	theirs := o.read("theirs.krl")
	k, err := Parse(theirs)
	if err != nil {
		t.Fatal(err)
	}
	if k.Version != 7 || k.Signed || k.Comment != "" {
		t.Fatalf("header: %+v", k)
	}
	b := NewBuilder(7, "")
	a, bk := o.pub(caA), o.pub(caB)
	b.RevokeSerial(a, 5)
	b.RevokeSerialRange(a, 10, 20)
	b.RevokeKeyID(a, "alice")
	for _, s := range []uint64{100, 101, 103, 106, 110, 115, 1000, 50000, 1000000} {
		b.RevokeSerial(a, s)
	}
	b.RevokeSerialRange(a, 2000000, 3000000)
	b.RevokeSerialRange(a, maxU64-15, maxU64)
	b.RevokeSerialRange(bk, 1, 3)
	b.RevokeSerial(bk, 7)
	b.RevokeKeyID(bk, "bob")
	b.RevokeKeyID(nil, "carol")
	b.RevokeSerial(nil, 30)
	b.RevokeKey(o.pub(u2))
	b.RevokeKey(o.pub(caC))
	ours, err := b.Marshal(k.GeneratedDate)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(ours, theirs) {
		t.Errorf("Builder output differs from ssh-keygen's for the same revocations:\nours   %x\ntheirs %x", ours, theirs)
	}
	o.write("ours.krl", ours)
	if d1, d2 := o.dump("ours.krl"), o.dump("theirs.krl"); d1 != d2 {
		t.Errorf("ssh-keygen -Q -l lists different revocations:\nours:\n%s\ntheirs:\n%s", d1, d2)
	}
	o.judge("ours.krl", files)
}

// TestOracleFingerprints revokes keys by SHA-1 and SHA-256 fingerprint, the
// three ways ssh-keygen -k spells it, and checks keys and certificates of
// those keys.
func TestOracleFingerprints(t *testing.T) {
	o := newOracle(t)
	ca := o.keygen("ca", "-t", "ed25519")
	var keys []string
	for i, typ := range [][]string{
		{"-t", "ed25519"}, {"-t", "ecdsa", "-b", "256"}, {"-t", "ecdsa", "-b", "521"},
		{"-t", "rsa", "-b", "2048"}, {"-t", "ed25519"}, {"-t", "ed25519"},
	} {
		keys = append(keys, o.keygen(fmt.Sprintf("k%d", i), typ...))
	}
	fp := strings.Fields(o.mustRun("-l", "-E", "sha256", "-f", keys[2]))[1]
	o.write("spec", []byte(
		"sha1: "+string(o.read(keys[0]))+
			"sha256: "+string(o.read(keys[1]))+
			"hash: "+fp+"\n"+
			"sha256: "+string(o.read(keys[3]))+
			"sha1: "+string(o.read(ca))))
	o.mustRun("-k", "-f", "fp.krl", "spec")

	files := slices.Clone(keys)
	files = append(files, ca)
	for i, k := range keys {
		files = append(files, o.sign("ca", k, fmt.Sprintf("k%d", i), uint64(i+1)))
	}
	other := o.keygen("other", "-t", "ed25519")
	for i, k := range keys {
		files = append(files, o.sign("other", k, fmt.Sprintf("o%d", i), uint64(i+1)))
	}
	files = append(files, other)
	n := o.judge("fp.krl", files)
	t.Logf("fingerprint KRL: %d of %d revoked, IsRevoked agrees", n, len(files))

	k, err := Parse(o.read("fp.krl"))
	if err != nil {
		t.Fatal(err)
	}
	if len(k.sha1s) != 2 || len(k.sha256s) != 3 {
		t.Fatalf("sections: %d SHA-1, %d SHA-256; want 2 and 3", len(k.sha1s), len(k.sha256s))
	}
}

// goCA signs certificates in Go, so that a sweep can hold thousands of them.
type goCA struct {
	signer ssh.Signer
	user   ssh.PublicKey
}

func newGoCA(t *testing.T) goCA {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	s, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	upub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	u, err := ssh.NewPublicKey(upub)
	if err != nil {
		t.Fatal(err)
	}
	return goCA{signer: s, user: u}
}

func (c goCA) cert(t *testing.T, serial uint64, id string) *ssh.Certificate {
	cert := &ssh.Certificate{
		Key: c.user, Serial: serial, CertType: ssh.UserCert, KeyId: id,
		ValidPrincipals: []string{"u"}, ValidBefore: ssh.CertTimeInfinity,
	}
	if err := cert.SignCert(rand.Reader, c.signer); err != nil {
		t.Fatal(err)
	}
	return cert
}

// randomSerials draws clusters of serials, dense and sparse, with the odd
// range, so that every encoding and every transition between them occurs.
func randomSerials(r *mrand.Rand) (singles []uint64, ranges [][2]uint64) {
	base := uint64(1)
	for range 1 + r.IntN(12) {
		base += 1 + r.Uint64N(5000)
		switch r.IntN(4) {
		case 0: // dense
			for range 1 + r.IntN(60) {
				base += 1 + r.Uint64N(3)
				singles = append(singles, base)
			}
		case 1: // sparse
			for range 1 + r.IntN(30) {
				base += 1 + r.Uint64N(200)
				singles = append(singles, base)
			}
		case 2: // a range
			n := 1 + r.Uint64N(400)
			ranges = append(ranges, [2]uint64{base, base + n})
			base += n
		default: // lonely
			base += r.Uint64N(1 << 40)
			singles = append(singles, base)
		}
	}
	return singles, ranges
}

// TestOracleRandomSerials writes random serial sets both with ssh-keygen -k
// and with Builder. The two KRLs must list the same revocations under
// ssh-keygen -Q -l and be byte-identical (date aside); Builder's must be
// accepted by ssh-keygen -Q and give, with IsRevoked on both, the answer
// ssh-keygen gives for certificates on each side of every edge.
func TestOracleRandomSerials(t *testing.T) {
	o := newOracle(t)
	ca := newGoCA(t)
	o.write("ca.pub", ssh.MarshalAuthorizedKey(ca.signer.PublicKey()))
	r := mrand.New(mrand.NewPCG(1, 2))
	trials, checked, identical := 40, 0, 0
	if testing.Short() {
		trials = 8
	}
	for trial := range trials {
		singles, ranges := randomSerials(r)
		var spec strings.Builder
		b := NewBuilder(uint64(trial), "")
		probe := map[uint64]bool{}
		edge := func(lo, hi uint64) {
			for _, s := range []uint64{lo - 1, lo, lo + 1, hi - 1, hi, hi + 1} {
				probe[s] = true
			}
		}
		for _, s := range singles {
			fmt.Fprintf(&spec, "serial: %d\n", s)
			b.RevokeSerial(ca.signer.PublicKey(), s)
			edge(s, s)
		}
		for _, rg := range ranges {
			fmt.Fprintf(&spec, "serial: %d-%d\n", rg[0], rg[1])
			b.RevokeSerialRange(ca.signer.PublicKey(), rg[0], rg[1])
			edge(rg[0], rg[1])
		}
		for range 20 {
			probe[1+r.Uint64N(1<<20)] = true
		}
		name := fmt.Sprintf("t%d", trial)
		o.write(name+".spec", []byte(spec.String()))
		o.mustRun("-k", "-f", name+"-theirs.krl", "-s", "ca.pub", "-z", strconv.Itoa(trial), name+".spec")
		theirs := o.read(name + "-theirs.krl")
		k, err := Parse(theirs)
		if err != nil {
			t.Fatalf("trial %d: Parse(ssh-keygen output): %v", trial, err)
		}
		ours, err := b.Marshal(k.GeneratedDate)
		if err != nil {
			t.Fatal(err)
		}
		o.write(name+"-ours.krl", ours)
		if bytes.Equal(ours, theirs) {
			identical++
		} else {
			t.Errorf("trial %d: Builder bytes differ from ssh-keygen's", trial)
		}
		if d1, d2 := o.dump(name+"-ours.krl"), o.dump(name+"-theirs.krl"); d1 != d2 {
			t.Errorf("trial %d: listings differ:\nours:\n%s\ntheirs:\n%s", trial, d1, d2)
		}
		var files []string
		for s := range probe {
			f := fmt.Sprintf("%s-%d-cert.pub", name, s)
			o.write(f, ssh.MarshalAuthorizedKey(ca.cert(t, s, "p")))
			files = append(files, f)
		}
		slices.Sort(files)
		o.judge(name+"-theirs.krl", files)
		o.judge(name+"-ours.krl", files)
		checked += len(files)
	}
	t.Logf("%d random KRLs, %d byte-identical to ssh-keygen's, %d certificates judged against each", trials, identical, checked)
}

// TestOracleBitmapOverflow records an ssh-keygen defect and that Builder
// avoids it: for many sparse serials close together ssh-keygen writes one
// bitmap wider than its own reader accepts, and then refuses the KRL it
// wrote. Parse refuses it too. Builder's KRL for the same serials is read by
// ssh-keygen and lists exactly those serials.
func TestOracleBitmapOverflow(t *testing.T) {
	o := newOracle(t)
	ca := newGoCA(t)
	o.write("ca.pub", ssh.MarshalAuthorizedKey(ca.signer.PublicKey()))
	var spec strings.Builder
	var want []string
	b := NewBuilder(1, "odd serials")
	for s := uint64(1); s <= 40001; s += 2 {
		fmt.Fprintf(&spec, "serial: %d\n", s)
		want = append(want, fmt.Sprintf("serial: %d", s))
		b.RevokeSerial(ca.signer.PublicKey(), s)
	}
	o.write("spec", []byte(spec.String()))
	o.mustRun("-k", "-f", "theirs.krl", "-s", "ca.pub", "spec")
	out, code := o.run("-Q", "-l", "-f", "theirs.krl")
	if code == 0 {
		t.Logf("this ssh-keygen reads back its wide bitmap; the defect is fixed upstream")
	} else {
		t.Logf("ssh-keygen refuses its own KRL (exit %d): %s", code, strings.TrimSpace(out))
		if _, err := Parse(o.read("theirs.krl")); err == nil {
			t.Errorf("Parse accepts a KRL ssh-keygen refuses")
		}
	}
	ours, err := b.Marshal(time.Unix(1_700_000_000, 0))
	if err != nil {
		t.Fatal(err)
	}
	o.write("ours.krl", ours)
	var got []string
	for _, l := range strings.Split(o.dump("ours.krl"), "\n") {
		if strings.HasPrefix(l, "serial: ") {
			got = append(got, l)
		}
	}
	if !slices.Equal(got, want) {
		t.Fatalf("ssh-keygen lists %d serials from Builder's KRL, want %d", len(got), len(want))
	}
	files := []string{}
	for _, s := range []uint64{1, 2, 3, 16383, 16384, 16385, 20001, 40000, 40001, 40002, 40003} {
		f := fmt.Sprintf("s%d-cert.pub", s)
		o.write(f, ssh.MarshalAuthorizedKey(ca.cert(t, s, "x")))
		files = append(files, f)
	}
	o.judge("ours.krl", files)
}

// TestOracleSigned hand-builds a KRL with a signature section in the format
// PROTOCOL.krl describes (OpenSSH never offered a way to write one) and
// records what ssh-keygen makes of it. Parse must read it, skip the
// signature and still revoke.
func TestOracleSigned(t *testing.T) {
	o := newOracle(t)
	ca := newGoCA(t)
	b := NewBuilder(3, "signed")
	b.RevokeSerial(ca.signer.PublicKey(), 9)
	body, err := b.Marshal(time.Unix(1_600_000_000, 0))
	if err != nil {
		t.Fatal(err)
	}
	signed := signKRL(t, body, ca.signer)
	o.write("signed.krl", signed)
	f := o.write("s9-cert.pub", ssh.MarshalAuthorizedKey(ca.cert(t, 9, "x")))
	g := o.write("s8-cert.pub", ssh.MarshalAuthorizedKey(ca.cert(t, 8, "x")))

	k, err := Parse(signed)
	if err != nil {
		t.Fatalf("Parse(signed KRL): %v", err)
	}
	if !k.Signed || !k.IsRevoked(o.pub(f)) || k.IsRevoked(o.pub(g)) {
		t.Fatalf("signed KRL: Signed=%v, serial 9 revoked=%v, serial 8 revoked=%v", k.Signed, k.IsRevoked(o.pub(f)), k.IsRevoked(o.pub(g)))
	}
	if theirs, ok := o.query("signed.krl", []string{f, g}); ok {
		t.Logf("ssh-keygen reads a signed KRL and skips the signature: %v", theirs)
		if !theirs[0] || theirs[1] {
			t.Errorf("ssh-keygen answers %v for serials 9 and 8", theirs)
		}
	} else {
		t.Logf("ssh-keygen refuses a signed KRL")
	}
}

// signKRL appends a signature section: the signature covers the KRL from
// its magic through the section's signature_key string.
func signKRL(t testing.TB, body []byte, s ssh.Signer) []byte {
	w := &writer{b: slices.Clone(body)}
	w.u8(sectionSignature)
	w.str(s.PublicKey().Marshal())
	sig, err := s.Sign(rand.Reader, w.b)
	if err != nil {
		t.Fatal(err)
	}
	w.str(ssh.Marshal(sig))
	return w.b
}

// TestOracleMutations is the strictness judge: it truncates and corrupts a
// KRL holding every section Parse reads, byte by byte, and requires Parse to
// refuse exactly the variants ssh-keygen refuses and, for the others, to
// answer as ssh-keygen does for a set of certificates and keys.
func TestOracleMutations(t *testing.T) {
	o := newOracle(t)
	caA := o.keygen("caA", "-t", "ed25519")
	caB := o.keygen("caB", "-t", "ecdsa", "-b", "256")
	u1 := o.keygen("u1", "-t", "ed25519")
	u2 := o.keygen("u2", "-t", "ed25519")
	o.write("specA", []byte("serial: 5\nserial: 10-20\nserial: 100\nserial: 102\nserial: 107\nserial: 900\nid: alice\n"))
	o.write("specB", []byte("serial: 1\nid: bob\n"))
	o.write("specK", []byte(string(o.read(u2))+"sha256: "+string(o.read(u2))+"sha1: "+string(o.read(u2))))
	o.mustRun("-k", "-f", "base.krl", "-s", caA, "-z", "1", "specA")
	o.mustRun("-k", "-u", "-f", "base.krl", "-s", caB, "specB")
	o.mustRun("-k", "-u", "-f", "base.krl", "specK")
	base := o.read("base.krl")
	// A non-critical extension section, which both must ignore.
	ext := &writer{}
	ext.str([]byte("x@example.org"))
	ext.u8(0)
	ext.str([]byte("v"))
	base = append(base, sectionExtension)
	base = (&writer{b: base}).strAppend(ext.b)

	var files []string
	for _, ca := range []string{"caA", "caB"} {
		for _, s := range []uint64{0, 1, 5, 6, 10, 20, 21, 100, 101, 102, 107, 900} {
			files = append(files, o.sign(ca, u1, "u", s))
		}
		files = append(files, o.sign(ca, u1, "alice", 0), o.sign(ca, u1, "bob", 0), o.sign(ca, u2, "v", 3))
	}
	files = append(files, u1, u2, caA, caB)
	keys := make([]ssh.PublicKey, len(files))
	for i, f := range files {
		keys[i] = o.pub(f)
	}

	var variants [][]byte
	for n := range len(base) {
		variants = append(variants, base[:n])
	}
	for i := range base {
		for _, f := range []func(byte) byte{
			func(c byte) byte { return c + 1 },
			func(c byte) byte { return c - 1 },
			func(c byte) byte { return c ^ 0x80 },
		} {
			v := slices.Clone(base)
			v[i] = f(v[i])
			variants = append(variants, v)
		}
	}
	variants = append(variants, append(slices.Clone(base), 0))
	if testing.Short() {
		variants = variants[:len(base)]
	}
	refused, accepted := 0, 0
	for i, v := range variants {
		o.write("m.krl", v)
		theirs, ok := o.query("m.krl", files)
		k, err := Parse(v)
		if (err == nil) != ok {
			t.Errorf("variant %d: Parse error %v, ssh-keygen accepts = %v\n%x", i, err, ok, v)
			continue
		}
		if !ok {
			refused++
			continue
		}
		accepted++
		for j, key := range keys {
			if got := k.IsRevoked(key); got != theirs[j] {
				t.Errorf("variant %d: %s: IsRevoked = %v, ssh-keygen = %v", i, files[j], got, theirs[j])
			}
		}
	}
	t.Logf("%d variants of a %d-byte KRL: %d refused and %d accepted by both, answers agree on %d keys each",
		len(variants), len(base), refused, accepted, len(files))
}

// strAppend appends s as a string and returns the buffer.
func (w *writer) strAppend(s []byte) []byte {
	w.str(s)
	return w.b
}
