// SPDX-License-Identifier: BSD-3-Clause

package krl

import (
	"bytes"
	"encoding/binary"
	"errors"
)

// reader decodes the SSH wire types of RFC 4251 section 5 with the limits of
// OpenSSH's sshbuf. The first failure is kept and every later read returns a
// zero value, so a caller checks err once after a group of reads.
type reader struct {
	b   []byte
	err error
}

func (r *reader) fail(msg string) {
	if r.err == nil {
		r.err = errors.New("krl: " + msg)
	}
}

// take consumes n bytes. It returns nil once r has failed.
func (r *reader) take(n uint64) []byte {
	if r.err != nil {
		return nil
	}
	if uint64(len(r.b)) < n {
		r.fail("truncated")
		return nil
	}
	p := r.b[:n:n]
	r.b = r.b[n:]
	return p
}

func (r *reader) u8() byte {
	if p := r.take(1); p != nil {
		return p[0]
	}
	return 0
}

func (r *reader) u32() uint32 {
	if p := r.take(4); p != nil {
		return binary.BigEndian.Uint32(p)
	}
	return 0
}

func (r *reader) u64() uint64 {
	if p := r.take(8); p != nil {
		return binary.BigEndian.Uint64(p)
	}
	return 0
}

// str reads a length-prefixed byte string.
func (r *reader) str() []byte {
	n := r.u32()
	return r.take(uint64(n))
}

// cstr reads a string the way sshbuf_get_cstring does: a NUL is allowed only
// as the very last byte, and is then not part of the value.
func (r *reader) cstr() string {
	s := r.str()
	if i := bytes.IndexByte(s, 0); i >= 0 {
		if i < len(s)-1 {
			r.fail("string with an embedded NUL")
			return ""
		}
		s = s[:i]
	}
	return string(s)
}

// maxBignum is SSHBUF_MAX_BIGNUM: the largest mpint OpenSSH accepts, in
// bytes, not counting one leading zero byte.
const maxBignum = 16384 / 8

// mpint reads a non-negative mpint the way sshbuf_get_bignum2_bytes_direct
// does and returns its magnitude, big-endian, without leading zeros.
func (r *reader) mpint() []byte {
	s := r.str()
	switch {
	case len(s) > 0 && s[0]&0x80 != 0:
		r.fail("negative bitmap")
		return nil
	case len(s) > maxBignum+1 || (len(s) == maxBignum+1 && s[0] != 0):
		r.fail("bitmap larger than OpenSSH accepts")
		return nil
	}
	for len(s) > 0 && s[0] == 0 {
		s = s[1:]
	}
	return s
}

// writer is the encoding side of reader.
type writer struct{ b []byte }

func (w *writer) u8(v byte)    { w.b = append(w.b, v) }
func (w *writer) u32(v uint32) { w.b = binary.BigEndian.AppendUint32(w.b, v) }
func (w *writer) u64(v uint64) { w.b = binary.BigEndian.AppendUint64(w.b, v) }

func (w *writer) str(s []byte) {
	w.u32(uint32(len(s)))
	w.b = append(w.b, s...)
}

// mpint writes a non-negative magnitude given big-endian, as
// sshbuf_put_bignum2_bytes does: leading zeros dropped, one zero byte
// prepended when the top bit is set.
func (w *writer) mpint(mag []byte) {
	for len(mag) > 0 && mag[0] == 0 {
		mag = mag[1:]
	}
	if len(mag) > 0 && mag[0]&0x80 != 0 {
		w.u32(uint32(len(mag) + 1))
		w.u8(0)
		w.b = append(w.b, mag...)
		return
	}
	w.str(mag)
}
