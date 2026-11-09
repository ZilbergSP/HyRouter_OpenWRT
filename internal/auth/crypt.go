// Package auth checks the router's root password for the web interface
// (docs/ARCHITECTURE.md, «Веб-интерфейс») against /etc/shadow: crypt(3)
// hashes $1$ (MD5), $5$ (SHA-256) and $6$ (SHA-512), the ones BusyBox's
// passwd writes on OpenWrt. The password never leaves hyrouterd.
package auth

import (
	"crypto/md5"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/subtle"
	"errors"
	"hash"
	"strconv"
	"strings"
)

const itoa64 = "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"

// errFormat: a hash of a kind this package does not know.
var errFormat = errors.New("auth: unsupported password hash")

func to64(b *strings.Builder, v uint32, n int) {
	for ; n > 0; n-- {
		b.WriteByte(itoa64[v&0x3f])
		v >>= 6
	}
}

// Verify reports whether password matches a crypt(3) hash.
func Verify(password, hashed string) (bool, error) {
	var got string
	switch {
	case strings.HasPrefix(hashed, "$1$"):
		got = md5Crypt(password, hashed)
	case strings.HasPrefix(hashed, "$5$"):
		got = shaCrypt(sha256.New, sha256.Size, "$5$", sha256Order, password, hashed)
	case strings.HasPrefix(hashed, "$6$"):
		got = shaCrypt(sha512.New, sha512.Size, "$6$", sha512Order, password, hashed)
	default:
		return false, errFormat
	}
	return subtle.ConstantTimeCompare([]byte(got), []byte(hashed)) == 1, nil
}

// md5Crypt is the FreeBSD MD5 crypt with the salt of setting ("$1$salt$…").
func md5Crypt(password, setting string) string {
	const magic = "$1$"
	salt := strings.TrimPrefix(setting, magic)
	if i := strings.IndexByte(salt, '$'); i >= 0 {
		salt = salt[:i]
	}
	if len(salt) > 8 {
		salt = salt[:8]
	}
	pw := []byte(password)
	d := md5.New()
	d.Write(pw)
	d.Write([]byte(magic))
	d.Write([]byte(salt))
	alt := md5.New()
	alt.Write(pw)
	alt.Write([]byte(salt))
	alt.Write(pw)
	final := alt.Sum(nil)
	for i := len(pw); i > 0; i -= 16 {
		d.Write(final[:min(i, 16)])
	}
	for i := len(pw); i > 0; i >>= 1 {
		if i&1 != 0 {
			d.Write([]byte{0})
		} else {
			d.Write(pw[:1])
		}
	}
	final = d.Sum(nil)
	for i := range 1000 {
		r := md5.New()
		if i&1 != 0 {
			r.Write(pw)
		} else {
			r.Write(final)
		}
		if i%3 != 0 {
			r.Write([]byte(salt))
		}
		if i%7 != 0 {
			r.Write(pw)
		}
		if i&1 != 0 {
			r.Write(final)
		} else {
			r.Write(pw)
		}
		final = r.Sum(nil)
	}
	var b strings.Builder
	b.WriteString(magic + salt + "$")
	f := func(i int) uint32 { return uint32(final[i]) }
	to64(&b, f(0)<<16|f(6)<<8|f(12), 4)
	to64(&b, f(1)<<16|f(7)<<8|f(13), 4)
	to64(&b, f(2)<<16|f(8)<<8|f(14), 4)
	to64(&b, f(3)<<16|f(9)<<8|f(15), 4)
	to64(&b, f(4)<<16|f(10)<<8|f(5), 4)
	to64(&b, f(11), 2)
	return b.String()
}

// The byte order of the SHA crypt encodings: triples of digest indexes
// (-1 = a zero byte), the last one written with fewer characters.
var (
	sha256Order = [][3]int{{0, 10, 20}, {21, 1, 11}, {12, 22, 2}, {3, 13, 23}, {24, 4, 14}, {15, 25, 5}, {6, 16, 26}, {27, 7, 17}, {18, 28, 8}, {9, 19, 29}, {-1, 31, 30}}
	sha512Order = [][3]int{{0, 21, 42}, {22, 43, 1}, {44, 2, 23}, {3, 24, 45}, {25, 46, 4}, {47, 5, 26}, {6, 27, 48}, {28, 49, 7}, {50, 8, 29}, {9, 30, 51}, {31, 52, 10}, {53, 11, 32}, {12, 33, 54}, {34, 55, 13}, {56, 14, 35}, {15, 36, 57}, {37, 58, 16}, {59, 17, 38}, {18, 39, 60}, {40, 61, 19}, {62, 20, 41}, {-1, -1, 63}}
)

// shaCrypt is Ulrich Drepper's SHA crypt with the salt and rounds of
// setting ("$5$rounds=N$salt$…" or "$5$salt$…").
func shaCrypt(newHash func() hash.Hash, size int, magic string, order [][3]int, password, setting string) string {
	rest := strings.TrimPrefix(setting, magic)
	rounds, explicit := 5000, false
	if r, ok := strings.CutPrefix(rest, "rounds="); ok {
		if i := strings.IndexByte(r, '$'); i > 0 {
			if n, err := strconv.Atoi(r[:i]); err == nil {
				rounds, explicit = min(max(n, 1000), 999999999), true
				rest = r[i+1:]
			}
		}
	}
	salt := rest
	if i := strings.IndexByte(salt, '$'); i >= 0 {
		salt = salt[:i]
	}
	if len(salt) > 16 {
		salt = salt[:16]
	}
	pw, s := []byte(password), []byte(salt)
	a := newHash()
	a.Write(pw)
	a.Write(s)
	alt := newHash()
	alt.Write(pw)
	alt.Write(s)
	alt.Write(pw)
	b := alt.Sum(nil)
	for i := len(pw); i > 0; i -= size {
		a.Write(b[:min(i, size)])
	}
	for i := len(pw); i > 0; i >>= 1 {
		if i&1 != 0 {
			a.Write(b)
		} else {
			a.Write(pw)
		}
	}
	c := a.Sum(nil)
	dp := newHash()
	for range len(pw) {
		dp.Write(pw)
	}
	p := repeat(dp.Sum(nil), len(pw))
	ds := newHash()
	for range 16 + int(c[0]) {
		ds.Write(s)
	}
	sp := repeat(ds.Sum(nil), len(s))
	for i := range rounds {
		r := newHash()
		if i&1 != 0 {
			r.Write(p)
		} else {
			r.Write(c)
		}
		if i%3 != 0 {
			r.Write(sp)
		}
		if i%7 != 0 {
			r.Write(p)
		}
		if i&1 != 0 {
			r.Write(c)
		} else {
			r.Write(p)
		}
		c = r.Sum(nil)
	}
	var out strings.Builder
	out.WriteString(magic)
	if explicit {
		out.WriteString("rounds=" + strconv.Itoa(rounds) + "$")
	}
	out.WriteString(salt + "$")
	byteAt := func(i int) uint32 {
		if i < 0 {
			return 0
		}
		return uint32(c[i])
	}
	for k, t := range order {
		n := 4
		if k == len(order)-1 {
			n = 4 - countZero(t)
		}
		to64(&out, byteAt(t[0])<<16|byteAt(t[1])<<8|byteAt(t[2]), n)
	}
	return out.String()
}

// countZero counts the zero bytes of a triple: the last group of a
// digest writes one character fewer for each.
func countZero(t [3]int) int {
	n := 0
	for _, i := range t {
		if i < 0 {
			n++
		}
	}
	return n
}

// repeat fills n bytes with copies of d.
func repeat(d []byte, n int) []byte {
	out := make([]byte, n)
	for i := 0; i < n; i += len(d) {
		copy(out[i:], d)
	}
	return out
}
