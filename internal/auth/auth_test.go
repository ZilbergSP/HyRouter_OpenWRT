package auth

import (
	"crypto/sha256"
	"crypto/sha512"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func shaCrypt256(password, setting string) string {
	return shaCrypt(sha256.New, sha256.Size, "$5$", sha256Order, password, setting)
}

func shaCrypt512(password, setting string) string {
	return shaCrypt(sha512.New, sha512.Size, "$6$", sha512Order, password, setting)
}

// The vectors of the SHA crypt specification, of passlib and of
// "openssl passwd -1".
var vectors = []struct{ password, hash string }{
	{"Hello world!", "$5$saltstring$5B8vYYiY.CVt1RlTTf8KbXBH3hsxY/GNooZF2wf8vg3"},
	{"Hello world!", "$5$rounds=10000$saltstringsaltst$3xv.VbSHBb41AL9AvLeujZkZRBAwqFMz2.opqey6IcA"},
	{"Hello world!", "$6$saltstring$svn8UoSVapNtMuq1ukKS4tPQd8iKwSMHWjl/O817G3uBnIFNjnQJuesI68u4OTLiBFdcbYEdFCoEOfaS35inz1"},
	{"Hello world!", "$6$rounds=10000$saltstringsaltst$OW1/O6BYHV6BcXZu8QVeXbDWra3Oeqh0sbHbbMCVNSnCM/UrjmM0Dp8vOuZeHBy/YTBmSK6H9qs/y3RnOaw5v."},
	{"password", "$1$3azHgidD$SrJPt7B.9rekpmwJwtON31"},
	{"password", "$1$xxxxxxxx$UYCIxa628.9qXjpQCjM4a."},
}

func TestVerify(t *testing.T) {
	for _, v := range vectors {
		ok, err := Verify(v.password, v.hash)
		if err != nil || !ok {
			got := ""
			switch v.hash[:3] {
			case "$1$":
				got = md5Crypt(v.password, v.hash)
			case "$5$":
				got = shaCrypt256(v.password, v.hash)
			case "$6$":
				got = shaCrypt512(v.password, v.hash)
			}
			t.Errorf("%s: %v %v, computed %s", v.hash, ok, err, got)
		}
		if ok, _ := Verify(v.password+"x", v.hash); ok {
			t.Errorf("%s: a wrong password matched", v.hash)
		}
	}
	if _, err := Verify("x", "$y$j9T$salt$hash"); err == nil {
		t.Error("an unknown hash was checked")
	}
}

func TestRoot(t *testing.T) {
	dir := t.TempDir()
	write := func(content string) string {
		p := filepath.Join(dir, "shadow")
		if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	p := write("daemon:*:0:0:99999:7:::\nroot:" + vectors[2].hash + ":19000:0:99999:7:::\n")
	if ok, err := Root(p, "Hello world!"); !ok || err != nil {
		t.Errorf("right password: %v %v", ok, err)
	}
	if ok, err := Root(p, "hello world!"); ok || err != nil {
		t.Errorf("wrong password: %v %v", ok, err)
	}
	if _, err := Root(write("root:::0:99999:7:::\n"), ""); !errors.Is(err, ErrNoPassword) {
		t.Errorf("no password: %v", err)
	}
	if _, err := Root(write("root:!"+vectors[0].hash+":0:0:99999:7:::\n"), "Hello world!"); !errors.Is(err, ErrLocked) {
		t.Errorf("locked: %v", err)
	}
	if _, err := Root(write("daemon:*:0:0:99999:7:::\n"), "x"); err == nil {
		t.Error("a file without root")
	}
}
