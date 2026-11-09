package auth

import (
	"errors"
	"os"
	"strings"
)

// Shadow is the router's shadow password file.
const Shadow = "/etc/shadow"

// ErrNoPassword: root has no password, as on a fresh OpenWrt. The web
// interface refuses to work without one.
var ErrNoPassword = errors.New("у root нет пароля: задайте его (команда passwd или LuCI → Система → Администрирование) и войдите снова")

// ErrLocked: root's password is locked.
var ErrLocked = errors.New("вход root по паролю заблокирован")

// rootHash returns root's password field from a shadow file.
func rootHash(path string) (string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	for _, line := range strings.Split(string(b), "\n") {
		f := strings.SplitN(line, ":", 3)
		if len(f) >= 2 && f[0] == "root" {
			return f[1], nil
		}
	}
	return "", errors.New("auth: no root in " + path)
}

// RootFrom reports whether password is root's password in the first of
// paths that holds root's hash: Entware keeps it in /opt/etc/shadow, or
// in /opt/etc/passwd itself ("x" there points to the shadow file).
func RootFrom(paths []string, password string) (bool, error) {
	err := errors.New("auth: root's password is not found")
	for _, p := range paths {
		h, e := rootHash(p)
		if e != nil {
			err = e
			continue
		}
		if h == "x" {
			continue
		}
		return check(h, password)
	}
	return false, err
}

// Root reports whether password is root's password in the shadow file.
func Root(shadow, password string) (bool, error) {
	h, err := rootHash(shadow)
	if err != nil {
		return false, err
	}
	return check(h, password)
}

// check verifies password against root's password field h.
func check(h, password string) (bool, error) {
	switch {
	case h == "":
		return false, ErrNoPassword
	case strings.HasPrefix(h, "!") || h == "*" || h == "x":
		return false, ErrLocked
	}
	return Verify(password, h)
}
