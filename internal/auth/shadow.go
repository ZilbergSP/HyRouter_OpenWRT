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

// Root reports whether password is root's password in the shadow file.
func Root(shadow, password string) (bool, error) {
	h, err := rootHash(shadow)
	if err != nil {
		return false, err
	}
	switch {
	case h == "":
		return false, ErrNoPassword
	case strings.HasPrefix(h, "!") || h == "*" || h == "x":
		return false, ErrLocked
	}
	return Verify(password, h)
}
