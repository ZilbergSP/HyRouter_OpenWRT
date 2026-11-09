//go:build linux

// Package cores installs the proxy cores hyrouterd runs: the official
// Hysteria and Xray builds pinned in build/deps.json. A core is
// downloaded the first time it is needed and checked against its SHA-256
// before it is ever started; the package carries none of them. A newer
// release of a core may replace the pinned one (updates.go).
package cores

import (
	"archive/zip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"sync"
	"time"

	"golang.org/x/sys/unix"

	"github.com/zilbergsp/hyrouter/build"
)

// Names of the cores in build/deps.json.
const (
	Hysteria = "hysteria"
	Xray     = "xray"
)

// maxSize bounds a download and a core's file.
const maxSize = 64 << 20

// needRoom is the free space Dir must have for a download; with less the
// core goes to Spare (a zip and the core taken out of it).
const needRoom = 48 << 20

// Asset is one file of a core's release for one architecture.
type Asset struct {
	URL    string `json:"url"`
	SHA256 string `json:"sha256"`
	// Member is the core's file inside a zip archive ("" = the asset is
	// the core itself).
	Member string `json:"member,omitempty"`
}

// Core is a pinned release and its assets by GOARCH.
type Core struct {
	Version string           `json:"version"`
	Assets  map[string]Asset `json:"assets"`
}

// Pinned returns the release of a core pinned in build/deps.json.
func Pinned(name string) (Core, error) {
	var deps map[string]json.RawMessage
	if err := json.Unmarshal(build.Deps, &deps); err != nil {
		return Core{}, err
	}
	raw, ok := deps[name]
	if !ok {
		return Core{}, fmt.Errorf("cores: %s is not in build/deps.json", name)
	}
	var c Core
	if err := json.Unmarshal(raw, &c); err != nil {
		return Core{}, fmt.Errorf("cores: %s: %w", name, err)
	}
	return c, nil
}

// Installer keeps the cores in Dir, or in Spare when Dir has too little
// room (HyRouter Lite on a small flash: RAM, downloaded again after a
// reboot).
type Installer struct {
	Dir   string
	Spare string
	// Client downloads (nil: a client with a 10 minute timeout).
	Client *http.Client
	// Arch is the architecture to install for ("" = runtime.GOARCH).
	Arch string
	// Version runs a core's "version" (hysteria.ExeVersion and
	// XrayVersion): a downloaded update must start and name itself.
	Version func(name, path string) (string, error)

	mu      sync.Mutex
	updates map[string]*coreState // updates.json (updates.go)
	hashOK  map[string]string     // path|mtime|size → its checked SHA-256
}

// freeSpace is the room left on the file system of dir (tests replace it).
var freeSpace = func(dir string) int64 {
	var st unix.Statfs_t
	for d := dir; ; d = filepath.Dir(d) {
		if err := unix.Statfs(d, &st); err == nil {
			return int64(st.Bavail) * int64(st.Bsize)
		}
		if d == filepath.Dir(d) {
			return 0
		}
	}
}

// Path returns the file of a core: an update installed from the core's
// releases (updates.go) while it checks out, else the pinned one,
// downloaded and checked first when it is not there yet.
func (in *Installer) Path(ctx context.Context, name string) (string, error) {
	c, err := Pinned(name)
	if err != nil {
		return "", err
	}
	in.mu.Lock()
	p := in.updated(name, c.Version)
	in.mu.Unlock()
	if p != "" {
		return p, nil
	}
	return in.install(ctx, name, c)
}

func (in *Installer) install(ctx context.Context, name string, c Core) (string, error) {
	arch := in.Arch
	if arch == "" {
		arch = runtime.GOARCH
	}
	a, ok := c.Assets[arch]
	if !ok {
		return "", fmt.Errorf("%s нет для процессора этого роутера (%s)", name, arch)
	}
	file := name + "-" + strings.ReplaceAll(c.Version, "/", "-")
	in.mu.Lock()
	defer in.mu.Unlock()
	for _, dir := range []string{in.Dir, in.Spare} {
		if dir == "" {
			continue
		}
		p := filepath.Join(dir, file)
		if st, err := os.Stat(p); err == nil && st.Mode().IsRegular() && st.Mode()&0o111 != 0 {
			return p, nil
		}
	}
	dir := in.Dir
	if in.Spare != "" && freeSpace(in.Dir) < needRoom {
		dir = in.Spare
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", err
	}
	p := filepath.Join(dir, file)
	if err := in.download(ctx, a, p); err != nil {
		return "", fmt.Errorf("не удалось скачать %s %s: %w", name, c.Version, err)
	}
	prune(dir, name+"-", append(in.keep(name), file)...)
	return p, nil
}

func (in *Installer) client() *http.Client {
	if in.Client != nil {
		return in.Client
	}
	return &http.Client{Timeout: 10 * time.Minute}
}

// download fetches a, checks its SHA-256 and puts the core at dst: the
// file itself, or the member of a zip.
func (in *Installer) download(ctx context.Context, a Asset, dst string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, a.URL, nil)
	if err != nil {
		return err
	}
	resp, err := in.client().Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	dir := filepath.Dir(dst)
	tmp, err := os.CreateTemp(dir, ".download-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	defer tmp.Close()
	h := sha256.New()
	n, err := io.Copy(io.MultiWriter(tmp, h), io.LimitReader(resp.Body, maxSize+1))
	if err != nil {
		return err
	}
	if n > maxSize {
		return errors.New("файл больше ожидаемого")
	}
	if got := hex.EncodeToString(h.Sum(nil)); !strings.EqualFold(got, a.SHA256) {
		return fmt.Errorf("SHA-256 не совпадает с закреплённой (%s)", got)
	}
	if a.Member == "" {
		if err := tmp.Chmod(0o755); err != nil {
			return err
		}
		if err := tmp.Close(); err != nil {
			return err
		}
		return os.Rename(tmp.Name(), dst)
	}
	zr, err := zip.NewReader(tmp, n)
	if err != nil {
		return err
	}
	for _, f := range zr.File {
		if f.Name != a.Member {
			continue
		}
		rc, err := f.Open()
		if err != nil {
			return err
		}
		defer rc.Close()
		out, err := os.CreateTemp(dir, ".core-*")
		if err != nil {
			return err
		}
		defer os.Remove(out.Name())
		defer out.Close()
		if _, err := io.Copy(out, io.LimitReader(rc, maxSize)); err != nil {
			return err
		}
		if err := out.Chmod(0o755); err != nil {
			return err
		}
		if err := out.Close(); err != nil {
			return err
		}
		return os.Rename(out.Name(), dst)
	}
	return fmt.Errorf("в архиве нет %s", a.Member)
}

// prune removes other versions of a core (files starting with prefix,
// other than keep) and what interrupted downloads left in dir.
func prune(dir, prefix string, keep ...string) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	for _, e := range entries {
		n := e.Name()
		if !slices.Contains(keep, n) && (strings.HasPrefix(n, prefix) || strings.HasPrefix(n, ".download-") || strings.HasPrefix(n, ".core-")) {
			os.Remove(filepath.Join(dir, n))
		}
	}
}
