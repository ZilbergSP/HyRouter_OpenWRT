//go:build linux

package cores

// Updates of the cores, as HyRoute's internal/core does them: a core newer
// than the pinned one, from the core's own stable releases, checked
// against the release's checksums and by starting it, kept with the core
// it replaced for a rollback. A HyRouter update that pins a core as new
// or newer retires the downloaded ones. updates.json in Dir records them.

import (
	"archive/zip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"time"

	"github.com/zilbergsp/hyrouter/internal/release"
)

// Kind is where a core's releases are and how one is checked.
type Kind struct {
	Title string // "Hysteria", "Xray"
	Repo  string
	// Accept picks the core's releases (stable ones only are offered).
	Accept func(tag string) bool
	// Sums are the release's official checksums of an asset; none means
	// no update.
	Sums func(ctx context.Context, c *release.Client, r release.Release, a release.Asset) []string
}

// Kinds are the cores that update.
var Kinds = map[string]Kind{
	// Hysteria 2 only: HyRouter's configs are Hysteria 2's.
	Hysteria: {Title: "Hysteria", Repo: "apernet/hysteria",
		Accept: func(tag string) bool {
			v, err := release.Parse(tag)
			return err == nil && strings.HasPrefix(tag, "app/") && v.Major == 2
		},
		// hashes.txt of the release, and GitHub's own digest.
		Sums: func(ctx context.Context, c *release.Client, r release.Release, a release.Asset) []string {
			var out []string
			if h, ok := r.Asset("hashes.txt"); ok {
				if list, err := c.Fetch(ctx, h.URL); err == nil {
					if s := release.SumFor(list, a.Name); s != "" {
						out = append(out, s)
					}
				}
			}
			if d := a.SHA256(); d != "" {
				out = append(out, d)
			}
			return out
		},
	},
	// Xray's versions are dates with no major version that would mark a
	// change of its configs: a new one has to connect, or it is rolled
	// back (ctl).
	Xray: {Title: "Xray", Repo: "XTLS/Xray-core",
		Accept: func(tag string) bool {
			_, err := release.Parse(tag)
			return err == nil && strings.HasPrefix(tag, "v")
		},
		// The zip's .dgst file ("SHA2-256= <hex>"), and GitHub's digest.
		Sums: func(ctx context.Context, c *release.Client, r release.Release, a release.Asset) []string {
			var out []string
			if h, ok := r.Asset(a.Name + ".dgst"); ok {
				if b, err := c.Fetch(ctx, h.URL); err == nil {
					if m := dgstSHA256.FindSubmatch(b); m != nil {
						out = append(out, strings.ToLower(string(m[1])))
					}
				}
			}
			if d := a.SHA256(); d != "" {
				out = append(out, d)
			}
			return out
		},
	},
}

var dgstSHA256 = regexp.MustCompile(`(?m)^SHA2-256=\s*([0-9a-fA-F]{64})\s*$`)

type entry struct {
	Version string `json:"version"` // the release's tag: app/v2.12.4, v26.11.2
	SHA256  string `json:"sha256"`  // of the core itself
	// RAM: the core lives in Staging, as the flash had no room for it.
	// After a reboot it is downloaded again from URL (Member of a zip),
	// checked against Sums, and its SHA256 again.
	RAM    bool     `json:"ram,omitempty"`
	URL    string   `json:"url,omitempty"`
	Member string   `json:"member,omitempty"`
	Sums   []string `json:"sums,omitempty"`
}

// coreState: the update in use, and what a rollback returns to (nil: the
// pinned core).
type coreState struct {
	Current  *entry `json:"current,omitempty"`
	Previous *entry `json:"previous,omitempty"`
}

// fileName is a core's file in Dir, pinned or downloaded.
func fileName(name, version string) string {
	return name + "-" + strings.ReplaceAll(version, "/", "-")
}

// stage is Staging, or Dir without one.
func (in *Installer) stage() string {
	if in.Staging != "" {
		return in.Staging
	}
	return in.Dir
}

// entryPath is where an update's core lives.
func (in *Installer) entryPath(name string, e *entry) string {
	dir := in.Dir
	if e.RAM {
		dir = in.stage()
	}
	return filepath.Join(dir, fileName(name, e.Version))
}

// usable: an update's core checks out, or is one kept in RAM that a
// reboot took and Path downloads again (in.mu held).
func (in *Installer) usable(name string, e *entry) bool {
	p := in.entryPath(name, e)
	if in.verified(p, e.SHA256) {
		return true
	}
	_, err := os.Stat(p)
	return e.RAM && e.URL != "" && errors.Is(err, fs.ErrNotExist)
}

func (in *Installer) arch() string {
	if in.Arch != "" {
		return in.Arch
	}
	return runtime.GOARCH
}

// loadUpdates reads updates.json (in.mu held).
func (in *Installer) loadUpdates() {
	if in.updates != nil {
		return
	}
	in.updates = map[string]*coreState{}
	if b, err := os.ReadFile(filepath.Join(in.Dir, "updates.json")); err == nil {
		json.Unmarshal(b, &in.updates)
	}
}

// saveUpdates writes updates.json (in.mu held).
func (in *Installer) saveUpdates() error {
	b, _ := json.MarshalIndent(in.updates, "", "  ")
	tmp := filepath.Join(in.Dir, "updates.json.tmp")
	if err := os.WriteFile(tmp, b, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, filepath.Join(in.Dir, "updates.json"))
}

// verified: the file still has the hash recorded for it (in.mu held).
func (in *Installer) verified(p, want string) bool {
	fi, err := os.Stat(p)
	if err != nil || !fi.Mode().IsRegular() {
		return false
	}
	key := fmt.Sprintf("%s|%d|%d", p, fi.ModTime().UnixNano(), fi.Size())
	if in.hashOK[key] == want {
		return true
	}
	f, err := os.Open(p)
	if err != nil {
		return false
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil || !strings.EqualFold(hex.EncodeToString(h.Sum(nil)), want) {
		return false
	}
	if in.hashOK == nil {
		in.hashOK = map[string]string{}
	}
	in.hashOK[key] = want
	return true
}

// updated is the downloaded core in use instead of the pinned one ("" =
// none); again is one kept in RAM that a reboot took, to download again.
// One that a HyRouter update caught up with retires (in.mu held).
func (in *Installer) updated(name, pinned string) (p string, again *entry) {
	in.loadUpdates()
	st := in.updates[name]
	if st == nil || st.Current == nil {
		return "", nil
	}
	if release.Compare(pinned, st.Current.Version) >= 0 {
		delete(in.updates, name)
		in.saveUpdates()
		return "", nil
	}
	e := st.Current
	if p := in.entryPath(name, e); in.verified(p, e.SHA256) {
		return p, nil
	}
	if in.usable(name, e) {
		return "", e
	}
	return "", nil
}

// refetch downloads again an update kept in RAM that a reboot took and
// checks it as it was installed.
func (in *Installer) refetch(ctx context.Context, name string, e entry) (string, error) {
	in.mu.Lock()
	defer in.mu.Unlock()
	dst := in.entryPath(name, &e)
	if in.verified(dst, e.SHA256) {
		return dst, nil // another start fetched it meanwhile
	}
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return "", err
	}
	tmp := filepath.Join(filepath.Dir(dst), ".update-again-"+fileName(name, e.Version))
	defer os.Remove(tmp)
	c := &release.Client{HTTP: in.client(), UserAgent: "HyRouter"}
	sum, err := c.Download(ctx, e.URL, tmp, maxSize, nil, e.Sums...)
	if err == nil && e.Member != "" {
		sum, err = unzipMember(tmp, e.Member, dst)
	} else if err == nil {
		if err = os.Chmod(tmp, 0o755); err == nil {
			err = os.Rename(tmp, dst)
		}
	}
	if err == nil && !strings.EqualFold(sum, e.SHA256) {
		os.Remove(dst)
		err = errors.New("скачанное заново ядро не совпадает с установленным")
	}
	if err != nil {
		return "", fmt.Errorf("ядро %s %s не скачалось заново: %w", Kinds[name].Title, e.Version, err)
	}
	return dst, nil
}

// keep are the files of a core install must not prune: the downloaded
// ones in use or to roll back to (in.mu held).
func (in *Installer) keep(name string) []string {
	in.loadUpdates()
	var out []string
	if st := in.updates[name]; st != nil {
		for _, e := range []*entry{st.Current, st.Previous} {
			if e != nil {
				out = append(out, fileName(name, e.Version))
			}
		}
	}
	return out
}

// Info is a core for the page.
type Info struct {
	Name    string `json:"name"`
	Title   string `json:"title"`
	Version string `json:"version"` // in use: a downloaded one or the pinned one
	Pinned  string `json:"pinned"`
	Updated bool   `json:"updated"`
	// Previous is what a rollback returns to ("" = nothing).
	Previous string `json:"previous,omitempty"`
	Error    string `json:"error,omitempty"`
	// RAM: the core in use lives in RAM (the flash had no room for it);
	// after a reboot it is downloaded again.
	RAM bool `json:"ram,omitempty"`
}

// Info describes a core.
func (in *Installer) Info(name string) Info {
	pinned, err := Pinned(name)
	if err != nil {
		return Info{Name: name, Error: err.Error()}
	}
	return in.info(name, pinned)
}

func (in *Installer) info(name string, pinned Core) Info {
	inf := Info{Name: name, Title: Kinds[name].Title, Version: pinned.Version, Pinned: pinned.Version}
	in.mu.Lock()
	defer in.mu.Unlock()
	if p, again := in.updated(name, pinned.Version); p != "" || again != nil {
		st := in.updates[name]
		inf.Version, inf.Updated, inf.RAM = st.Current.Version, true, st.Current.RAM
		inf.Previous = "закреплённое " + pinned.Version
		if e := st.Previous; e != nil && release.Compare(e.Version, pinned.Version) > 0 && in.usable(name, e) {
			inf.Previous = e.Version
		}
	} else if st := in.updates[name]; st != nil && st.Current != nil {
		inf.Error = "скачанное обновление ядра повреждено или изменено: используется закреплённое"
	}
	return inf
}

// Update is a newer release of a core.
type Update struct {
	Name      string    `json:"name"`
	Version   string    `json:"version"` // the tag: app/v2.13.0
	Notes     string    `json:"notes"`
	Published time.Time `json:"published"`
	Page      string    `json:"page"`
	asset     string
	member    string
	url       string
	size      int64
	sums      []string
}

// Check finds the newest stable release of a core newer than the one in
// use (ok is false when it is up to date).
func (in *Installer) Check(ctx context.Context, c *release.Client, name string) (Update, bool, error) {
	pinned, err := Pinned(name)
	if err != nil {
		return Update{}, false, err
	}
	return in.check(ctx, c, name, pinned)
}

func (in *Installer) check(ctx context.Context, c *release.Client, name string, pinned Core) (Update, bool, error) {
	k, ok := Kinds[name]
	if !ok {
		return Update{}, false, fmt.Errorf("ядро %s не обновляется", name)
	}
	pa, ok := pinned.Assets[in.arch()]
	if !ok {
		return Update{}, false, fmt.Errorf("%s нет для процессора этого роутера (%s)", k.Title, in.arch())
	}
	// The asset of a newer release has the pinned one's name: the last
	// part of its address.
	asset, err := url.PathUnescape(path.Base(pa.URL))
	if err != nil {
		return Update{}, false, err
	}
	cur := in.info(name, pinned).Version
	list, err := c.Releases(ctx, k.Repo)
	if err != nil {
		return Update{}, false, err
	}
	r, found := release.Latest(list, false, k.Accept)
	if !found {
		return Update{}, false, fmt.Errorf("стабильных выпусков %s не найдено", k.Title)
	}
	if release.Compare(r.Tag, cur) <= 0 {
		return Update{}, false, nil
	}
	a, ok := r.Asset(asset)
	if !ok {
		return Update{}, false, fmt.Errorf("в выпуске %s %s нет %s", k.Title, r.Tag, asset)
	}
	u := Update{Name: name, Version: r.Tag, Notes: r.Body, Published: r.Published, Page: r.Page,
		asset: asset, member: pa.Member, url: a.URL, size: a.Size, sums: k.Sums(ctx, c, r, a)}
	if len(u.sums) == 0 {
		return Update{}, false, fmt.Errorf("у выпуска %s %s нет контрольных сумм: обновление небезопасно", k.Title, r.Tag)
	}
	return u, true, nil
}

// Install downloads u, checks it, makes sure it starts and reports its
// version (in.Version), and makes it the core in use; the one it replaces
// is kept for Rollback. Running cores are not touched: a server takes the
// new one when it starts again.
func (in *Installer) Install(ctx context.Context, c *release.Client, u Update, progress func(done, total int64)) error {
	pinned, err := Pinned(u.Name)
	if err != nil {
		return err
	}
	return in.install1(ctx, c, u, pinned.Version, progress)
}

func (in *Installer) install1(ctx context.Context, c *release.Client, u Update, pinned string, progress func(done, total int64)) error {
	if u.url == "" || len(u.sums) == 0 {
		return errors.New("обновление ядра не проверено: нажмите «Проверить» ещё раз")
	}
	if in.Version == nil {
		return errors.New("нечем проверить новое ядро")
	}
	if err := os.MkdirAll(in.Dir, 0o755); err != nil {
		return err
	}
	// The download, its zip and the try take place in Staging (RAM): the
	// flash takes only the core itself, when it has room for it.
	stage := in.stage()
	if err := os.MkdirAll(stage, 0o755); err != nil {
		return err
	}
	need := u.size + 4<<20
	if u.member != "" {
		need = 3*u.size + 4<<20 // the zip and the core taken out of it
	}
	if u.size > 0 && freeSpace(stage) < need {
		return fmt.Errorf("во временном хранилище (%s) нет %d МБ для нового ядра", stage, need>>20)
	}
	file := fileName(u.Name, u.Version)
	// Not ".download-" or ".core-": a pinned core's install prunes those.
	tmp := filepath.Join(stage, ".update-"+u.asset)
	staged := filepath.Join(stage, ".update-core-"+file)
	defer os.Remove(tmp)
	defer os.Remove(staged)
	sum, err := c.Download(ctx, u.url, tmp, maxSize, progress, u.sums...)
	if err != nil {
		return err
	}
	if u.member != "" {
		sum, err = unzipMember(tmp, u.member, staged)
		os.Remove(tmp)
	} else if err = os.Chmod(tmp, 0o755); err == nil {
		err = os.Rename(tmp, staged)
	}
	if err != nil {
		return err
	}
	got, err := in.Version(u.Name, staged)
	if err == nil && release.Compare(got, u.Version) != 0 {
		err = fmt.Errorf("сообщает версию %s", got)
	}
	if err != nil {
		return fmt.Errorf("новое ядро %s %s не запускается, обновление отменено: %v", Kinds[u.Name].Title, u.Version, err)
	}
	fi, err := os.Stat(staged)
	if err != nil {
		return err
	}

	in.mu.Lock()
	defer in.mu.Unlock()
	in.loadUpdates()
	st := in.updates[u.Name]
	if st == nil {
		st = &coreState{}
		in.updates[u.Name] = st
	}
	e := &entry{Version: u.Version, SHA256: sum}
	placed := false
	if stage != in.Dir && in.room(u.Name, fi.Size(), st, pinned) {
		placed = moveFile(staged, in.entryPath(u.Name, e)) == nil
	}
	if !placed && stage != in.Dir {
		// The flash has no room: the core stays in RAM, and a reboot
		// downloads it again.
		e.RAM, e.URL, e.Member, e.Sums = true, u.url, u.member, u.sums
	}
	if !placed {
		if err := os.Rename(staged, in.entryPath(u.Name, e)); err != nil {
			return err
		}
	}
	old := *st
	st.Previous, st.Current = st.Current, e
	if err := in.saveUpdates(); err != nil {
		*st = old
		if !in.kept(u.Name, u.Version) {
			os.Remove(in.entryPath(u.Name, e))
		}
		return err
	}
	in.pruneUpdates(u.Name, pinned)
	return nil
}

// kept: a version of a core is the current update or the rollback target
// (in.mu held).
func (in *Installer) kept(name, version string) bool {
	st := in.updates[name]
	return st != nil && (st.Current != nil && st.Current.Version == version || st.Previous != nil && st.Previous.Version == version)
}

// room makes room on the flash (Dir) for a new core of size bytes and
// reports whether there is enough. The update before the current one goes
// first (this install prunes it anyway); then, when an update is the
// rollback target, the pinned core's file, which is downloaded again if
// it is needed (in.mu held).
func (in *Installer) room(name string, size int64, st *coreState, pinned string) bool {
	need := size + 1<<20
	if freeSpace(in.Dir) >= need {
		return true
	}
	if e := st.Previous; e != nil && !e.RAM && (st.Current == nil || e.Version != st.Current.Version) {
		os.Remove(in.entryPath(name, e))
		if freeSpace(in.Dir) >= need {
			return true
		}
	}
	p := filepath.Join(in.Dir, fileName(name, pinned))
	if fi, err := os.Stat(p); err == nil && st.Current != nil && freeSpace(in.Dir)+fi.Size() >= need {
		os.Remove(p)
		return freeSpace(in.Dir) >= need
	}
	return false
}

// moveFile moves a core from RAM to the flash: a copy (another file
// system), made whole under a temporary name first.
func moveFile(src, dst string) error {
	if err := os.Rename(src, dst); err == nil {
		return nil
	}
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	part := dst + ".part"
	out, err := os.OpenFile(part, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o755)
	if err != nil {
		return err
	}
	_, err = io.Copy(out, in)
	if err == nil {
		err = out.Sync()
	}
	if cerr := out.Close(); err == nil {
		err = cerr
	}
	if err == nil {
		err = os.Rename(part, dst)
	}
	if err != nil {
		os.Remove(part)
		return err
	}
	os.Remove(src)
	return nil
}

// Rollback returns a core to the one it replaced (or the pinned one).
func (in *Installer) Rollback(name string) error {
	in.mu.Lock()
	defer in.mu.Unlock()
	in.loadUpdates()
	st := in.updates[name]
	if st == nil || st.Current == nil {
		return errors.New("используется закреплённое ядро: откатываться некуда")
	}
	old := *st
	if e := st.Previous; e != nil && !in.usable(name, e) {
		st.Previous = nil
	}
	st.Current, st.Previous = st.Previous, st.Current
	if err := in.saveUpdates(); err != nil {
		*st = old
		return err
	}
	return nil
}

// pruneUpdates removes the files of a core but the pinned one and those
// of updates.json, on the flash and in RAM (in.mu held).
func (in *Installer) pruneUpdates(name, pinned string) {
	keep := append(in.keep(name), fileName(name, pinned))
	prune(in.Dir, name+"-", keep...)
	if in.stage() != in.Dir {
		prune(in.stage(), name+"-", keep...)
	}
}

// unzipMember takes member out of the zip at zipPath into dst (executable)
// and returns its SHA-256. Only that one member, by its exact name, is
// read into a path HyRouter chose.
func unzipMember(zipPath, member, dst string) (string, error) {
	zr, err := zip.OpenReader(zipPath)
	if err != nil {
		return "", err
	}
	defer zr.Close()
	for _, f := range zr.File {
		if f.Name != member {
			continue
		}
		rc, err := f.Open()
		if err != nil {
			return "", err
		}
		defer rc.Close()
		tmp, err := os.CreateTemp(filepath.Dir(dst), ".update-core-*")
		if err != nil {
			return "", err
		}
		defer os.Remove(tmp.Name())
		h := sha256.New()
		n, err := io.Copy(io.MultiWriter(tmp, h), io.LimitReader(rc, maxSize+1))
		if cerr := tmp.Close(); err == nil {
			err = cerr
		}
		if err == nil && n > maxSize {
			err = errors.New("файл больше ожидаемого")
		}
		if err == nil {
			err = os.Chmod(tmp.Name(), 0o755)
		}
		if err == nil {
			err = os.Rename(tmp.Name(), dst)
		}
		if err != nil {
			return "", err
		}
		return hex.EncodeToString(h.Sum(nil)), nil
	}
	return "", fmt.Errorf("в архиве нет %s", member)
}
