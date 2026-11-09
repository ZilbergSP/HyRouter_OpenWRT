package zapret

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// The NFQUEUE queues other programs hold. Another DPI bypass on the router
// (zapret and nfqws-keenetic take queue 200 by default) holds the queue
// HyRouter's nfqws2 would take, and nfqws2 then ends with
// "nfq_create_queue(): Operation not permitted": the kernel refuses a
// queue another socket has bound. HyRouter takes a free range instead
// (PickQueue) and says who holds the default one.

// QueueFile is the kernel's list of the bound queues.
var QueueFile = "/proc/net/netfilter/nfnetlink_queue"

// procDir is /proc (tests replace it).
var procDir = "/proc"

// queueStep is the distance between the ranges PickQueue tries.
const queueStep = 100

// BoundQueues reads QueueFile: each bound queue and the netlink port ID of
// its socket, which is the process ID for most programs (nfqws, nfqws2).
// No file (no queue was ever bound: the module is not loaded) is none.
func BoundQueues() (map[int]int64, error) {
	b, err := os.ReadFile(QueueFile)
	if errors.Is(err, fs.ErrNotExist) {
		return map[int]int64{}, nil
	}
	if err != nil {
		return nil, err
	}
	return parseQueues(string(b)), nil
}

// parseQueues reads QueueFile's lines: the queue, the port ID, then
// counters.
func parseQueues(s string) map[int]int64 {
	out := map[int]int64{}
	for _, l := range strings.Split(s, "\n") {
		f := strings.Fields(l)
		if len(f) < 2 {
			continue
		}
		q, err := strconv.Atoi(f[0])
		if err != nil || q < 0 || q > 65535 {
			continue
		}
		p, err := strconv.ParseInt(f[1], 10, 64)
		if err != nil {
			continue
		}
		out[q] = p
	}
	return out
}

// PickQueue is the first range of queues (base … base+ProbeSlots-1; base
// QNumBypass, then 100 more each time) in which foreign reports none held
// by another program. When every range is taken: QNumBypass.
func PickQueue(bound map[int]int64, foreign func(queue int, port int64) bool) int {
	for base := QNumBypass; base+ProbeSlots <= 65536; base += queueStep {
		free := true
		for q := base; q < base+ProbeSlots && free; q++ {
			if p, ok := bound[q]; ok && foreign(q, p) {
				free = false
			}
		}
		if free {
			return base
		}
	}
	return QNumBypass
}

// Holder is the process behind a netlink port ID.
type Holder struct {
	PID    int
	Name   string // its comm: "nfqws"
	Exe    string // its executable ("" when not readable)
	Parent int    // its parent's process ID
}

// FindHolder is the process whose ID is port (false: there is none, the
// socket got another port ID).
func FindHolder(port int64) (Holder, bool) {
	if port <= 0 || port > 1<<31-1 {
		return Holder{}, false
	}
	dir := filepath.Join(procDir, strconv.FormatInt(port, 10))
	stat, err := os.ReadFile(filepath.Join(dir, "stat"))
	if err != nil {
		return Holder{}, false
	}
	h := Holder{PID: int(port)}
	// "pid (comm) state ppid …": comm may hold spaces and parentheses.
	s := string(stat)
	if i, j := strings.IndexByte(s, '('), strings.LastIndexByte(s, ')'); i >= 0 && j > i {
		h.Name = s[i+1 : j]
		if f := strings.Fields(s[j+1:]); len(f) >= 2 {
			h.Parent, _ = strconv.Atoi(f[1])
		}
	}
	if exe, err := os.Readlink(filepath.Join(dir, "exe")); err == nil {
		h.Exe = strings.TrimSuffix(exe, " (deleted)")
	}
	return h, true
}
