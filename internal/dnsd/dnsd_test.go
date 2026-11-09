//go:build linux

package dnsd

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"slices"
	"sync"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"

	"github.com/zilbergsp/hyrouter/internal/dnscache"
	"github.com/zilbergsp/hyrouter/internal/nft"
	"github.com/zilbergsp/hyrouter/internal/rules"
)

type fakeSets struct {
	mu   sync.Mutex
	add  []nft.Elem
	del  []nft.Elem
	fail bool // fail an Apply that deletes, once
}

func (f *fakeSets) Apply(del, add []nft.Elem) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.fail && len(del) > 0 {
		f.fail = false
		return errors.New("an element is gone")
	}
	f.del = append(f.del, del...)
	f.add = append(f.add, add...)
	return nil
}

func (f *fakeSets) take() (del, add []nft.Elem) {
	f.mu.Lock()
	defer f.mu.Unlock()
	del, add = f.del, f.add
	f.del, f.add = nil, nil
	return del, add
}

func question(name string, typ dnsmessage.Type) dnsmessage.Question {
	return dnsmessage.Question{Name: dnsmessage.MustNewName(name + "."), Type: typ, Class: dnsmessage.ClassINET}
}

func query(t *testing.T, id uint16, name string, typ dnsmessage.Type) []byte {
	t.Helper()
	b := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: id, RecursionDesired: true})
	b.StartQuestions()
	if err := b.Question(question(name, typ)); err != nil {
		t.Fatal(err)
	}
	msg, err := b.Finish()
	if err != nil {
		t.Fatal(err)
	}
	return msg
}

// answer is the reply to a query for name with addresses, all with ttl.
func answer(t *testing.T, id uint16, name string, typ dnsmessage.Type, ttl uint32, addrs ...string) []byte {
	t.Helper()
	b := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: id, Response: true, RecursionDesired: true, RecursionAvailable: true})
	b.StartQuestions()
	if err := b.Question(question(name, typ)); err != nil {
		t.Fatal(err)
	}
	b.StartAnswers()
	h := dnsmessage.ResourceHeader{Name: dnsmessage.MustNewName(name + "."), Class: dnsmessage.ClassINET, TTL: ttl}
	for _, s := range addrs {
		a := netip.MustParseAddr(s)
		var err error
		if a.Is4() {
			err = b.AResource(h, dnsmessage.AResource{A: a.As4()})
		} else {
			err = b.AAAAResource(h, dnsmessage.AAAAResource{AAAA: a.As16()})
		}
		if err != nil {
			t.Fatal(err)
		}
	}
	msg, err := b.Finish()
	if err != nil {
		t.Fatal(err)
	}
	return msg
}

func testServer(t *testing.T) (*Server, *fakeSets) {
	t.Helper()
	set, err := rules.Compile(rules.Config{DefaultAction: rules.Direct, Rules: []rules.Rule{
		{Name: "video", Domains: []string{".video.example"}, Action: rules.Tunnel},
		{Name: "bank", Domains: []string{"bank.example"}, Action: rules.Direct},
		{Name: "ghost", Devices: []string{"dev:none"}, Domains: []string{".video.example"}, Action: rules.Block},
	}})
	if err != nil {
		t.Fatal(err)
	}
	set.Main = "p1"
	fs := &fakeSets{}
	s := New(Config{
		Rules:   func() *rules.Set { return set },
		HasSets: func(pos int) bool { return pos != 2 }, // the ghost rule is not in the table
		Cache:   dnscache.New(),
		Sets:    fs,
	})
	t.Cleanup(s.Close)
	return s, fs
}

func elem(set, addr string, timeout time.Duration) nft.Elem {
	return nft.Elem{Set: set, Addr: netip.MustParseAddr(addr), Timeout: timeout}
}

func sortElems(es []nft.Elem) []nft.Elem {
	slices.SortFunc(es, func(a, b nft.Elem) int {
		if a.Set != b.Set {
			if a.Set < b.Set {
				return -1
			}
			return 1
		}
		return a.Addr.Compare(b.Addr)
	})
	return es
}

func TestLearn(t *testing.T) {
	s, fs := testServer(t)
	q := query(t, 1, "www.video.example", dnsmessage.TypeA)
	s.Learn(q, answer(t, 1, "www.video.example", dnsmessage.TypeA, 60, "93.184.216.34", "2606:2800:220:1::1"))
	_, add := fs.take()
	want := []nft.Elem{elem("r0_dns4", "93.184.216.34", minTimeout), elem("r0_dns6", "2606:2800:220:1::1", minTimeout)}
	if !slices.Equal(sortElems(add), want) {
		t.Fatalf("added %+v, want %+v", add, want)
	}

	// The same address for a site the rules send another way: it goes into
	// that rule's set and the ambiguous one; the first set is fresh.
	q = query(t, 2, "bank.example", dnsmessage.TypeA)
	s.Learn(q, answer(t, 2, "bank.example", dnsmessage.TypeA, 3600, "93.184.216.34"))
	del, add := fs.take()
	want = []nft.Elem{elem("ambig4", "93.184.216.34", time.Hour), elem("r1_dns4", "93.184.216.34", time.Hour)}
	if len(del) != 0 || !slices.Equal(sortElems(add), want) {
		t.Fatalf("deleted %+v, added %+v, want %+v", del, add, want)
	}

	// Past half its time an address is refreshed: deleted and added in one
	// transaction; when it has just left the set, only added.
	k := elemKey{"r0_dns4", netip.MustParseAddr("93.184.216.34")}
	s.mu.Lock()
	s.elems[k] = elemTime{time.Now().Add(time.Minute), minTimeout}
	s.mu.Unlock()
	fs.fail = true
	q = query(t, 3, "www.video.example", dnsmessage.TypeA)
	s.Learn(q, answer(t, 3, "www.video.example", dnsmessage.TypeA, 60, "93.184.216.34"))
	del, add = fs.take()
	if len(del) != 0 || !slices.Contains(add, elem("r0_dns4", "93.184.216.34", minTimeout)) {
		t.Fatalf("refresh after a failed delete: deleted %+v, added %+v", del, add)
	}
	s.mu.Lock()
	s.elems[k] = elemTime{time.Now().Add(time.Minute), minTimeout}
	s.mu.Unlock()
	q = query(t, 4, "www.video.example", dnsmessage.TypeA)
	s.Learn(q, answer(t, 4, "www.video.example", dnsmessage.TypeA, 60, "93.184.216.34"))
	del, add = fs.take()
	if !slices.Contains(del, elem("r0_dns4", "93.184.216.34", minTimeout)) || !slices.Contains(add, elem("r0_dns4", "93.184.216.34", minTimeout)) {
		t.Fatalf("refresh: deleted %+v, added %+v", del, add)
	}

	// A new table: every known address goes in again.
	s.Refill()
	_, add = fs.take()
	for _, set := range []string{"r0_dns4", "r0_dns6", "r1_dns4", "ambig4"} {
		if !slices.ContainsFunc(add, func(e nft.Elem) bool { return e.Set == set }) {
			t.Errorf("refill left %s empty: %+v", set, add)
		}
	}

	// An answer that does not answer the query teaches nothing.
	s.Learn(query(t, 5, "evil.example", dnsmessage.TypeA), answer(t, 6, "www.video.example", dnsmessage.TypeA, 60, "203.0.113.9"))
	if _, add := fs.take(); len(add) != 0 {
		t.Errorf("an unsolicited answer was learned: %+v", add)
	}
}

// Without a policy every query goes to dnsmasq as it is, and its answer
// is learned.
func TestHandlePasses(t *testing.T) {
	up, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer up.Close()
	resp := answer(t, 0, "www.video.example", dnsmessage.TypeA, 300, "198.51.100.7")
	go func() {
		buf := make([]byte, 512)
		for {
			n, from, err := up.ReadFromUDPAddrPort(buf)
			if err != nil || n < 2 {
				return
			}
			out := append([]byte(nil), resp...)
			copy(out[:2], buf[:2]) // the query's ID
			up.WriteToUDPAddrPort(out, from)
		}
	}()
	s, fs := testServer(t)
	s.cfg.Upstream = up.LocalAddr().String()
	out := s.Handle(context.Background(), netip.MustParseAddrPort("192.168.1.20:5353"), query(t, 7, "www.video.example", dnsmessage.TypeA), false)
	var p dnsmessage.Parser
	if h, err := p.Start(out); err != nil || h.ID != 7 {
		t.Fatalf("answer %x: %v", out, err)
	}
	if _, add := fs.take(); !slices.Contains(add, elem("r0_dns4", "198.51.100.7", minTimeout)) {
		t.Errorf("the passed answer was not learned: %+v", add)
	}
}
