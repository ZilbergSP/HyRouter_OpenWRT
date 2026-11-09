//go:build linux

package nft

import (
	"bytes"
	"context"
	"fmt"
	"net/netip"
	"os/exec"
	"strings"
	"sync"
	"time"

	"github.com/google/nftables"
)

// Load replaces HyRouter's table with script in one transaction (nft -f).
func Load(ctx context.Context, script string) error {
	cmd := exec.CommandContext(ctx, "nft", "-f", "-")
	cmd.Stdin = strings.NewReader(script)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("nft: %v: %s", err, bytes.TrimSpace(out))
	}
	return nil
}

// Remove deletes HyRouter's table: the LAN goes on as without HyRouter.
// A table that is not there is no error.
func Remove(ctx context.Context) error {
	out, err := exec.CommandContext(ctx, "nft", "delete", "table", "inet", Table).CombinedOutput()
	if err != nil && !bytes.Contains(out, []byte("No such file")) {
		return fmt.Errorf("nft: %v: %s", err, bytes.TrimSpace(out))
	}
	return nil
}

// Elem is an address in a set of HyRouter's table, kept for Timeout.
type Elem struct {
	Set     string
	Addr    netip.Addr
	Timeout time.Duration
}

// Sets changes the elements of the table's sets through netlink.
type Sets struct {
	mu   sync.Mutex
	conn *nftables.Conn
}

// OpenSets opens the netlink connection; Close ends it.
func OpenSets() (*Sets, error) {
	c, err := nftables.New(nftables.AsLasting())
	if err != nil {
		return nil, fmt.Errorf("nftables: %w", err)
	}
	return &Sets{conn: c}, nil
}

// Close closes the netlink connection.
func (s *Sets) Close() error { return s.conn.CloseLasting() }

// Apply removes del and adds add in one transaction: an address being
// refreshed (in both) is never missing from its set. If any element of
// del is not there, nothing changes and the error says so.
func (s *Sets) Apply(del, add []Elem) error {
	if len(del) == 0 && len(add) == 0 {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, g := range groups(del) {
		if err := s.conn.SetDeleteElements(g.set, g.elems); err != nil {
			return err
		}
	}
	for _, g := range groups(add) {
		if err := s.conn.SetAddElements(g.set, g.elems); err != nil {
			return err
		}
	}
	return s.conn.Flush()
}

type group struct {
	set   *nftables.Set
	elems []nftables.SetElement
}

// groups sorts elements by set, in the order the sets come.
func groups(es []Elem) []group {
	table := &nftables.Table{Name: Table, Family: nftables.TableFamilyINet}
	var out []group
	idx := map[string]int{}
	for _, e := range es {
		i, ok := idx[e.Set]
		if !ok {
			key := nftables.TypeIPAddr
			if e.Addr.Is6() && !e.Addr.Is4In6() {
				key = nftables.TypeIP6Addr
			}
			i = len(out)
			idx[e.Set] = i
			out = append(out, group{set: &nftables.Set{Table: table, Name: e.Set, KeyType: key, HasTimeout: true}})
		}
		a := e.Addr.Unmap()
		out[i].elems = append(out[i].elems, nftables.SetElement{Key: a.AsSlice(), Timeout: e.Timeout})
	}
	return out
}
