package geodata

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"regexp"
	"slices"
	"strings"
)

// HyRouter: a router keeps only the categories its rules use, written out
// of the downloaded databases (the files are too large for its flash and
// memory). Entries and ParseEntries carry a geosite category, Prefixes a
// geoip one (also into nftables sets).

// Entries lists a geosite category as "full:", "domain:", "keyword:" and
// "regexp:" lines.
func (d *DomainSet) Entries() []string {
	out := make([]string, 0, d.Len())
	for _, s := range d.full {
		out = append(out, "full:"+s)
	}
	for _, s := range d.suffix {
		out = append(out, "domain:"+s)
	}
	for _, s := range d.keyword {
		out = append(out, "keyword:"+s)
	}
	for _, re := range d.regex {
		out = append(out, "regexp:"+re.String())
	}
	return out
}

// ParseEntries builds a category from the lines of Entries.
func ParseEntries(lines []string) (*DomainSet, error) {
	d := &DomainSet{}
	for _, l := range lines {
		kind, v, ok := strings.Cut(l, ":")
		if !ok || v == "" {
			return nil, fmt.Errorf("неверная строка %q", l)
		}
		switch kind {
		case "full":
			d.full = append(d.full, v)
		case "domain":
			d.suffix = append(d.suffix, v)
		case "keyword":
			d.keyword = append(d.keyword, v)
		case "regexp":
			re, err := regexp.Compile(v)
			if err != nil {
				return nil, fmt.Errorf("неверное выражение %q: %v", v, err)
			}
			d.regex = append(d.regex, re)
		default:
			return nil, fmt.Errorf("неверная строка %q", l)
		}
	}
	slices.Sort(d.full)
	d.full = slices.Compact(d.full)
	slices.Sort(d.suffix)
	d.suffix = slices.Compact(d.suffix)
	return d, nil
}

// Prefixes lists the networks of a geoip category (of its complement for
// a reversed one), as few as cover its ranges exactly.
func (s *IPSet) Prefixes() []netip.Prefix {
	v4, v6 := s.v4, s.v6
	if s.reverse {
		v4, v6 = invert4(v4), invert6(v6)
	}
	var out []netip.Prefix
	for _, r := range v4 {
		out = appendRange4(out, r.lo, r.hi)
	}
	for _, r := range v6 {
		out = appendRange6(out, r.lo, r.hi)
	}
	return out
}

// appendRange4 appends the networks that cover lo..hi.
func appendRange4(out []netip.Prefix, lo, hi uint32) []netip.Prefix {
	l, h := uint64(lo), uint64(hi)
	for l <= h {
		k := 32
		for ; k > 0; k-- {
			block := uint64(1) << k
			if l%block == 0 && l+block-1 <= h {
				break
			}
		}
		var b [4]byte
		binary.BigEndian.PutUint32(b[:], uint32(l))
		out = append(out, netip.PrefixFrom(netip.AddrFrom4(b), 32-k))
		l += uint64(1) << k
	}
	return out
}

// mask128 is the 128-bit number with the k low bits set.
func mask128(k int) u128 {
	switch {
	case k <= 0:
		return u128{}
	case k < 64:
		return u128{0, 1<<k - 1}
	case k == 64:
		return u128{0, ^uint64(0)}
	case k < 128:
		return u128{1<<(k-64) - 1, ^uint64(0)}
	}
	return u128{^uint64(0), ^uint64(0)}
}

// appendRange6 appends the networks that cover lo..hi.
func appendRange6(out []netip.Prefix, lo, hi u128) []netip.Prefix {
	for lo.cmp(hi) <= 0 {
		k := 128
		var end u128
		for ; k > 0; k-- {
			m := mask128(k)
			if lo.hi&m.hi != 0 || lo.lo&m.lo != 0 {
				continue // lo is not aligned to 2^k
			}
			end = u128{lo.hi | m.hi, lo.lo | m.lo}
			if end.cmp(hi) <= 0 {
				break
			}
		}
		if k == 0 {
			end = lo
		}
		var b [16]byte
		binary.BigEndian.PutUint64(b[:8], lo.hi)
		binary.BigEndian.PutUint64(b[8:], lo.lo)
		out = append(out, netip.PrefixFrom(netip.AddrFrom16(b), 128-k))
		next, ok := end.next()
		if !ok {
			break
		}
		lo = next
	}
	return out
}

// invert4 is the complement of sorted, merged ranges.
func invert4(rs []r4) []r4 {
	var out []r4
	next := uint64(0)
	for _, r := range rs {
		if uint64(r.lo) > next {
			out = append(out, r4{uint32(next), r.lo - 1})
		}
		next = uint64(r.hi) + 1
	}
	if next <= uint64(^uint32(0)) {
		out = append(out, r4{uint32(next), ^uint32(0)})
	}
	return out
}

// invert6 is the complement of sorted, merged ranges.
func invert6(rs []r6) []r6 {
	var out []r6
	next, more := u128{}, true
	for _, r := range rs {
		if more && r.lo.cmp(next) > 0 {
			out = append(out, r6{next, prev128(r.lo)})
		}
		next, more = r.hi.next()
	}
	if more {
		out = append(out, r6{next, u128{^uint64(0), ^uint64(0)}})
	}
	return out
}

// prev128 is a-1 (a is not zero).
func prev128(a u128) u128 {
	if a.lo == 0 {
		return u128{a.hi - 1, ^uint64(0)}
	}
	return u128{a.hi, a.lo - 1}
}

// PublishedSum is the checksum published next to a database ("" when its
// source publishes none): HyRouter keeps no database between updates and
// downloads one only when it changed.
func (u *Updater) PublishedSum(ctx context.Context, url string) (string, error) {
	h, err := u.fetchSum(ctx, sumURL(url), 0)
	if errors.Is(err, errNoSum) {
		return "", nil
	}
	return h, err
}
