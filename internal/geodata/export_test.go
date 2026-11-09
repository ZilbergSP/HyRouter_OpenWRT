package geodata

import (
	"net/netip"
	"slices"
	"testing"
)

func TestEntriesRoundTrip(t *testing.T) {
	d, err := ParseEntries([]string{"full:a.example", "domain:video.example", "keyword:tube", "regexp:^cdn[0-9]+\\.", "full:a.example"})
	if err != nil {
		t.Fatal(err)
	}
	for name, want := range map[string]bool{"a.example": true, "x.video.example": true, "youtube.com": true, "cdn12.net": true, "b.example": false} {
		if d.Match(name) != want {
			t.Errorf("%s: %v", name, !want)
		}
	}
	d2, err := ParseEntries(d.Entries())
	if err != nil || !slices.Equal(d2.Entries(), d.Entries()) || d.Len() != 4 {
		t.Fatalf("round trip: %v %v", d2, err)
	}
	if _, err := ParseEntries([]string{"other:x"}); err == nil {
		t.Error("an unknown kind was taken")
	}
}

func TestPrefixes(t *testing.T) {
	pfx := func(ss ...string) []netip.Prefix {
		var out []netip.Prefix
		for _, s := range ss {
			out = append(out, netip.MustParsePrefix(s))
		}
		return out
	}
	s := NewIPSet(pfx("10.0.0.0/24", "10.0.1.0/24", "192.0.2.7/32", "2001:db8::/33", "2001:db8:8000::/33"))
	got := s.Prefixes()
	want := pfx("10.0.0.0/23", "192.0.2.7/32", "2001:db8::/32")
	if !slices.Equal(got, want) {
		t.Fatalf("prefixes %v, want %v", got, want)
	}
	// A range that is no single network is split exactly.
	s = &IPSet{v4: []r4{{lo: 0x0a000001, hi: 0x0a000006}}}
	if got := s.Prefixes(); !slices.Equal(got, pfx("10.0.0.1/32", "10.0.0.2/31", "10.0.0.4/31", "10.0.0.6/32")) {
		t.Errorf("split %v", got)
	}
	// A reversed category is its complement.
	s = NewIPSet(pfx("128.0.0.0/1", "::/1"))
	s.reverse = true
	if got := s.Prefixes(); !slices.Equal(got, pfx("0.0.0.0/1", "8000::/1")) {
		t.Errorf("reversed %v", got)
	}
	whole := NewIPSet(pfx("0.0.0.0/0", "::/0"))
	if got := whole.Prefixes(); !slices.Equal(got, pfx("0.0.0.0/0", "::/0")) {
		t.Errorf("everything %v", got)
	}
}
