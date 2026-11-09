package zapret

import (
	"encoding/json"
	"slices"
	"strings"
	"testing"
)

// HyRoute tests these through its controller (internal/app), which
// HyRouter does not have yet.

func TestChecksSkip(t *testing.T) {
	sites := []string{"a.example", "dead.example", "1.2.3.4", "b.example"}
	if got := ChecksSkip(Sites, sites, []string{"dead.example"}); !slices.Equal(got, []string{"https://a.example/", "https://b.example/"}) {
		t.Fatalf("%v", got)
	}
	if got := ChecksSkip(Sites, sites, nil); !slices.Equal(got, Checks(Sites, sites)) || len(got) != 3 {
		t.Fatalf("%v", got)
	}
	// The services' checks never skip.
	if got := ChecksSkip(YouTube, sites, []string{"www.youtube.com"}); !slices.Equal(got, Checks(YouTube, nil)) {
		t.Fatalf("%v", got)
	}
	// Up to 20 names, no addresses.
	var many []string
	for i := range 30 {
		many = append(many, string(rune('a'+i%26))+string(rune('a'+i/26))+".example")
	}
	if got := SiteProbes(append([]string{"1.2.3.4"}, many...)); len(got) != 20 || got[0] != "https://aa.example/" {
		t.Fatalf("%d %v", len(got), got)
	}
}

func TestPickedSkippedSites(t *testing.T) {
	p := Picked{Methods: map[Target]string{Sites: "fake"}, SkippedSites: []string{"dead.example"}}
	b, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	var back Picked
	if err := json.Unmarshal(b, &back); err != nil || !slices.Equal(back.SkippedSites, p.SkippedSites) {
		t.Fatalf("%s: %v %+v", b, err, back)
	}
	// Picks from before 1.3.24 stay as they were: no field when empty.
	if b, _ := json.Marshal(Picked{}); strings.Contains(string(b), "skippedSites") {
		t.Fatalf("an empty pick writes %s", b)
	}
}
