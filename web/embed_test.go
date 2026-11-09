package webui

import (
	"io/fs"
	"testing"
)

func TestDistHasIndex(t *testing.T) {
	if _, err := fs.Stat(Dist(), "index.html"); err != nil {
		t.Fatalf("the built interface is not embedded: %v", err)
	}
}
