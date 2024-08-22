package procfs

import (
	"testing"
)

func TestDefault(t *testing.T) {
	cl := Default()
	if len(cl) == 0 {
		t.Skip()
		return
	}
	c := cl[0]
	if c.Name == "" {
		t.Error("expecting name")
	}
	if c.Type == "" {
		t.Error("expecting type")
	}
}
