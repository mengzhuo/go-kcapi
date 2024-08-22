package procfs

import (
	"bytes"
	"encoding/json"
	"testing"
)

func TestDefault(t *testing.T) {
	cl := Default()
	buf := bytes.NewBuffer(nil)
	enc := json.NewEncoder(buf)
	enc.SetIndent("\t", "  ")
	err := enc.Encode(cl)
	if err != nil {
		t.Fatal(err)
	}
	t.Log(buf.String())
}
