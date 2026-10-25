//go:build linux

package bpf

import (
	"reflect"
	"testing"

	"github.com/sonix03/heideltrace/internal/abi"
)

// TestEventLayout checks that abi.RawEvent matches struct ht_event as the
// compiler laid it out. bpf2go derives cudaHtEvent from the object's BTF.
func TestEventLayout(t *testing.T) {
	compareLayout(t, "ht_event", reflect.TypeOf(cudaHtEvent{}), reflect.TypeOf(abi.RawEvent{}))
}

func compareLayout(t *testing.T, name string, c, g reflect.Type) {
	t.Helper()
	if c.Size() != g.Size() {
		t.Fatalf("%s: C size %d, Go size %d", name, c.Size(), g.Size())
	}
	for i := 0; i < c.NumField(); i++ {
		cf := c.Field(i)
		if cf.Name == "_" {
			continue
		}
		gf, ok := g.FieldByName(cf.Name)
		if !ok {
			t.Errorf("%s.%s: missing in abi", name, cf.Name)
			continue
		}
		if cf.Offset != gf.Offset || cf.Type.Size() != gf.Type.Size() {
			t.Errorf("%s.%s: C offset %d size %d, Go offset %d size %d",
				name, cf.Name, cf.Offset, cf.Type.Size(), gf.Offset, gf.Type.Size())
		}
		if cf.Type.Kind() == reflect.Struct {
			compareLayout(t, name+"."+cf.Name, cf.Type, gf.Type)
		}
	}
}
