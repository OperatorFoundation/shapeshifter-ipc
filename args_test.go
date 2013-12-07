package pt

import (
	"testing"
)

func TestArgsGet(t *testing.T) {
	args := Args{
		"a": []string{},
		"b": []string{"value"},
		"c": []string{"v1", "v2", "v3"},
	}

	var v string
	var ok bool
	v, ok = args.Get("a")
	if ok {
		t.Errorf("Unexpected Get success for %q", "a")
	}
	v, ok = args.Get("b")
	if !ok {
		t.Errorf("Unexpected Get failure for %q", "b")
	}
	if v != "value" {
		t.Errorf("Get(%q) → %q (expected %q)", "b", v, "value")
	}
	v, ok = args.Get("c")
	if !ok {
		t.Errorf("Unexpected Get failure for %q", "c")
	}
	if v != "v1" {
		t.Errorf("Get(%q) → %q (expected %q)", "c", v, "v1")
	}
	v, ok = args.Get("d")
	if ok {
		t.Errorf("Unexpected Get success for %q", "d")
	}
}

func TestArgsAdd(t *testing.T) {
	args := make(Args)
	if !argsEqual(args, Args{}) {
		t.Error()
	}
	args.Add("k1", "v1")
	if !argsEqual(args, Args{"k1": []string{"v1"}}) {
		t.Error()
	}
	args.Add("k2", "v2")
	if !argsEqual(args, Args{"k1": []string{"v1"}, "k2": []string{"v2"}}) {
		t.Error()
	}
	args.Add("k1", "v3")
	if !argsEqual(args, Args{"k1": []string{"v1", "v3"}, "k2": []string{"v2"}}) {
		t.Error()
	}
}
