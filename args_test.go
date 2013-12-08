package pt

import (
	"testing"
)

func stringSlicesEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func argsEqual(a, b Args) bool {
	for k, av := range a {
		bv := b[k]
		if !stringSlicesEqual(av, bv) {
			return false
		}
	}
	for k, bv := range b {
		av := a[k]
		if !stringSlicesEqual(av, bv) {
			return false
		}
	}
	return true
}

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

func TestParseClientParameters(t *testing.T) {
	badTests := [...]string{
		"key",
		"=value",
		"==value",
		"==key=value",
		"key=value\\",
		"a=b;key=value\\",
		"a;b=c",
		";",
		"key=value;",
		";key=value",
		"key\\=value",
	}
	goodTests := [...]struct {
		input    string
		expected Args
	}{
		{
			"",
			Args{},
		},
		{
			"key=",
			Args{"key": []string{""}},
		},
		{
			"key==",
			Args{"key": []string{"="}},
		},
		{
			"key=value",
			Args{"key": []string{"value"}},
		},
		{
			"a=b=c",
			Args{"a": []string{"b=c"}},
		},
		{
			"key=a\nb",
			Args{"key": []string{"a\nb"}},
		},
		{
			"key=value\\;",
			Args{"key": []string{"value;"}},
		},
		{
			"key=\"value\"",
			Args{"key": []string{"\"value\""}},
		},
		{
			"key=\"\"value\"\"",
			Args{"key": []string{"\"\"value\"\""}},
		},
		{
			"\"key=value\"",
			Args{"\"key": []string{"value\""}},
		},
		{
			"key=value;key=value",
			Args{"key": []string{"value", "value"}},
		},
		{
			"key=value1;key=value2",
			Args{"key": []string{"value1", "value2"}},
		},
		{
			"key1=value1;key2=value2;key1=value3",
			Args{"key1": []string{"value1", "value3"}, "key2": []string{"value2"}},
		},
		{
			"\\;=\\;;\\\\=\\;",
			Args{";": []string{";"}, "\\": []string{";"}},
		},
		{
			"a\\=b=c",
			Args{"a=b": []string{"c"}},
		},
	}

	for _, input := range badTests {
		_, err := parseClientParameters(input)
		if err == nil {
			t.Errorf("%q unexpectedly succeeded", input)
		}
	}

	for _, test := range goodTests {
		args, err := parseClientParameters(test.input)
		if err != nil {
			t.Errorf("%q unexpectedly returned an error: %s", test.input, err)
		}
		if !argsEqual(args, test.expected) {
			t.Errorf("%q → %q (expected %q)", test.input, args, test.expected)
		}
	}
}

func optsEqual(a, b map[string]Args) bool {
	for k, av := range a {
		bv, ok := b[k]
		if !ok || !argsEqual(av, bv) {
			return false
		}
	}
	for k, bv := range b {
		av, ok := a[k]
		if !ok || !argsEqual(av, bv) {
			return false
		}
	}
	return true
}

func TestParseServerTransportOptions(t *testing.T) {
	badTests := [...]string{
		":=",
		"t:=",
		":k=",
		":=v",
		"t:=v",
		"t:=v",
		"t:k=v;",
		"abc",
		"t:",
		"key=value",
		"=value",
		"t:k=v\\",
		"t1:k=v;t2:k=v\\",
		"t:=key=value",
		"t:==key=value",
		"t:;key=value",
		"t:key\\=value",
	}
	goodTests := [...]struct {
		input    string
		expected map[string]Args
	}{
		{
			"",
			map[string]Args{},
		},
		{
			"t:k=v",
			map[string]Args{
				"t": Args{"k": []string{"v"}},
			},
		},
		{
			"t1:k=v1;t2:k=v2;t1:k=v3",
			map[string]Args{
				"t1": Args{"k": []string{"v1", "v3"}},
				"t2": Args{"k": []string{"v2"}},
			},
		},
		{
			"t\\:1:k=v;t\\=2:k=v;t\\;3:k=v;t\\\\4:k=v",
			map[string]Args{
				"t:1":  Args{"k": []string{"v"}},
				"t=2":  Args{"k": []string{"v"}},
				"t;3":  Args{"k": []string{"v"}},
				"t\\4": Args{"k": []string{"v"}},
			},
		},
		{
			"t:k\\:1=v;t:k\\=2=v;t:k\\;3=v;t:k\\\\4=v",
			map[string]Args{
				"t": Args{
					"k:1":  []string{"v"},
					"k=2":  []string{"v"},
					"k;3":  []string{"v"},
					"k\\4": []string{"v"},
				},
			},
		},
		{
			"t:k=v\\:1;t:k=v\\=2;t:k=v\\;3;t:k=v\\\\4",
			map[string]Args{
				"t": Args{"k": []string{"v:1", "v=2", "v;3", "v\\4"}},
			},
		},
		{
			"trebuchet:secret=nou;trebuchet:cache=/tmp/cache;ballista:secret=yes",
			map[string]Args{
				"trebuchet": Args{"secret": []string{"nou"}, "cache": []string{"/tmp/cache"}},
				"ballista":  Args{"secret": []string{"yes"}},
			},
		},
	}

	for _, input := range badTests {
		_, err := parseServerTransportOptions(input)
		if err == nil {
			t.Errorf("%q unexpectedly succeeded", input)
		}
	}

	for _, test := range goodTests {
		opts, err := parseServerTransportOptions(test.input)
		if err != nil {
			t.Errorf("%q unexpectedly returned an error: %s", test.input, err)
		}
		if !optsEqual(opts, test.expected) {
			t.Errorf("%q → %q (expected %q)", test.input, opts, test.expected)
		}
	}
}
