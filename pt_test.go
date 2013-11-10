package pt

import (
	"bytes"
	"os"
	"sort"
	"testing"
)

func stringIsSafe(s string) bool {
	for _, c := range []byte(s) {
		if c == '\x00' || c == '\n' || c > 127 {
			return false
		}
	}
	return true
}

func TestEscape(t *testing.T) {
	tests := [...]string{
		"",
		"abc",
		"a\nb",
		"a\\b",
		"ab\\",
		"ab\\\n",
		"ab\n\\",
	}

	check := func(input string) {
		output := escape(input)
		if !stringIsSafe(output) {
			t.Errorf("escape(%q) → %q", input, output)
		}
	}
	for _, input := range tests {
		check(input)
	}
	for b := 0; b < 256; b++ {
		// check one-byte string with each byte value 0–255
		check(string([]byte{byte(b)}))
		// check UTF-8 encoding of each character 0–255
		check(string(b))
	}
}

func TestGetManagedTransportVer(t *testing.T) {
	badTests := [...]string{
		"",
		"2",
	}
	goodTests := [...]struct {
		input, expected string
	}{
		{"1", "1"},
		{"1,1", "1"},
		{"1,2", "1"},
		{"2,1", "1"},
	}

	os.Clearenv()
	_, err := getManagedTransportVer()
	if err == nil {
		t.Errorf("empty environment unexpectedly succeeded")
	}

	for _, input := range badTests {
		os.Setenv("TOR_PT_MANAGED_TRANSPORT_VER", input)
		_, err := getManagedTransportVer()
		if err == nil {
			t.Errorf("%q unexpectedly succeeded", input)
		}
	}

	for _, test := range goodTests {
		os.Setenv("TOR_PT_MANAGED_TRANSPORT_VER", test.input)
		output, err := getManagedTransportVer()
		if err != nil {
			t.Errorf("%q unexpectedly returned an error: %s", test.input, err)
		}
		if output != test.expected {
			t.Errorf("%q → %q (expected %q)", test.input, output, test.expected)
		}
	}
}

// return true iff the two slices contain the same elements, possibly in a
// different order.
func stringSetsEqual(a, b []string) bool {
	ac := make([]string, len(a))
	bc := make([]string, len(b))
	sort.Strings(ac)
	sort.Strings(bc)
	if len(ac) != len(bc) {
		return false
	}
	for i := 0; i < len(ac); i++ {
		if ac[i] != bc[i] {
			return false
		}
	}
	return true
}

func TestGetClientTransports(t *testing.T) {
	tests := [...]struct {
		envvar      string
		methodNames []string
		expected    []string
	}{
		{
			"*",
			[]string{},
			[]string{},
		},
		{
			"*",
			[]string{"alpha", "beta", "gamma"},
			[]string{"alpha", "beta", "gamma"},
		},
		{
			"alpha,beta,gamma",
			[]string{"alpha", "beta", "gamma"},
			[]string{"alpha", "beta", "gamma"},
		},
		{
			"alpha,beta",
			[]string{"alpha", "beta", "gamma"},
			[]string{"alpha", "beta"},
		},
		{
			"alpha",
			[]string{"alpha", "beta", "gamma"},
			[]string{"alpha"},
		},
		{
			"alpha,beta",
			[]string{"alpha", "beta", "alpha"},
			[]string{"alpha", "beta"},
		},
		// my reading of pt-spec.txt says that "*" has special meaning
		// only when it is the entirety of the environment variable.
		{
			"alpha,*,gamma",
			[]string{"alpha", "beta", "gamma"},
			[]string{"alpha", "gamma"},
		},
		{
			"alpha",
			[]string{"beta"},
			[]string{},
		},
	}

	os.Clearenv()
	_, err := getClientTransports([]string{"alpha", "beta", "gamma"})
	if err == nil {
		t.Errorf("empty environment unexpectedly succeeded")
	}

	for _, test := range tests {
		os.Setenv("TOR_PT_CLIENT_TRANSPORTS", test.envvar)
		output, err := getClientTransports(test.methodNames)
		if err != nil {
			t.Errorf("%q unexpectedly returned an error: %s", test.envvar, err)
		}
		if !stringSetsEqual(output, test.expected) {
			t.Errorf("%q %q → %q (expected %q)", test.envvar, test.methodNames, output, test.expected)
		}
	}
}

func TestReadAuthCookie(t *testing.T) {
	badTests := [...][]byte{
		[]byte(""),
		// bad header
		[]byte("! Impostor ORPort Auth Cookie !\x0a0123456789ABCDEF0123456789ABCDEF"),
		// too short
		[]byte("! Extended ORPort Auth Cookie !\x0a0123456789ABCDEF0123456789ABCDE"),
		// too long
		[]byte("! Extended ORPort Auth Cookie !\x0a0123456789ABCDEF0123456789ABCDEFX"),
	}
	goodTests := [...][]byte{
		[]byte("! Extended ORPort Auth Cookie !\x0a0123456789ABCDEF0123456789ABCDEF"),
	}

	for _, input := range badTests {
		var buf bytes.Buffer
		buf.Write(input)
		_, err := readAuthCookie(&buf)
		if err == nil {
			t.Errorf("%q unexpectedly succeeded", input)
		}
	}

	for _, input := range goodTests {
		var buf bytes.Buffer
		buf.Write(input)
		cookie, err := readAuthCookie(&buf)
		if err != nil {
			t.Errorf("%q unexpectedly returned an error: %s", input, err)
		}
		if !bytes.Equal(cookie, input[32:64]) {
			t.Errorf("%q → %q (expected %q)", input, cookie, input[:32])
		}
	}
}
