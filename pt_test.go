package pt

import "os"
import "testing"

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
			t.Errorf("%q unexpectedly returned an error", test.input)
		}
		if output != test.expected {
			t.Errorf("%q → %q (expected %q)", test.input, output, test.expected)
		}
	}
}
