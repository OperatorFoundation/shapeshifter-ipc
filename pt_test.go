package pt

import (
	"bytes"
	"net"
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
			t.Errorf("TOR_PT_MANAGED_TRANSPORT_VER=%q unexpectedly succeeded", input)
		}
	}

	for _, test := range goodTests {
		os.Setenv("TOR_PT_MANAGED_TRANSPORT_VER", test.input)
		output, err := getManagedTransportVer()
		if err != nil {
			t.Errorf("TOR_PT_MANAGED_TRANSPORT_VER=%q unexpectedly returned an error: %s", test.input, err)
		}
		if output != test.expected {
			t.Errorf("TOR_PT_MANAGED_TRANSPORT_VER=%q → %q (expected %q)", test.input, output, test.expected)
		}
	}
}

// return true iff the two slices contain the same elements, possibly in a
// different order.
func stringSetsEqual(a, b []string) bool {
	ac := make([]string, len(a))
	bc := make([]string, len(b))
	copy(ac, a)
	copy(bc, b)
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

func tcpAddrsEqual(a, b *net.TCPAddr) bool {
	return a.IP.Equal(b.IP) && a.Port == b.Port
}

func TestGetClientTransports(t *testing.T) {
	tests := [...]struct {
		ptServerClientTransports string
		methodNames              []string
		expected                 []string
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
		os.Setenv("TOR_PT_CLIENT_TRANSPORTS", test.ptServerClientTransports)
		output, err := getClientTransports(test.methodNames)
		if err != nil {
			t.Errorf("TOR_PT_CLIENT_TRANSPORTS=%q unexpectedly returned an error: %s",
				test.ptServerClientTransports, err)
		}
		if !stringSetsEqual(output, test.expected) {
			t.Errorf("TOR_PT_CLIENT_TRANSPORTS=%q %q → %q (expected %q)",
				test.ptServerClientTransports, test.methodNames, output, test.expected)
		}
	}
}

func TestResolveAddr(t *testing.T) {
	badTests := [...]string{
		"",
		"1.2.3.4",
		"1.2.3.4:",
		"9999",
		":9999",
		"[1:2::3:4]",
		"[1:2::3:4]:",
		"[1::2::3:4]",
		"1:2::3:4::9999",
		"1:2:3:4::9999",
		"localhost:9999",
		"[localhost]:9999",
	}
	goodTests := [...]struct {
		input    string
		expected net.TCPAddr
	}{
		{"1.2.3.4:9999", net.TCPAddr{IP: net.ParseIP("1.2.3.4"), Port: 9999}},
		{"[1:2::3:4]:9999", net.TCPAddr{IP: net.ParseIP("1:2::3:4"), Port: 9999}},
		{"1:2::3:4:9999", net.TCPAddr{IP: net.ParseIP("1:2::3:4"), Port: 9999}},
	}

	for _, input := range badTests {
		output, err := resolveAddr(input)
		if err == nil {
			t.Errorf("%q unexpectedly succeeded: %q", input, output)
		}
	}

	for _, test := range goodTests {
		output, err := resolveAddr(test.input)
		if err != nil {
			t.Errorf("%q unexpectedly returned an error: %s", test.input, err)
		}
		if !tcpAddrsEqual(output, &test.expected) {
			t.Errorf("%q → %q (expected %q)", test.input, output, test.expected)
		}
	}
}

func bindaddrSliceContains(s []Bindaddr, v Bindaddr) bool {
	for _, sv := range s {
		if sv.MethodName == v.MethodName && tcpAddrsEqual(sv.Addr, v.Addr) {
			return true
		}
	}
	return false
}

func bindaddrSetsEqual(a, b []Bindaddr) bool {
	for _, v := range a {
		if !bindaddrSliceContains(b, v) {
			return false
		}
	}
	for _, v := range b {
		if !bindaddrSliceContains(a, v) {
			return false
		}
	}
	return true
}

func TestGetServerBindaddrs(t *testing.T) {
	badTests := [...]struct {
		ptServerBindaddr   string
		ptServerTransports string
		methodNames        []string
	}{
		{
			"xxx",
			"xxx",
			[]string{},
		},
		{
			"alpha-1.2.3.4",
			"alpha",
			[]string{"alpha", "beta", "gamma"},
		},
	}
	goodTests := [...]struct {
		ptServerBindaddr   string
		ptServerTransports string
		methodNames        []string
		expected           []Bindaddr
	}{
		{
			"alpha-1.2.3.4:1111,beta-[1:2::3:4]:2222",
			"alpha,beta,gamma",
			[]string{"alpha", "beta"},
			[]Bindaddr{
				{"alpha", &net.TCPAddr{IP: net.ParseIP("1.2.3.4"), Port: 1111}},
				{"beta", &net.TCPAddr{IP: net.ParseIP("1:2::3:4"), Port: 2222}},
			},
		},
		{
			"alpha-1.2.3.4:1111",
			"xxx",
			[]string{"alpha", "beta", "gamma"},
			[]Bindaddr{},
		},
		{
			"alpha-1.2.3.4:1111",
			"alpha,beta,gamma",
			[]string{},
			[]Bindaddr{},
		},
		{
			"alpha-1.2.3.4:1111,beta-[1:2::3:4]:2222",
			"*",
			[]string{"alpha", "beta"},
			[]Bindaddr{
				{"alpha", &net.TCPAddr{IP: net.ParseIP("1.2.3.4"), Port: 1111}},
				{"beta", &net.TCPAddr{IP: net.ParseIP("1:2::3:4"), Port: 2222}},
			},
		},
	}

	os.Clearenv()
	_, err := getServerBindaddrs([]string{"alpha", "beta", "gamma"})
	if err == nil {
		t.Errorf("empty environment unexpectedly succeeded")
	}

	for _, test := range badTests {
		os.Setenv("TOR_PT_SERVER_BINDADDR", test.ptServerBindaddr)
		os.Setenv("TOR_PT_SERVER_TRANSPORTS", test.ptServerTransports)
		_, err := getServerBindaddrs(test.methodNames)
		if err == nil {
			t.Errorf("TOR_PT_SERVER_BINDADDR=%q TOR_PT_SERVER_TRANSPORTS=%q %q unexpectedly succeeded",
				test.ptServerBindaddr, test.ptServerTransports, test.methodNames)
		}
	}

	for _, test := range goodTests {
		os.Setenv("TOR_PT_SERVER_BINDADDR", test.ptServerBindaddr)
		os.Setenv("TOR_PT_SERVER_TRANSPORTS", test.ptServerTransports)
		output, err := getServerBindaddrs(test.methodNames)
		if err != nil {
			t.Errorf("TOR_PT_SERVER_BINDADDR=%q TOR_PT_SERVER_TRANSPORTS=%q %q unexpectedly returned an error: %s",
				test.ptServerBindaddr, test.ptServerTransports, test.methodNames, err)
		}
		if !bindaddrSetsEqual(output, test.expected) {
			t.Errorf("TOR_PT_SERVER_BINDADDR=%q TOR_PT_SERVER_TRANSPORTS=%q %q → %q (expected %q)",
				test.ptServerBindaddr, test.ptServerTransports, test.methodNames, output, test.expected)
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
