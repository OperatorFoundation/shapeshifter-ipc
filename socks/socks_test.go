package socks

import (
	"bytes"
	"net"
	"testing"
)

func tcpAddrsEqual(a, b *net.TCPAddr) bool {
	return a.IP.Equal(b.IP) && a.Port == b.Port
}

func TestReadSocks4aConnect(t *testing.T) {
	badTests := [...][]byte{
		[]byte(""),
		// missing userid
		[]byte("\x04\x01\x12\x34\x01\x02\x03\x04"),
		// missing \x00 after userid
		[]byte("\x04\x01\x12\x34\x01\x02\x03\x04userid"),
		// missing hostname
		[]byte("\x04\x01\x12\x34\x00\x00\x00\x01userid\x00"),
		// missing \x00 after hostname
		[]byte("\x04\x01\x12\x34\x00\x00\x00\x01userid\x00hostname"),
		// BIND request
		[]byte("\x04\x02\x12\x34\x01\x02\x03\x04userid\x00"),
		// SOCKS5
		[]byte("\x05\x01\x00"),
	}
	ipTests := [...]struct {
		input  []byte
		userid string
		addr   net.TCPAddr
	}{
		{
			[]byte("\x04\x01\x12\x34\x01\x02\x03\x04userid\x00"),
			"userid", net.TCPAddr{IP: net.ParseIP("1.2.3.4"), Port: 0x1234},
		},
		{
			[]byte("\x04\x01\x12\x34\x01\x02\x03\x04\x00"),
			"", net.TCPAddr{IP: net.ParseIP("1.2.3.4"), Port: 0x1234},
		},
	}
	hostnameTests := [...]struct {
		input  []byte
		userid string
		target string
	}{
		{
			[]byte("\x04\x01\x12\x34\x00\x00\x00\x01userid\x00hostname\x00"),
			"userid", "hostname:4660",
		},
		{
			[]byte("\x04\x01\x12\x34\x00\x00\x00\x01\x00hostname\x00"),
			"", "hostname:4660",
		},
		{
			[]byte("\x04\x01\x12\x34\x00\x00\x00\x01userid\x00\x00"),
			"userid", ":4660",
		},
		{
			[]byte("\x04\x01\x12\x34\x00\x00\x00\x01\x00\x00"),
			"", ":4660",
		},
	}

	for _, input := range badTests {
		var buf bytes.Buffer
		buf.Write(input)
		_, err := readSocks4aConnect(&buf)
		if err == nil {
			t.Errorf("%q unexpectedly succeeded", input)
		}
	}

	for _, test := range ipTests {
		var buf bytes.Buffer
		buf.Write(test.input)
		req, err := readSocks4aConnect(&buf)
		if err != nil {
			t.Errorf("%q unexpectedly returned an error: %s", test.input, err)
		}
		if req.Username != test.userid {
			t.Errorf("%q → username %q (expected %q)", test.input,
				req.Username, test.userid)
		}
		addr, err := net.ResolveTCPAddr("tcp", req.Target)
		if err != nil {
			t.Error("%q → target %q: cannot resolve: %s", test.input,
				req.Target, err)
		}
		if !tcpAddrsEqual(addr, &test.addr) {
			t.Errorf("%q → address %s (expected %s)", test.input,
				req.Target, test.addr.String())
		}
	}

	for _, test := range hostnameTests {
		var buf bytes.Buffer
		buf.Write(test.input)
		req, err := readSocks4aConnect(&buf)
		if err != nil {
			t.Errorf("%q unexpectedly returned an error: %s", test.input, err)
		}
		if req.Username != test.userid {
			t.Errorf("%q → username %q (expected %q)", test.input,
				req.Username, test.userid)
		}
		if req.Target != test.target {
			t.Errorf("%q → target %q (expected %q)", test.input,
				req.Target, test.target)
		}
	}
}
