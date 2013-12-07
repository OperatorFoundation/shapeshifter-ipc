// Package socks implements a SOCKS4a server sufficient for a Tor client
// transport plugin.
//
// 	ln, err := socks.Listen("tcp", ":3128")
// 	if err != nil {
// 		return err
// 	}
// 	conn, err := ln.AcceptSocks()
// 	if err != nil {
// 		return err
// 	}
// 	defer conn.Close()
// 	remote, err := net.Dial("tcp", local.Req.Target)
// 	if err != nil {
// 		local.Reject()
// 		return err
// 	}
// 	err = local.Grant(remote.RemoteAddr().(*net.TCPAddr))
// 	if err != nil {
// 		return err
// 	}
//
// http://ftp.icm.edu.pl/packages/socks/socks4/SOCKS4.protocol
package socks

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"net"
)

const (
	socksVersion         = 0x04
	socksCmdConnect      = 0x01
	socksResponseVersion = 0x00
	socksRequestGranted  = 0x5a
	socksRequestRejected = 0x5b
)

// Request describes a SOCKS request.
type Request struct {
	Username string
	Target   string
}

// Conn encapsulates a net.Conn and information associated with a SOCKS request.
type Conn struct {
	net.Conn
	Req Request
}

// Send a message to the proxy client that access to the given address is
// granted.
func (conn *Conn) Grant(addr *net.TCPAddr) error {
	return sendSocks4aResponseGranted(conn, addr)
}

// Send a message to the proxy client that access was rejected or failed.
func (conn *Conn) Reject() error {
	return sendSocks4aResponseRejected(conn)
}

// Listener wraps a net.Listener in order to read a SOCKS request on Accept.
type Listener struct {
	net.Listener
}

// Open a net.Listener according to network and laddr, and return it as a
// Listener.
func Listen(network, laddr string) (*Listener, error) {
	ln, err := net.Listen(network, laddr)
	if err != nil {
		return nil, err
	}
	return NewListener(ln), nil
}

// Create a new Listener wrapping the given net.Listener.
func NewListener(ln net.Listener) *Listener {
	return &Listener{ln}
}

// Accept is the same as AcceptSocks, except that it returns a generic net.Conn.
// It is present for the sake of satisfying the net.Listener interface.
func (ln *Listener) Accept() (net.Conn, error) {
	return ln.AcceptSocks()
}

// Call Accept on the wrapped net.Listener, do SOCKS negotiation, and return a
// Conn. After accepting, you must call either conn.Grant or conn.Reject
// (presumably after trying to connect to conn.Req.Target).
func (ln *Listener) AcceptSocks() (*Conn, error) {
	c, err := ln.Listener.Accept()
	if err != nil {
		return nil, err
	}
	conn := new(Conn)
	conn.Conn = c
	conn.Req, err = readSocks4aConnect(conn)
	if err != nil {
		conn.Close()
		return nil, err
	}
	return conn, nil
}

// Read a SOCKS4a connect request. Returns a Request.
func readSocks4aConnect(s io.Reader) (req Request, err error) {
	r := bufio.NewReader(s)

	var h [8]byte
	_, err = io.ReadFull(r, h[:])
	if err != nil {
		return
	}
	if h[0] != socksVersion {
		err = errors.New(fmt.Sprintf("SOCKS header had version 0x%02x, not 0x%02x", h[0], socksVersion))
		return
	}
	if h[1] != socksCmdConnect {
		err = errors.New(fmt.Sprintf("SOCKS header had command 0x%02x, not 0x%02x", h[1], socksCmdConnect))
		return
	}

	var usernameBytes []byte
	usernameBytes, err = r.ReadBytes('\x00')
	if err != nil {
		return
	}
	req.Username = string(usernameBytes[:len(usernameBytes)-1])

	var port int
	var host string

	port = int(h[2])<<8 | int(h[3])<<0
	if h[4] == 0 && h[5] == 0 && h[6] == 0 && h[7] != 0 {
		var hostBytes []byte
		hostBytes, err = r.ReadBytes('\x00')
		if err != nil {
			return
		}
		host = string(hostBytes[:len(hostBytes)-1])
	} else {
		host = net.IPv4(h[4], h[5], h[6], h[7]).String()
	}

	if r.Buffered() != 0 {
		err = errors.New(fmt.Sprintf("%d bytes left after SOCKS header", r.Buffered()))
		return
	}

	req.Target = fmt.Sprintf("%s:%d", host, port)
	return
}

// Send a SOCKS4a response with the given code and address.
func sendSocks4aResponse(w io.Writer, code byte, addr *net.TCPAddr) error {
	var resp [8]byte
	resp[0] = socksResponseVersion
	resp[1] = code
	resp[2] = byte((addr.Port >> 8) & 0xff)
	resp[3] = byte((addr.Port >> 0) & 0xff)
	resp[4] = addr.IP[0]
	resp[5] = addr.IP[1]
	resp[6] = addr.IP[2]
	resp[7] = addr.IP[3]
	_, err := w.Write(resp[:])
	return err
}

var emptyAddr = net.TCPAddr{IP: net.IPv4(0, 0, 0, 0), Port: 0}

// Send a SOCKS4a response code 0x5a.
func sendSocks4aResponseGranted(w io.Writer, addr *net.TCPAddr) error {
	return sendSocks4aResponse(w, socksRequestGranted, addr)
}

// Send a SOCKS4a response code 0x5b (with an all-zero address).
func sendSocks4aResponseRejected(w io.Writer) error {
	return sendSocks4aResponse(w, socksRequestRejected, &emptyAddr)
}
