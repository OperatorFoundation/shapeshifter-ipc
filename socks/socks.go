// Package socks implements a SOCKS4a server sufficient for a Tor client
// transport plugin.
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

type Request struct {
	Username string
	Target   string
}

// Read a SOCKS4a connect request, and call the given connect callback with the
// requested destination string. If the callback returns an error, sends a SOCKS
// request failed message. Otherwise, sends a SOCKS request granted message for
// the destination address returned by the callback.
// 	var remote net.Conn
// 	err := socks.AwaitSocks4aConnect(local.(*net.TCPConn), func(dest string) (*net.TCPAddr, error) {
// 		var err error
// 		// set remote in outer function environment
// 		remote, err = net.Dial("tcp", dest)
// 		if err != nil {
// 			return nil, err
// 		}
// 		return remote.RemoteAddr().(*net.TCPAddr), nil
// 	})
// 	if err != nil {
// 		return err
// 	}
// 	defer remote.Close()
// 	copyLoop(local, remote)
func AwaitSocks4aConnect(conn *net.TCPConn, connect func(string) (*net.TCPAddr, error)) error {
	req, err := readSocks4aConnect(conn)
	if err != nil {
		sendSocks4aResponseRejected(conn)
		return err
	}
	destAddr, err := connect(req.Target)
	if err != nil {
		sendSocks4aResponseRejected(conn)
		return err
	}
	sendSocks4aResponseGranted(conn, destAddr)
	return nil
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
