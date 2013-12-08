// Package pt implements the Tor pluggable transports specification.
//
// Sample client usage:
// 	var ptInfo pt.ClientInfo
// 	var err error
// 	ptInfo, err = pt.ClientSetup([]string{"foo"})
// 	if err != nil {
// 		os.Exit(1)
// 	}
// 	for _, methodName := range ptInfo.MethodNames {
// 		ln, err := pt.ListenSocks("tcp", "127.0.0.1:0")
// 		if err != nil {
// 			pt.CmethodError(methodName, err.Error())
// 			continue
// 		}
// 		go acceptLoop(ln)
// 		pt.Cmethod(methodName, "socks4", ln.Addr())
// 	}
// 	pt.CmethodsDone()
//
// Sample server usage:
// 	func handler(conn net.Conn) {
// 		or, err := pt.ConnectOr(&ptInfo, conn.RemoteAddr(), "foo")
// 		if err != nil {
// 			return
// 		}
// 		// do something with or and conn
// 	}
// 	...
// 	var ptInfo pt.ServerInfo
// 	var err error
// 	ptInfo, err = pt.ServerSetup([]string{"foo"})
// 	if err != nil {
// 		os.Exit(1)
// 	}
// 	for _, bindaddr := range ptInfo.Bindaddrs {
// 		ln, err := startListener(bindaddr.Addr, bindaddr.MethodName)
// 		if err != nil {
// 			pt.SmethodError(bindaddr.MethodName, err.Error())
// 			continue
// 		}
// 		pt.Smethod(bindaddr.MethodName, ln.Addr())
// 	}
// 	pt.SmethodsDone()
//
// Tor pluggable transports specification:
// https://gitweb.torproject.org/torspec.git/blob/HEAD:/pt-spec.txt.
//
// Extended ORPort Authentication:
// https://gitweb.torproject.org/torspec.git/blob/HEAD:/proposals/217-ext-orport-auth.txt.
//
// The package implements a SOCKS4a server sufficient for a Tor client transport
// plugin.
//
// http://ftp.icm.edu.pl/packages/socks/socks4/SOCKS4.protocol
package pt

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"time"
)

// This type wraps a Write method and calls Sync after each Write.
type syncWriter struct {
	*os.File
}

// Call File.Write and then Sync. An error is returned if either operation
// returns an error.
func (w syncWriter) Write(p []byte) (n int, err error) {
	n, err = w.File.Write(p)
	if err != nil {
		return
	}
	err = w.Sync()
	return
}

// Writer to which pluggable-transport negotiation messages are written. It
// defaults to a Writer that writes to os.Stdout and calls Sync after each
// write.
//
// You may, for example, log pluggable-transport messages by defining a Writer
// that logs what is written to it:
// 	type logWriteWrapper struct {
// 		io.Writer
// 	}
//
// 	func (w logWriteWrapper) Write(p []byte) (int, error) {
// 		log.Print(string(p))
// 		return w.Writer.Write(p)
// 	}
// and then redefining Stdout:
// 	pt.Stdout = logWriteWrapper{pt.Stdout}
var Stdout io.Writer = syncWriter{os.Stdout}

// Represents an error that can happen during negotiation, for example
// ENV-ERROR. When an error occurs, we print it to stdout and also pass it up
// the return chain.
type ptErr struct {
	Keyword string
	Args    []string
}

// Implements the error interface.
func (err *ptErr) Error() string {
	return formatLine(err.Keyword, err.Args...)
}

func getenv(key string) string {
	return os.Getenv(key)
}

// Returns an ENV-ERROR if the environment variable isn't set.
func getenvRequired(key string) (string, error) {
	value := os.Getenv(key)
	if value == "" {
		return "", EnvError(fmt.Sprintf("no %s environment variable", key))
	}
	return value, nil
}

// Escape a string so it contains no byte values over 127 and doesn't contain
// any of the characters '\x00' or '\n'.
func escape(s string) string {
	var buf bytes.Buffer
	for _, b := range []byte(s) {
		if b == '\n' {
			buf.WriteString("\\n")
		} else if b == '\\' {
			buf.WriteString("\\\\")
		} else if 0 < b && b < 128 {
			buf.WriteByte(b)
		} else {
			fmt.Fprintf(&buf, "\\x%02x", b)
		}
	}
	return buf.String()
}

func formatLine(keyword string, v ...string) string {
	var buf bytes.Buffer
	buf.WriteString(keyword)
	for _, x := range v {
		buf.WriteString(" " + escape(x))
	}
	return buf.String()
}

// Print a pluggable transports protocol line to Stdout. The line consists of an
// unescaped keyword, followed by any number of escaped strings.
func Line(keyword string, v ...string) {
	fmt.Fprintln(Stdout, formatLine(keyword, v...))
}

// Emit and return the given error as a ptErr.
func doError(keyword string, v ...string) *ptErr {
	Line(keyword, v...)
	return &ptErr{keyword, v}
}

// Emit an ENV-ERROR line with explanation text. Returns a representation of the
// error.
func EnvError(msg string) error {
	return doError("ENV-ERROR", msg)
}

// Emit a VERSION-ERROR line with explanation text. Returns a representation of
// the error.
func VersionError(msg string) error {
	return doError("VERSION-ERROR", msg)
}

// Emit a CMETHOD-ERROR line with explanation text. Returns a representation of
// the error.
func CmethodError(methodName, msg string) error {
	return doError("CMETHOD-ERROR", methodName, msg)
}

// Emit an SMETHOD-ERROR line with explanation text. Returns a representation of
// the error.
func SmethodError(methodName, msg string) error {
	return doError("SMETHOD-ERROR", methodName, msg)
}

// Emit a CMETHOD line. socks must be "socks4" or "socks5". Call this once for
// each listening client SOCKS port.
func Cmethod(name string, socks string, addr net.Addr) {
	Line("CMETHOD", name, socks, addr.String())
}

// Emit a CMETHODS DONE line. Call this after opening all client listeners.
func CmethodsDone() {
	Line("CMETHODS", "DONE")
}

// Emit an SMETHOD line. Call this once for each listening server port.
func Smethod(name string, addr net.Addr) {
	Line("SMETHOD", name, addr.String())
}

// Emit an SMETHODS DONE line. Call this after opening all server listeners.
func SmethodsDone() {
	Line("SMETHODS", "DONE")
}

// Get a pluggable transports version offered by Tor and understood by us, if
// any. The only version we understand is "1". This function reads the
// environment variable TOR_PT_MANAGED_TRANSPORT_VER.
func getManagedTransportVer() (string, error) {
	const transportVersion = "1"
	managedTransportVer, err := getenvRequired("TOR_PT_MANAGED_TRANSPORT_VER")
	if err != nil {
		return "", err
	}
	for _, offered := range strings.Split(managedTransportVer, ",") {
		if offered == transportVersion {
			return offered, nil
		}
	}
	return "", VersionError("no-version")
}

// Get the intersection of the method names offered by Tor and those in
// methodNames. This function reads the environment variable
// TOR_PT_CLIENT_TRANSPORTS.
func getClientTransports(methodNames []string) ([]string, error) {
	clientTransports, err := getenvRequired("TOR_PT_CLIENT_TRANSPORTS")
	if err != nil {
		return nil, err
	}
	if clientTransports == "*" {
		return methodNames, nil
	}
	result := make([]string, 0)
	for _, requested := range strings.Split(clientTransports, ",") {
		for _, methodName := range methodNames {
			if requested == methodName {
				result = append(result, methodName)
				break
			}
		}
	}
	return result, nil
}

// This structure is returned by ClientSetup. It consists of a list of method
// names.
type ClientInfo struct {
	MethodNames []string
}

// Check the client pluggable transports environments, emitting an error message
// and returning a non-nil error if any error is encountered. Returns a
// ClientInfo struct.
func ClientSetup(methodNames []string) (ClientInfo, error) {
	var info ClientInfo

	ver, err := getManagedTransportVer()
	if err != nil {
		return info, err
	}
	Line("VERSION", ver)

	info.MethodNames, err = getClientTransports(methodNames)
	if err != nil {
		return info, err
	}

	return info, nil
}

// A combination of a method name and an address, as extracted from
// TOR_PT_SERVER_BINDADDR.
type Bindaddr struct {
	MethodName string
	Addr       *net.TCPAddr
}

// Resolve an address string into a net.TCPAddr. We are a bit more strict than
// net.ResolveTCPAddr; we don't allow an empty host or port, and the host part
// must be a literal IP address.
func resolveAddr(addrStr string) (*net.TCPAddr, error) {
	ipStr, portStr, err := net.SplitHostPort(addrStr)
	if err != nil {
		// Before the fixing of bug #7011, tor doesn't put brackets around IPv6
		// addresses. Split after the last colon, assuming it is a port
		// separator, and try adding the brackets.
		parts := strings.Split(addrStr, ":")
		if len(parts) <= 2 {
			return nil, err
		}
		addrStr := "[" + strings.Join(parts[:len(parts)-1], ":") + "]:" + parts[len(parts)-1]
		ipStr, portStr, err = net.SplitHostPort(addrStr)
	}
	if err != nil {
		return nil, err
	}
	if ipStr == "" {
		return nil, net.InvalidAddrError(fmt.Sprintf("address string %q lacks a host part", addrStr))
	}
	if portStr == "" {
		return nil, net.InvalidAddrError(fmt.Sprintf("address string %q lacks a port part", addrStr))
	}
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return nil, net.InvalidAddrError(fmt.Sprintf("not an IP string: %q", ipStr))
	}
	port, err := net.LookupPort("tcp", portStr)
	if err != nil {
		return nil, err
	}
	return &net.TCPAddr{IP: ip, Port: port}, nil
}

// Return a new slice, the members of which are those members of addrs having a
// MethodName in methodNames.
func filterBindaddrs(addrs []Bindaddr, methodNames []string) []Bindaddr {
	var result []Bindaddr

	for _, ba := range addrs {
		for _, methodName := range methodNames {
			if ba.MethodName == methodName {
				result = append(result, ba)
				break
			}
		}
	}

	return result
}

// Return an array of Bindaddrs, those being the contents of
// TOR_PT_SERVER_BINDADDR, with keys filtered by TOR_PT_SERVER_TRANSPORTS, and
// further filtered by the methods in methodNames.
func getServerBindaddrs(methodNames []string) ([]Bindaddr, error) {
	var result []Bindaddr

	// Get the list of all requested bindaddrs.
	serverBindaddr, err := getenvRequired("TOR_PT_SERVER_BINDADDR")
	if err != nil {
		return nil, err
	}
	for _, spec := range strings.Split(serverBindaddr, ",") {
		var bindaddr Bindaddr

		parts := strings.SplitN(spec, "-", 2)
		if len(parts) != 2 {
			return nil, EnvError(fmt.Sprintf("TOR_PT_SERVER_BINDADDR: %q: doesn't contain \"-\"", spec))
		}
		bindaddr.MethodName = parts[0]
		addr, err := resolveAddr(parts[1])
		if err != nil {
			return nil, EnvError(fmt.Sprintf("TOR_PT_SERVER_BINDADDR: %q: %s", spec, err.Error()))
		}
		bindaddr.Addr = addr
		result = append(result, bindaddr)
	}

	// Filter by TOR_PT_SERVER_TRANSPORTS.
	serverTransports, err := getenvRequired("TOR_PT_SERVER_TRANSPORTS")
	if err != nil {
		return nil, err
	}
	if serverTransports != "*" {
		result = filterBindaddrs(result, strings.Split(serverTransports, ","))
	}

	// Finally filter by what we understand.
	result = filterBindaddrs(result, methodNames)

	return result, nil
}

func readAuthCookie(f io.Reader) ([]byte, error) {
	authCookieHeader := []byte("! Extended ORPort Auth Cookie !\x0a")
	buf := make([]byte, 64)

	n, err := io.ReadFull(f, buf)
	if err != nil {
		return nil, err
	}
	// Check that the file ends here.
	n, err = f.Read(make([]byte, 1))
	if n != 0 {
		return nil, errors.New(fmt.Sprintf("file is longer than 64 bytes"))
	} else if err != io.EOF {
		return nil, errors.New(fmt.Sprintf("did not find EOF at end of file"))
	}
	header := buf[0:32]
	cookie := buf[32:64]
	if subtle.ConstantTimeCompare(header, authCookieHeader) != 1 {
		return nil, errors.New(fmt.Sprintf("missing auth cookie header"))
	}

	return cookie, nil
}

// Read and validate the contents of an auth cookie file. Returns the 32-byte
// cookie. See section 4.2.1.2 of pt-spec.txt.
func readAuthCookieFile(filename string) ([]byte, error) {
	f, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	return readAuthCookie(f)
}

// This structure is returned by ServerSetup. It consists of a list of
// Bindaddrs, an address for the ORPort, an address for the extended ORPort (if
// any), and an authentication cookie (if any).
type ServerInfo struct {
	Bindaddrs      []Bindaddr
	OrAddr         *net.TCPAddr
	ExtendedOrAddr *net.TCPAddr
	AuthCookie     []byte
}

// Check the server pluggable transports environments, emitting an error message
// and returning a non-nil error if any error is encountered. Resolves the
// various requested bind addresses, the server ORPort and extended ORPort, and
// reads the auth cookie file. Returns a ServerInfo struct.
func ServerSetup(methodNames []string) (ServerInfo, error) {
	var info ServerInfo

	ver, err := getManagedTransportVer()
	if err != nil {
		return info, err
	}
	Line("VERSION", ver)

	orPort, err := getenvRequired("TOR_PT_ORPORT")
	if err != nil {
		return info, err
	}
	info.OrAddr, err = resolveAddr(orPort)
	if err != nil {
		return info, EnvError(fmt.Sprintf("cannot resolve TOR_PT_ORPORT %q: %s", orPort, err.Error()))
	}

	info.Bindaddrs, err = getServerBindaddrs(methodNames)
	if err != nil {
		return info, err
	}

	var extendedOrPort = getenv("TOR_PT_EXTENDED_SERVER_PORT")
	if extendedOrPort != "" {
		info.ExtendedOrAddr, err = resolveAddr(extendedOrPort)
		if err != nil {
			return info, EnvError(fmt.Sprintf("cannot resolve TOR_PT_EXTENDED_SERVER_PORT %q: %s", extendedOrPort, err.Error()))
		}
	}

	var authCookieFilename = getenv("TOR_PT_AUTH_COOKIE_FILE")
	if authCookieFilename != "" {
		info.AuthCookie, err = readAuthCookieFile(authCookieFilename)
		if err != nil {
			return info, EnvError(fmt.Sprintf("error reading TOR_PT_AUTH_COOKIE_FILE %q: %s", authCookieFilename, err.Error()))
		}
	}

	return info, nil
}

// See 217-ext-orport-auth.txt section 4.2.1.3.
func computeServerHash(authCookie, clientNonce, serverNonce []byte) []byte {
	h := hmac.New(sha256.New, authCookie)
	io.WriteString(h, "ExtORPort authentication server-to-client hash")
	h.Write(clientNonce)
	h.Write(serverNonce)
	return h.Sum([]byte{})
}

// See 217-ext-orport-auth.txt section 4.2.1.3.
func computeClientHash(authCookie, clientNonce, serverNonce []byte) []byte {
	h := hmac.New(sha256.New, authCookie)
	io.WriteString(h, "ExtORPort authentication client-to-server hash")
	h.Write(clientNonce)
	h.Write(serverNonce)
	return h.Sum([]byte{})
}

func extOrPortAuthenticate(s io.ReadWriter, info *ServerInfo) error {
	// Read auth types. 217-ext-orport-auth.txt section 4.1.
	var authTypes [256]bool
	var count int
	for count = 0; count < 256; count++ {
		buf := make([]byte, 1)
		_, err := io.ReadFull(s, buf)
		if err != nil {
			return err
		}
		b := buf[0]
		if b == 0 {
			break
		}
		authTypes[b] = true
	}
	if count >= 256 {
		return errors.New(fmt.Sprintf("read 256 auth types without seeing \\x00"))
	}

	// We support only type 1, SAFE_COOKIE.
	if !authTypes[1] {
		return errors.New(fmt.Sprintf("server didn't offer auth type 1"))
	}
	_, err := s.Write([]byte{1})
	if err != nil {
		return err
	}

	clientNonce := make([]byte, 32)
	clientHash := make([]byte, 32)
	serverNonce := make([]byte, 32)
	serverHash := make([]byte, 32)

	_, err = io.ReadFull(rand.Reader, clientNonce)
	if err != nil {
		return err
	}
	_, err = s.Write(clientNonce)
	if err != nil {
		return err
	}

	_, err = io.ReadFull(s, serverHash)
	if err != nil {
		return err
	}
	_, err = io.ReadFull(s, serverNonce)
	if err != nil {
		return err
	}

	expectedServerHash := computeServerHash(info.AuthCookie, clientNonce, serverNonce)
	if subtle.ConstantTimeCompare(serverHash, expectedServerHash) != 1 {
		return errors.New(fmt.Sprintf("mismatch in server hash"))
	}

	clientHash = computeClientHash(info.AuthCookie, clientNonce, serverNonce)
	_, err = s.Write(clientHash)
	if err != nil {
		return err
	}

	status := make([]byte, 1)
	_, err = io.ReadFull(s, status)
	if err != nil {
		return err
	}
	if status[0] != 1 {
		return errors.New(fmt.Sprintf("server rejected authentication"))
	}

	return nil
}

// See section 3.1 of 196-transport-control-ports.txt.
const (
	extOrCmdDone      = 0x0000
	extOrCmdUserAddr  = 0x0001
	extOrCmdTransport = 0x0002
	extOrCmdOkay      = 0x1000
	extOrCmdDeny      = 0x1001
)

func extOrPortSendCommand(s io.Writer, cmd uint16, body []byte) error {
	var buf bytes.Buffer
	if len(body) > 65535 {
		return errors.New(fmt.Sprintf("body length %d exceeds maximum of 65535", len(body)))
	}
	err := binary.Write(&buf, binary.BigEndian, cmd)
	if err != nil {
		return err
	}
	err = binary.Write(&buf, binary.BigEndian, uint16(len(body)))
	if err != nil {
		return err
	}
	err = binary.Write(&buf, binary.BigEndian, body)
	if err != nil {
		return err
	}
	_, err = s.Write(buf.Bytes())
	if err != nil {
		return err
	}

	return nil
}

// Send a USERADDR command on s. See section 3.1.2.1 of
// 196-transport-control-ports.txt.
func extOrPortSendUserAddr(s io.Writer, addr net.Addr) error {
	return extOrPortSendCommand(s, extOrCmdUserAddr, []byte(addr.String()))
}

// Send a TRANSPORT command on s. See section 3.1.2.2 of
// 196-transport-control-ports.txt.
func extOrPortSendTransport(s io.Writer, methodName string) error {
	return extOrPortSendCommand(s, extOrCmdTransport, []byte(methodName))
}

// Send a DONE command on s. See section 3.1 of 196-transport-control-ports.txt.
func extOrPortSendDone(s io.Writer) error {
	return extOrPortSendCommand(s, extOrCmdDone, []byte{})
}

func extOrPortRecvCommand(s io.Reader) (cmd uint16, body []byte, err error) {
	var bodyLen uint16
	data := make([]byte, 4)

	_, err = io.ReadFull(s, data)
	if err != nil {
		return
	}
	buf := bytes.NewBuffer(data)
	err = binary.Read(buf, binary.BigEndian, &cmd)
	if err != nil {
		return
	}
	err = binary.Read(buf, binary.BigEndian, &bodyLen)
	if err != nil {
		return
	}
	body = make([]byte, bodyLen)
	_, err = io.ReadFull(s, body)
	if err != nil {
		return
	}

	return cmd, body, err
}

// Send USERADDR and TRANSPORT commands followed by a DONE command. Wait for an
// OKAY or DENY response command from the server. Returns nil if and only if
// OKAY is received.
func extOrPortSetup(s io.ReadWriter, addr net.Addr, methodName string) error {
	var err error

	err = extOrPortSendUserAddr(s, addr)
	if err != nil {
		return err
	}
	err = extOrPortSendTransport(s, methodName)
	if err != nil {
		return err
	}
	err = extOrPortSendDone(s)
	if err != nil {
		return err
	}
	cmd, _, err := extOrPortRecvCommand(s)
	if err != nil {
		return err
	}
	if cmd == extOrCmdDeny {
		return errors.New("server returned DENY after our USERADDR and DONE")
	} else if cmd != extOrCmdOkay {
		return errors.New(fmt.Sprintf("server returned unknown command 0x%04x after our USERADDR and DONE", cmd))
	}

	return nil
}

// Connect to info.ExtendedOrAddr if defined, or else info.OrAddr, and return an
// open *net.TCPConn. If connecting to the extended OR port, extended OR port
// authentication à la 217-ext-orport-auth.txt is done before returning; an
// error is returned if authentication fails.
func ConnectOr(info *ServerInfo, addr net.Addr, methodName string) (*net.TCPConn, error) {
	if info.ExtendedOrAddr == nil {
		return net.DialTCP("tcp", nil, info.OrAddr)
	}

	s, err := net.DialTCP("tcp", nil, info.ExtendedOrAddr)
	if err != nil {
		return nil, err
	}
	s.SetDeadline(time.Now().Add(5 * time.Second))
	err = extOrPortAuthenticate(s, info)
	if err != nil {
		s.Close()
		return nil, err
	}
	err = extOrPortSetup(s, addr, methodName)
	if err != nil {
		s.Close()
		return nil, err
	}
	s.SetDeadline(time.Time{})

	return s, nil
}
