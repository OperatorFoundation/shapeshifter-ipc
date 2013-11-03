// Usage (in torrc):
//   BridgeRelay 1
//   ORPort 9001
//   ExtORPort 6669
//   ServerTransportPlugin dummy exec dummy-server

package main

import (
	"io"
	"net"
	"os"
	"os/signal"
	"sync"
	"syscall"
)

import "git.torproject.org/pluggable-transports/websocket.git/src/pt"

var ptInfo pt.ServerInfo

// When a connection handler starts, +1 is written to this channel; when it
// ends, -1 is written.
var handlerChan = make(chan int)

func copyLoop(a, b net.Conn) {
	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		io.Copy(b, a)
		wg.Done()
	}()
	go func() {
		io.Copy(a, b)
		wg.Done()
	}()

	wg.Wait()
}

func handleConnection(conn net.Conn) {
	handlerChan <- 1
	defer func() {
		handlerChan <- -1
	}()

	or, err := pt.ConnectOr(&ptInfo, conn, "dummy")
	if err != nil {
		return
	}
	copyLoop(conn, or)
}

func acceptLoop(ln net.Listener) error {
	for {
		conn, err := ln.Accept()
		if err != nil {
			return err
		}
		go handleConnection(conn)
	}
	return nil
}

func startListener(addr *net.TCPAddr) (net.Listener, error) {
	ln, err := net.ListenTCP("tcp", addr)
	if err != nil {
		return nil, err
	}
	go acceptLoop(ln)
	return ln, nil
}

func main() {
	var err error

	ptInfo, err = pt.ServerSetup([]string{"dummy"})
	if err != nil {
		os.Exit(1)
	}

	listeners := make([]net.Listener, 0)
	for _, bindAddr := range ptInfo.BindAddrs {
		ln, err := startListener(bindAddr.Addr)
		if err != nil {
			pt.SmethodError(bindAddr.MethodName, err.Error())
			continue
		}
		pt.Smethod(bindAddr.MethodName, ln.Addr())
		listeners = append(listeners, ln)
	}
	pt.SmethodsDone()

	var numHandlers int = 0
	var sig os.Signal
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	// wait for first signal
	sig = nil
	for sig == nil {
		select {
		case n := <-handlerChan:
			numHandlers += n
		case sig = <-sigChan:
		}
	}
	for _, ln := range listeners {
		ln.Close()
	}

	if sig == syscall.SIGTERM {
		return
	}

	// wait for second signal or no more handlers
	sig = nil
	for sig == nil && numHandlers != 0 {
		select {
		case n := <-handlerChan:
			numHandlers += n
		case sig = <-sigChan:
		}
	}
}
