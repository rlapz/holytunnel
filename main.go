package main

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"strings"
)

const (
	BUFFER_SIZE       = 8192
	HTTPS_HELO_SIZE   = 256 // TODO: correct HTTPS HELO packet size
	PACKET_SPLIT_SIZE = 64
)

/*
 * Http header
 */
type httpHeader struct {
	hostPort         string
	hasConnectMethod bool
}

var ErrHttpHeaderInval = errors.New("invalid http header")

func (self *httpHeader) parse(buffer []byte) error {
	if !bytes.Contains(buffer, []byte("\r\n\r\n")) {
		return ErrHttpHeaderInval
	}

	fb_end := bytes.Index(buffer, []byte("\r\n"))
	if fb_end < 0 {
		return ErrHttpHeaderInval
	}

	method_end := bytes.Index(buffer[:fb_end], []byte(" "))
	if method_end < 0 {
		return ErrHttpHeaderInval
	}

	header := bytes.Trim(buffer[:method_end], " ")
	if bytes.Equal(bytes.ToLower(header), []byte("connect")) {
		self.hasConnectMethod = true
	} else {
		self.hasConnectMethod = false
	}

	// finding host:port
	fb_host := bytes.Index(buffer[fb_end:], []byte("Host:"))
	if fb_host < 0 {
		return ErrHttpHeaderInval
	}

	// update buffer offset
	buffer = buffer[fb_host+fb_end:]

	fb_host_end := bytes.Index(buffer, []byte("\r\n"))
	if fb_host_end < 0 {
		return ErrHttpHeaderInval
	}

	// TODO: handle IPv6
	split := bytes.SplitN(buffer[:fb_host_end], []byte(":"), 2)
	if len(split) < 1 {
		return ErrHttpHeaderInval
	}

	hostPort := string(bytes.Trim(split[1], " "))
	if !strings.Contains(hostPort, ":") {
		if self.hasConnectMethod {
			hostPort += ":443"
		} else {
			hostPort += ":80"
		}
	}

	self.hostPort = hostPort
	return nil
}

/*
 * Server
 */
func runServer(address string) error {
	listener, err := net.Listen("tcp", address)
	if err != nil {
		return err
	}
	defer listener.Close()

	for {
		sourceConn, err := listener.Accept()
		if err != nil {
			log.Println("Cannot accept a new client:", err.Error())
			continue
		}

		go NewClient(sourceConn).handle()
	}
}

/*
 * Client
 */
type client struct {
	source net.Conn
	target net.Conn
}

func NewClient(conn net.Conn) *client {
	return &client{
		source: conn,
	}
}

func (self *client) handle() {
	defer self.source.Close()

	var rAddr = self.source.RemoteAddr()
	defer log.Println("closed connection:", rAddr)
	log.Println("new connection:", rAddr)

	var buffer [BUFFER_SIZE]byte
	var header httpHeader

	// TODO: handle big request header
	recvd, err := self.source.Read(buffer[:])
	if err != nil {
		if errors.Is(err, io.EOF) {
			return
		}

		log.Printf("Error: conn.Read: source: %s: %s\n", rAddr, err)
		return
	}

	if err = header.parse(buffer[:recvd]); err != nil {
		log.Printf("Error: header.parse: %s: %s\n", rAddr, err)
		return
	}

	// connect to the target host
	self.target, err = net.Dial("tcp", header.hostPort)
	if err != nil {
		log.Printf("Error: net.Dial: target: %s: %s\n", rAddr, err)
		return
	}
	defer self.target.Close()

	if header.hasConnectMethod {
		if err = self.handleHTTPS(&header, buffer[:]); err != nil {
			log.Printf("Error: handleHTTPS: %s: %s\n", rAddr, err)
		}

		return
	}

	if err = self.handleHTTP(&header, buffer[:recvd]); err != nil {
		log.Printf("Error: handleHTTP: %s: %s\n", rAddr, err)
	}
}

func (self *client) handleHTTP(header *httpHeader, buffer []byte) error {
	// send the first bytes
	if err := self.splitRequestBytes(buffer); err != nil {
		return err
	}

	// forward all traffics
	self.forwardAll()
	return nil
}

func (self *client) handleHTTPS(header *httpHeader, buffer []byte) error {
	// send established tunneling status
	resp := []byte("HTTP/1.1 200 OK\r\n\r\n")
	for sent := 0; sent < len(resp); {
		w, err := self.source.Write(resp[sent:])
		if err != nil {
			return err
		}

		sent += w
	}

	// Read HTTPS HELO packet
	rd, err := self.source.Read(buffer[:HTTPS_HELO_SIZE])
	if err != nil {
		return err
	}

	// "intercepts" and forward HTTPS HELO packet
	if err = self.splitRequestBytes(buffer[:rd]); err != nil {
		return err
	}

	// forward all traffics
	self.forwardAll()
	return nil
}

func (self *client) forwardAll() {
	go func() {
		io.Copy(self.target, self.source)
	}()

	io.Copy(self.source, self.target)
}

func (self *client) splitRequestBytes(buffer []byte) error {
	for snd := 0; snd < len(buffer); {
		s, err := self.target.Write(buffer[snd : snd+PACKET_SPLIT_SIZE])
		if err != nil {
			return err
		}

		snd += s
	}

	return nil
}

func main() {
	args := os.Args
	if len(args) != 2 {
		fmt.Println("Not enough argument!\nholytunnel [HOST:PORT]")
		os.Exit(1)
	}

	if err := runServer(args[1]); err != nil {
		log.Panicln(err)
	}
}
