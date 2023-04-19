package main

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"os"
)

const (
	BUFFER_SIZE            = 8192
	HTTPS_HELO_SIZE        = 256 // TODO: correct HTTPS HELO packet size
	HTTPS_HELO_SPLIT_SIZE  = 64
	HTTP_HEADER_SPLIT_SIZE = 4
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
	buffEndIdx := bytes.Index(buffer, []byte("\r\n\r\n"))
	if buffEndIdx < 0 {
		return ErrHttpHeaderInval
	}

	// update buffer offset
	buffer = buffer[:buffEndIdx]

	reqEnd := bytes.Index(buffer, []byte("\r\n"))
	if reqEnd < 0 {
		return ErrHttpHeaderInval
	}

	// finding method type
	methodEndIdx := bytes.Index(buffer[:reqEnd], []byte(" "))
	if methodEndIdx < 0 {
		return ErrHttpHeaderInval
	}

	method := bytes.ToUpper(bytes.Trim(buffer[:methodEndIdx], " "))
	if bytes.Equal(method, []byte("CONNECT")) {
		self.hasConnectMethod = true
	} else {
		self.hasConnectMethod = false
	}

	// update buffer offset
	buffer = buffer[reqEnd+2:]

	// finding host:port
	keyHost := []byte("Host:")
	valHostIdx := bytes.Index(buffer, keyHost)
	if valHostIdx < 0 {
		return ErrHttpHeaderInval
	}

	valHost := buffer[valHostIdx+len(keyHost):]
	valHostEndIdx := bytes.Index(valHost, []byte("\r\n"))
	if valHostEndIdx < 0 {
		valHostEndIdx = len(valHost)
	}

	hostPort := bytes.Trim(valHost[:valHostEndIdx], " ")
	hostPortStr := string(hostPort)

	// check ip version
	ipv6Idx := bytes.Index(hostPort, []byte("]"))
	if ipv6Idx < 0 {
		// IPv4
		if !bytes.Contains(hostPort, []byte(":")) {
			hostPortStr = self.addPort(hostPortStr)
		}
	} else {
		// IPv6
		if bytes.Index(hostPort[ipv6Idx:], []byte(":")) == -1 {
			hostPortStr = self.addPort(hostPortStr)
		}
	}

	self.hostPort = hostPortStr
	return nil
}

func (self *httpHeader) addPort(buffer string) string {
	if self.hasConnectMethod {
		buffer += ":443"
	} else {
		buffer += ":80"
	}

	return buffer
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

	log.Printf("%s -> %s\n", rAddr, header.hostPort)
	if header.hasConnectMethod {
		if err = self.handleHTTPS(&header, buffer[:]); err != nil {
			log.Printf("Error: handleHTTPS: %s -> %s: %s\n", rAddr,
				header.hostPort, err)
		}
	} else {
		if err = self.handleHTTP(&header, buffer[:recvd]); err != nil {
			log.Printf("Error: handleHTTPS: %s -> %s: %s\n", rAddr,
				header.hostPort, err)
		}
	}
}

func (self *client) handleHTTP(header *httpHeader, buffer []byte) error {
	// send the first bytes
	err := self.splitRequestBytes(buffer, HTTP_HEADER_SPLIT_SIZE)
	if err != nil {
		return err
	}

	// forward all traffics
	self.forwardAll()
	return nil
}

func (self *client) handleHTTPS(header *httpHeader, buffer []byte) error {
	// send established tunneling status
	resp := []byte("HTTP/1.1 200 OK\r\n\r\n")
	if err := writeAllBytes(self.source, resp); err != nil {
		return err
	}

	// Read HTTPS HELO packet
	rd, err := self.source.Read(buffer[:HTTPS_HELO_SIZE])
	if err != nil {
		return err
	}

	// "intercepts" and forward HTTPS HELO packet
	err = self.splitRequestBytes(buffer[:rd], HTTPS_HELO_SPLIT_SIZE)
	if err != nil {
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

func (self *client) splitRequestBytes(buffer []byte, splitSize int) error {
	bLen := len(buffer)
	if splitSize > bLen {
		splitSize = bLen
	}

	for snd := 0; snd < bLen; {
		s, err := self.target.Write(buffer[snd:splitSize])
		if err != nil {
			return err
		}

		if s == 0 {
			break
		}

		snd += s
		splitSize += snd
		if splitSize > bLen {
			splitSize -= (splitSize - bLen)
		}
	}

	return nil
}

func writeAllBytes(conn net.Conn, buffer []byte) error {
	for sent := 0; sent < len(buffer); {
		w, err := conn.Write(buffer[sent:])
		if err != nil {
			return err
		}

		sent += w
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
