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
	HTTPS_HELO_SPLIT_SIZE  = 128
	HTTP_HEADER_SPLIT_SIZE = 4
)

/*
 * Http header
 */
var ErrHttpHeaderInval = errors.New("invalid http header")

type httpHeader struct {
	hostPort         string
	method           string
	hasConnectMethod bool
}

func (self *httpHeader) parse(buffer []byte) error {
	buffEndIdx := bytes.Index(buffer, []byte("\r\n\r\n"))
	if buffEndIdx < 0 {
		return ErrHttpHeaderInval
	}

	// update buffer offset
	buffer = buffer[:buffEndIdx]

	// finding method type
	methodEndIdx := bytes.Index(buffer, []byte(" "))
	if methodEndIdx < 0 {
		return ErrHttpHeaderInval
	}

	method := string(bytes.ToUpper(bytes.TrimSpace(buffer[:methodEndIdx])))
	if method == "CONNECT" {
		self.hasConnectMethod = true
	} else {
		self.hasConnectMethod = false
	}

	self.method = method

	// update buffer offset
	buffer = buffer[methodEndIdx+len(method):]

	// finding host:port
	// TODO: case insensitive comparison
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

	hostPort := bytes.TrimSpace(valHost[:valHostEndIdx])
	hostPortStr := string(hostPort)

	// check IPv6 version
	ipv6Idx := bytes.Index(hostPort, []byte("]"))
	if ipv6Idx != -1 {
		hostPort = hostPort[ipv6Idx:]
	}

	if !bytes.Contains(hostPort, []byte(":")) {
		hostPortStr = self.addPort(hostPortStr)
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
	source     net.Conn
	target     net.Conn
	httpHeader httpHeader
}

func NewClient(conn net.Conn) *client {
	return &client{
		source: conn,
	}
}

func (self *client) handle() {
	defer self.source.Close()

	var realBuffer [BUFFER_SIZE]byte
	var rAddr = self.source.RemoteAddr()
	var header = &self.httpHeader
	var buffer = realBuffer[:]

	// TODO: handle big request header
	recvd, err := self.source.Read(buffer)
	if err != nil {
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

	log.Printf("%s -> %s %s\n", rAddr, header.method, header.hostPort)
	if err = self.nextState(buffer, recvd); err != nil {
		log.Printf("Error: %s -> %s: %s\n", rAddr, header.hostPort, err)
	}
}

func (self *client) nextState(buffer []byte, offset int) error {
	var err error
	var splitSize = HTTP_HEADER_SPLIT_SIZE

	// HTTPS handler
	if self.httpHeader.hasConnectMethod {
		// send established tunneling status
		req := []byte("HTTP/1.1 200 OK\r\n\r\n")
		if _, err = self.source.Write(req); err != nil {
			return err
		}

		// Read HTTPS HELO packet and update `offset` value
		if offset, err = self.source.Read(buffer[:]); err != nil {
			return err
		}

		splitSize = HTTPS_HELO_SPLIT_SIZE
	}

	if err = self.writeSplitRequest(buffer[:offset], splitSize); err != nil {
		return err
	}

	self.spliceConnection()
	return nil
}

func (self *client) writeSplitRequest(buffer []byte, splitSize int) error {
	bLen := len(buffer)
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

func (self *client) spliceConnection() {
	go func() {
		io.Copy(self.target, self.source)
	}()

	io.Copy(self.source, self.target)
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
