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

	fbEnd := bytes.Index(buffer, []byte("\r\n"))
	if fbEnd < 0 {
		return ErrHttpHeaderInval
	}

	// finding method type
	methodEnd := bytes.Index(buffer[:fbEnd], []byte(" "))
	if methodEnd < 0 {
		return ErrHttpHeaderInval
	}

	method := bytes.Trim(buffer[:methodEnd], " ")
	if bytes.Equal(bytes.ToUpper(method), []byte("CONNECT")) {
		self.hasConnectMethod = true
	} else {
		self.hasConnectMethod = false
	}

	// finding host:port
	hdHost := []byte("Host:")
	fbHost := bytes.Index(buffer[fbEnd:], hdHost)
	if fbHost < 0 {
		return ErrHttpHeaderInval
	}

	bufHostPort := buffer[fbHost+fbEnd+len(hdHost):]
	fbHostEnd := bytes.Index(bufHostPort, []byte("\r\n"))
	if fbHostEnd < 0 {
		return ErrHttpHeaderInval
	}

	hostPort := bytes.Trim(bufHostPort[:fbHostEnd], " ")
	sHostPort := string(hostPort)

	// check host ip version
	idxIPv6End := bytes.Index(hostPort, []byte("]"))
	if idxIPv6End < 0 {
		// IPv4
		if !bytes.Contains(hostPort, []byte(":")) {
			sHostPort = self.addPort(sHostPort)
		}
	} else {
		// IPv6
		if bytes.Index(hostPort[idxIPv6End:], []byte(":")) == -1 {
			sHostPort = self.addPort(sHostPort)
		}
	}

	self.hostPort = sHostPort
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
	} else {
		if err = self.handleHTTP(&header, buffer[:recvd]); err != nil {
			log.Printf("Error: handleHTTP: %s: %s\n", rAddr, err)
		}
	}
}

func (self *client) handleHTTP(header *httpHeader, buffer []byte) error {
	// send the first bytes
	if err := writeAllBytes(self.target, buffer); err != nil {
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
