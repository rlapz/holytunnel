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

/*
 * Http header
 */
type httpHeader struct {
	path     string
	method   string
	hostPort string
}

var (
	ErrHttpHeaderInval = errors.New("invalid http header")
)

// expect suffixed with "\r\n\r\n"
func (self *httpHeader) parse(buffer []byte) error {
	fb_end := bytes.Index(buffer, []byte("\r\n"))
	if fb_end < 0 {
		return ErrHttpHeaderInval
	}

	split := bytes.Split(buffer[:fb_end], []byte(" "))
	if len(split) != 3 {
		return ErrHttpHeaderInval
	}

	self.method = string(bytes.Trim(split[0], " "))
	self.path = string(bytes.Trim(split[1], " "))

	// finding host:port
	var fb_host int
	var fb_host_end int

	fb_host = bytes.Index(buffer[fb_end:], []byte("Host:"))
	if fb_host < 0 {
		goto out1
	}

	// update buffer offset
	buffer = buffer[fb_host+fb_end:]

	fb_host_end = bytes.Index(buffer, []byte("\r\n"))
	if fb_host_end < 0 {
		goto out1
	}

	split = bytes.SplitN(buffer[:fb_host_end], []byte(":"), 2)
	if len(split) < 1 {
		goto out1
	}

	self.hostPort = string(bytes.Trim(split[1], " "))
	return nil

out1:
	self.hostPort = ""
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
		conn, err := listener.Accept()
		if err != nil {
			log.Println("Cannot accept a new client:", err.Error())
			continue
		}

		go NewClient(conn).handle()
	}
}

/*
 * Client
 */
type client struct {
	conn   net.Conn
	buffer [8192]byte
}

func NewClient(conn net.Conn) *client {
	return &client{
		conn: conn,
	}
}

func (self *client) handle() {
	var rAddr = self.conn.RemoteAddr()

	defer self.conn.Close()
	defer log.Println("closed connection:", rAddr)
	log.Println("new connection:", rAddr)

	var buffer = self.buffer[:]
	var header httpHeader

	// TODO: handle big request header
	recvd, err := self.conn.Read(buffer)
	if err != nil {
		goto err0
	}

	buffer = buffer[:recvd]
	if !bytes.Contains(buffer, []byte("\r\n\r\n")) {
		err = ErrHttpHeaderInval
		goto err0
	}

	if err = header.parse(buffer); err != nil {
		goto err0
	}

	switch strings.ToLower(header.method) {
	case "connect":
		if !strings.Contains(header.path, ":") {
			header.path += ":443"
		}

		if err = self.handleHTTPS(&header, recvd); err != nil {
			goto err0
		}
	default:
		if !strings.Contains(header.hostPort, ":") {
			header.hostPort += ":80"
		}

		if err = self.handleHTTP(&header, recvd); err != nil {
			goto err0
		}
	}

	return

err0:
	log.Printf("Error: %s: %s\n", rAddr, err.Error())
}

func (self *client) handleHTTP(header *httpHeader, fb int) error {
	target, err := net.Dial("tcp", header.hostPort)
	if err != nil {
		return err
	}
	defer target.Close()

	// send the first bytes
	if err = splitRequestBytes(target, self.buffer[:fb]); err != nil {
		return err
	}

	// forward the traffics
	go func() {
		_, err = io.Copy(target, self.conn)
	}()

	if _, err = io.Copy(self.conn, target); err != nil {
		return err
	}

	return nil
}

func (self *client) handleHTTPS(header *httpHeader, fb int) error {
	target, err := net.Dial("tcp", header.path)
	if err != nil {
		return err
	}
	defer target.Close()

	// send established tunneling status
	reader := bytes.NewReader([]byte("HTTP/1.1 200 OK\r\n\r\n"))
	if _, err = io.Copy(self.conn, reader); err != nil {
		return err
	}

	// TODO: correct HTTPS HELO packet size
	rd, err := self.conn.Read(self.buffer[:256])
	if err != nil {
		return err
	}

	if err = splitRequestBytes(target, self.buffer[:rd]); err != nil {
		return err
	}

	// forward the traffics
	go func() {
		_, err = io.Copy(target, self.conn)
	}()

	if _, err := io.Copy(self.conn, target); err != nil {
		return err
	}

	return nil
}

func splitRequestBytes(target net.Conn, buffer []byte) error {
	snd := 0
	for snd < len(buffer) {
		s, err := target.Write(buffer[snd : snd+64])
		if err != nil {
			return err
		}

		snd += s
	}

	return nil
}

func main() {
	args := os.Args
	argc := len(args)
	if argc != 2 {
		fmt.Println("Not enough argument!\nholytunnel [HOST:PORT]")
		os.Exit(1)
	}

	if err := runServer(args[1]); err != nil {
		log.Panicln(err)
	}
}
