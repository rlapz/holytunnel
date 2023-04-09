package main

import (
	"bytes"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"strings"
	"sync"
)

/*
 * Http header
 */
type httpHeader struct {
	path     string
	method   string
	protocol string
	hostPort string
	hasBody  bool
}

// expect suffixed with "\r\n\r\n"
func (self *httpHeader) parse(buff []byte) int {
	fb_end := bytes.Index(buff, []byte("\r\n"))
	if fb_end < 0 {
		return -1
	}

	split := bytes.Split(buff[:fb_end], []byte(" "))
	if len(split) != 3 {
		return -1
	}

	self.method = string(bytes.Trim(split[0], " "))
	self.path = string(bytes.Trim(split[1], " "))
	self.protocol = string(bytes.Trim(split[2], " "))
	self.hasBody = false

	// finding Content-Length & Transfer-Encoding
	if bytes.Contains(buff, []byte("Content-Length")) {
		self.hasBody = true
	}

	if bytes.Contains(buff, []byte("Transfer-Encoding")) {
		self.hasBody = true
	}

	// finding host:port
	var fb_host int
	var fb_host_end int

	fb_host = bytes.Index(buff[fb_end:], []byte("Host:"))
	if fb_host < 0 {
		goto out1
	}

	// update buffer offset
	buff = buff[fb_host+fb_end:]

	fb_host_end = bytes.Index(buff, []byte("\r\n"))
	if fb_host_end < 0 {
		goto out1
	}

	split = bytes.SplitN(buff[:fb_host_end], []byte(":"), 2)
	if len(split) < 1 {
		goto out1
	}

	self.hostPort = string(bytes.Trim(split[1], " "))
	return 0

out1:
	self.hostPort = ""
	return 0
}

/*
 * Server
 */
type server struct {
	isAlive   bool
	listener  net.Listener
	waitGroup sync.WaitGroup
}

func (self *server) run(address string) error {
	return self.handle(address)
}

func (self *server) handle(address string) error {
	listener, err := net.Listen("tcp", address)
	if err != nil {
		return err
	}

	defer listener.Close()

	self.listener = listener
	self.isAlive = true
	for self.isAlive {
		if conn, err := listener.Accept(); err == nil {
			self.waitGroup.Add(1)
			go new(client).handle(conn, &self.waitGroup)
		} else {
			log.Println(err)
		}
	}

	self.waitGroup.Wait()
	return nil
}

/*
 * Client
 */
type client struct {
	conn   net.Conn
	count  int
	buffer [8192]byte
}

func (self *client) handle(conn net.Conn, wg *sync.WaitGroup) {
	var addr = conn.RemoteAddr()
	log.Println("new connection:", addr)

	defer conn.Close()
	defer wg.Done()

	defer log.Println("closed connection:", addr)

	var firstBytes = self.buffer[:]

	// TODO: handle big request header
	readBytes, err := conn.Read(firstBytes)
	if err != nil {
		log.Printf("%s: %s\n", addr, err.Error())
		return
	}

	firstBytes = firstBytes[:readBytes]
	if !bytes.Contains(firstBytes, []byte("\r\n\r\n")) {
		log.Printf("%s: %s\n", addr, err.Error())
		return
	}

	var header httpHeader
	if header.parse(firstBytes) < 0 {
		log.Printf("%s: Invalid http header\n", addr)
		return
	}

	self.conn = conn
	self.count = readBytes

	method := strings.ToLower(header.method)
	if method == "connect" {
		if !strings.Contains(header.hostPort, ":") {
			header.hostPort += ":443"
		}

		self.handleHTTPS(&header)
	} else {
		if !strings.Contains(header.hostPort, ":") {
			header.hostPort += ":80"
		}

		self.handleHTTP(&header)
	}
}

func (self *client) handleHTTP(header *httpHeader) {
	log.Println("http")
	var addr = self.conn.RemoteAddr()

	target, err := net.Dial("tcp", header.hostPort)
	if err != nil {
		log.Printf("%s: %s\n", addr, err)
		return
	}
	defer target.Close()

	// send the firstBytes
	reader := bytes.NewReader(self.buffer[:self.count])
	_, err = io.Copy(target, reader)
	if err != nil {
		log.Printf("%s: %s\n", addr, err)
		return
	}

	// send the remaining bytes
	go func(ctx *client, trg net.Conn) {
		_, err = io.Copy(trg, ctx.conn)
		if err != nil {
			log.Printf("%s: %s\n", self.conn.RemoteAddr(), err)
			return
		}
	}(self, target)

	// recv response bytes from the target
	_, err = io.Copy(self.conn, target)
	if err != nil {
		log.Printf("%s: %s\n", addr, err)
		return
	}
}

func (self *client) handleHTTPS(header *httpHeader) {
	log.Println("https")
}

func (self *client) forward() {
}

func main() {
	args := os.Args
	argc := len(args)
	if argc != 2 {
		fmt.Println("Not enough argument!\nholytunnel [HOST:PORT]")
		os.Exit(1)
	}

	var srv server
	if err := srv.run(args[1]); err != nil {
		log.Panicln(err)
	}
}
