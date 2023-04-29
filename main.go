package main

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
)

const (
	BUFFER_SIZE            = 8192
	HTTPS_HELO_SPLIT_SIZE  = 128
	HTTP_HEADER_SPLIT_SIZE = 4
)

/*
 * HTTP Request Handler
 */
var errHttpRequestInval = errors.New("invalid http request")

type httpRequest struct {
	method           string
	path             string
	version          string
	hostPort         string
	hasConnectMethod bool
}

func (self *httpRequest) parse(buffer []byte) error {
	rd := bufio.NewReader(bytes.NewReader(buffer))
	req, err := http.ReadRequest(rd)
	if err != nil {
		return err
	}

	self.method = req.Method
	if self.method == "CONNECT" {
		self.hasConnectMethod = true
	} else {
		self.hasConnectMethod = false
	}

	var path = "/"
	if req.URL.Path != "" {
		path = req.URL.Path
	}

	if req.URL.RawQuery != "" {
		path += "?" + req.URL.RawQuery
	}

	if req.URL.RawFragment != "" {
		path += "#" + req.URL.RawFragment
	}

	self.path = path
	self.version = req.Proto

	startIdx := strings.Index(req.Host, "]") // IPv6
	if startIdx < 0 {
		startIdx = 0
	}

	self.hostPort = req.Host
	if !strings.Contains(req.Host[startIdx:], ":") {
		// need port
		if self.hasConnectMethod {
			self.hostPort += ":443"
		} else {
			self.hostPort += ":80"
		}
	}

	req.Body.Close()
	return nil
}

func (self *httpRequest) newHttpRequest(buffer []byte) ([]byte, error) {
	reqLineEndIdx := bytes.Index(buffer, []byte("\r\n"))
	if reqLineEndIdx < 0 {
		return nil, errHttpRequestInval
	}

	u, err := url.Parse(self.path)
	if err != nil {
		return nil, err
	}

	newReqLine := fmt.Sprintf("%s %s %s", self.method, u.Path, self.version)
	newReqLineLen := len(newReqLine)
	newBuff := make([]byte, newReqLineLen+(len(buffer)-reqLineEndIdx))

	copy(newBuff, newReqLine)
	copy(newBuff[newReqLineLen:], buffer[reqLineEndIdx:])
	return newBuff, nil
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

	log.Println("Listening on:", address)

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
	source  net.Conn
	target  net.Conn
	request httpRequest
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
	var req = &self.request
	var buffer = realBuffer[:]

	// TODO: handle big request header
	recvd, err := self.source.Read(buffer)
	if err != nil {
		log.Printf("Error: conn.Read: source: %s: %s\n", rAddr, err)
		return
	}

	if err = req.parse(buffer); err != nil {
		log.Printf("Error: httpRequest.parse: %s: %s\n", rAddr, err)
		return
	}

	// connect to the target host
	self.target, err = net.Dial("tcp", req.hostPort)
	if err != nil {
		log.Printf("Error: net.Dial: target: %s: %s\n", rAddr, err)
		return
	}
	defer self.target.Close()

	log.Printf("%s -> %s %s\n", rAddr, req.method, req.hostPort)
	if req.hasConnectMethod {
		// HTTPS
		err = self.handleHttps(buffer)
	} else {
		// HTTP
		// update http request (buffer), handle absolute path
		buffer, err = req.newHttpRequest(buffer[:recvd])
		if err != nil {
			log.Printf("Error: request.newHttpRequest: %s: %s\n", rAddr, err)
			return
		}

		err = self.handleHttp(buffer)
	}

	if err != nil {
		log.Printf("Error: %s -> %s: %s\n", rAddr, req.hostPort, err)
	}
}

func (self *client) handleHttp(buffer []byte) error {
	err := self.writeSplitRequest(buffer, HTTP_HEADER_SPLIT_SIZE)
	if err != nil {
		return err
	}

	self.spliceConnection()
	return nil
}

func (self *client) handleHttps(buffer []byte) error {
	// send established tunneling status
	req := []byte("HTTP/1.1 200 OK\r\n\r\n")
	if _, err := self.source.Write(req); err != nil {
		return err
	}

	// Read HTTPS HELO packet and update `offset` value
	offset, err := self.source.Read(buffer)
	if err != nil {
		return err
	}

	err = self.writeSplitRequest(buffer[:offset], HTTPS_HELO_SPLIT_SIZE)
	if err != nil {
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
