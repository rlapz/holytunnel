package main

import (
	"bufio"
	"bytes"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
)

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
const (
	HTTP  = 0
	HTTPS = 1
)

type client struct {
	conn   net.Conn
	buffer [8192]byte
}

func (self *client) handle(conn net.Conn, wg *sync.WaitGroup) {
	defer conn.Close()
	defer wg.Done()

	self.conn = conn
	connStr := self.conn.RemoteAddr()
	log.Println("A new connection from:", connStr)

	rd, err := self.conn.Read(self.buffer[:])
	if err != nil {
		log.Println("err:", err)
		return
	}

	buff := self.buffer[:rd]
	fmt.Printf("Message from: %s\n%s",
		connStr,
		string(buff),
	)

	reader := bytes.NewReader(buff)
	req, err := http.ReadRequest(bufio.NewReader(reader))
	if err != nil {
		return
	}

	if strings.Contains(req.Host, "127.0.0.1") {
		return
	}

	if strings.ToLower(req.Method) == "connect" {
		self.handleHTTPS(req, rd)
	} else {
		self.handleHTTP(req, rd)
	}
}

func (self *client) handleHTTP(req *http.Request, buffLen int) {
	fmt.Println("http:", req.URL.Host)

	host := req.Host
	if !strings.Contains(host, ":") {
		host += ":80"
	}

	conn, err := net.Dial("tcp", host)
	if err != nil {
		log.Println(err)
		return
	}

	defer conn.Close()

	log.Println("connected:", conn.RemoteAddr())
	self.forward(req, conn, buffLen)
}

func (self *client) handleHTTPS(req *http.Request, buffLen int) {
	fmt.Println("https:", req.URL.Host)
}

func (self *client) forward(req *http.Request, conn net.Conn, buffLen int) {
	log.Println("forward:", conn.RemoteAddr())

	wrt := 0
	for wrt < buffLen {
		wr, err := conn.Write(self.buffer[:buffLen])
		if err != nil {
			return
		}

		wrt += wr
	}

	for {
		rd, err := conn.Read(self.buffer[:])
		if err != nil {
			return
		}

		wrt = 0
		for wrt < rd {
			wr, err := self.conn.Write(self.buffer[:rd])
			if err != nil {
				return
			}

			wrt += wr
		}
	}
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
