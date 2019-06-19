// Copyright 2017-2019 ajee.cai@gmail.com. All rights reserved
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"bufio"
	"crypto/tls"
	"flag"
	"log"
	"net"
	"os"
)

func main() {
	var ln net.Listener
	var err error
	var hostport = flag.String("hostport", "localhost:4433", "ip address or host:port for log server")
	var is_ssl = flag.Int("ssl", 1, "SSL or not")

	flag.Parse()
	log.Printf("hostport is %s, is_ssl %v\n", *hostport, *is_ssl)

	log.SetFlags(log.Lshortfile)

	if *is_ssl != 0 {
		cer, inn_err := tls.LoadX509KeyPair("server.crt", "server.key")
		if ( inn_err != nil) {
			log.Println(inn_err)
	                return
		}
		config := &tls.Config{Certificates: []tls.Certificate{cer}}
		ln, err = tls.Listen("tcp", *hostport, config)
	}else {
		ln, err = net.Listen("tcp", *hostport)
	}

	if ln == nil {
		log.Println(err)
		return
	}

	defer ln.Close()

        for {
		conn, err := ln.Accept()
		if err != nil {
			log.Println(err)
			continue
		}
		go handleConnection(conn)
		go handleConsole(conn)
        }
}

func handleConsole(conn net.Conn) {
	defer conn.Close()
	reader := bufio.NewReader(os.Stdin)
	for {
		log.Printf("Enter text: ")
		text, _ := reader.ReadString('\n')
		//log.Println(text)
		_, err := conn.Write([]byte(text))
                if err != nil {
                        log.Println(err)
                        return
                }
	}
}
func handleConnection(conn net.Conn) {
	defer conn.Close()
	var b = make([]byte, 15000)
	r := bufio.NewReader(conn)
	for {
		n, err := r.Read(b)
		if err != nil {
			log.Println(err)
			return
		}

		log.Printf("read %d bytes: %s", n, b[:n])

	}
}
