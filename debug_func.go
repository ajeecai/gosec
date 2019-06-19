// Copyright 2017-2019 ajee.cai@gmail.com. All rights reserved
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"crypto/tls"
	"fmt"
	"log"
)

/* four kinds of log functions:
1. No print
2. fmt print
3. log print
4. send to our private log server(see logServer)
*/
func nullPrintf(format string, args ...interface{}) {
}

func fmtPrintf(format string, args ...interface{}) {
	fmt.Printf(format, args...)
}

func logPrintf(format string, args ...interface{}) {
	log.Printf(format, args...)
}

var logFd *tls.Conn
var logServer string

func sendToLogServer(format string, args ...interface{}) {
	if logFd == nil {
		// has to explict declare err instead of shorthand otherwise global logFd is NULL
		var err error = nil
		logFd, err = tls.Dial("tcp", logServer, &tls.Config{InsecureSkipVerify: true})
		if err != nil {
			_ = logFd
			return
		}
	}

	fmt.Fprintf(logFd, format, args...)
}

func closeLogFd() {
	if logFd != nil {
		logFd.Close()
		logFd = nil
	}

}

// Set the debug Based on the above choices
var Debug = nullPrintf
