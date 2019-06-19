// Copyright 2017-2019 ajee.cai@gmail.com. All rights reserved
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/songgao/packets/ethernet"
	"github.com/songgao/water"
	"github.com/u-root/u-root/pkg/dhclient"
	"github.com/vishvananda/netlink"
)

const (
	KeepAliveMsg = 0xffffffff
	dhcpTimeout  = 15 * time.Second
	dhcpTries    = 3
)

func (c *vpnSetting) startConnect() {
	// create connection to server
	// a bit ugly to append port number
	hostport := c.host
	ipEnd := strings.LastIndexByte(c.host, ']')
	if ipEnd != -1 {
		Debug("with IPv6:port\n")
	} else if off := strings.IndexByte(c.host, ':'); off != -1 {
		ipEnd := strings.LastIndexByte(c.host, ':')
		if ipEnd != -1 && off != ipEnd {
			// This is IPv6 IP address without port
			hostport = "[" + c.host + "]" + ":443"
		}
	} else {
		hostport += ":443"
	}

	conn, err := tls.Dial("tcp", hostport, &tls.Config{InsecureSkipVerify: true})
	c.conn = conn
	Debug("conn type %T, to %v\n", conn, hostport)

	defer func() {
		c.connState = nDisconnected
		if conn != nil {
			conn.Close()
		}
	}()

	if err != nil {
		c.err = eConn
		Debug("Connection failed\n")
		(*c.mw).Changed()
		return
	}
	// Steps: upload signature
	waterMarkLen, waterMarkData := getWatermarkData()
	ipEnd = strings.LastIndexByte(conn.LocalAddr().String(), ':')
	if ipEnd == -1 {
		Debug("Can't get port from LocalAddr" + conn.LocalAddr().String())
		return
	}
	myIP := conn.LocalAddr().String()[:ipEnd]
	Debug("Connection established\n")
	fmt.Fprintf(conn, "POST /vpnsvc/connect.cgi HTTP/1.1\r\n"+
		"Connection: Keep-Alive\r\n"+
		"Content-Length: %d\r\n"+
		"Content-Type: image/jpedg\r\n"+
		"Host: %s\r\n\r\n%s", waterMarkLen, myIP, waterMarkData)

	Debug("TX done\n")
	// Steps: download server hello
	body, err := parseHttpResponse(conn)
	if err != nil {
		Debug("err: %v\n", err)
		return
	}
	serverResp, err := parseData(body)
	if err != nil {
		Debug("err: %v\n", err)
		return
	}

	//Debug("serverResp is: %v\n",serverResp)

	/* This is test code
	test_byte, err := AddData(serverResp)
	if err != nil {
		Debug("err: %v\n", err)
		return
	}
	serverResp2, err := ParseData(test_byte)
	if err != nil {
		Debug("err: %v\n", err)
		return
	}
	Debug("serverResp2 is: %v\n",serverResp2)
	*/

	// Steps: TODO: verify server certificate
	// Steps: send authentication
	authHdr := "POST /vpnsvc/vpn.cgi HTTP/1.1\r\n" +
		"Connection: Keep-Alive\r\n" +
		"Content-Length: %s\r\n" +
		"Content-Type: application/octet-stream\r\n"
	authHdr += "Date:" + time.Now().Format("Mon Jan 2 15:04:05 -0700 MST 2006") + "\r\n"
	authHdr += "Host: " + myIP + "\r\n"
	authHdr += "Keep-Alive: timeout=15; max=19" + "\r\n\r\n"

	authMap := make(map[string]interface{})
	authMap["method"] = "login"
	authMap["hubname"] = "DEFAULT"
	authMap["username"] = c.usr
	authMap["authtype"] = 2
	//	authMap["secure_password"] = HashTxt("password","") //string(serverResp["random"].([]byte)))
	//	Debug("txt: % x\nSHA1 Hash: % x\n", "Passw0rd!",authMap["secure_password"] )
	// Should use securepassword for preventing memory hacking
	authMap["plain_password"] = c.passwd //"password"
	authMap["timestamp"] = time.Now().Format("123456")
	authMap["client_str"] = serverResp["hello"]
	authMap["client_ver"] = serverResp["version"]
	authMap["client_build"] = serverResp["build"]
	// Add more control option if needed
	authMap["max_connection"] = 8
	authMap["use_encrypt"] = 1
	authMap["use_compress"] = 0

	var authByte []byte = make([]byte, 0)
	authByte, err = addData(authByte, authMap)
	if err != nil {
		Debug("err: %v\n", err)
		return
	}

	fmt.Fprintf(conn, "POST /vpnsvc/vpn.cgi HTTP/1.1\r\n"+
		"Connection: Keep-Alive\r\n"+
		"Content-Length: %s\r\n"+
		"Content-Type: application/octet-stream\r\n"+
		"Date: %s\r\n"+
		"Host: %s\r\n"+
		"Keep-Alive: timeout=15; max=19\r\n\r\n",
		strconv.Itoa(len(authByte)),
		time.Now().Format("Mon Jan 2 15:04:05 -0700 MST 2006"),
		myIP)

	//Debug("authByte is: %v\n",auth)
	conn.Write(authByte)

	body, err = parseHttpResponse(conn)
	if err != nil {
		Debug("err: %v\n", err)
		return
	}
	serverResp, err = parseData(body)
	if err != nil {
		Debug("err: %v\n", err)
		return
	}
	Debug("Server Response from auth: %v\n", serverResp)
	e := serverResp["error"]
	if e != nil {
		r, ok := e.(uint32)
		if !ok {
			Debug("can't cast, err %T\n", e)
		}
		Debug("Server Response With error %v,%T,(%d)\n", e, e, r)
		if int(r) == 9 {
			c.err = ePsw
		}
		(*c.mw).Changed()
		return
	}

	//Create Virtual Interface
	config := water.Config{
		DeviceType: water.TAP,
	}
	config.Name = "vpn_go"

	ifce, err := water.New(config)
	c.ifce = ifce
	if err != nil {
		Debug("err when creating tap: %v\n", err)
		c.err = ePerm
		(*c.mw).Changed()
		return
	}

	c.chanQuit = make(chan struct{})
	// Will there be any performance to pass slice over chan?
	chanWrite := make(chan []byte)

	// read tap interface and send frame to chanWrite
	go func() {
		for {
			var frame ethernet.Frame
			frame.Resize(1500)
			n, err := ifce.Read([]byte(frame))
			if err != nil {
				Debug("iface is closed for read, quit\n")
				return
			}
			//This parse is for debug only
			//pktParse(frame[:n])
			frameSent := framePack(1, n, frame[:n])
			if frameSent != nil {
				chanWrite <- frameSent
			}
		}
	}()

	// wait on chanWrite and write packets to SSL tunnel
	go func() {
		for {
			frameSent := <-chanWrite
			//Debug("Write to tunnel:\n% x\n", frameSent)
			_, err = conn.Write(frameSent)
			if err != nil {
				Debug("conn is closed for write, quit\n")
				return
			}

		}
	}()

	// read from SSL tunnel
	go func() {
		for {
			var frameRead ethernet.Frame
			frameRead.Resize(1500)

			n, err := conn.Read([]byte(frameRead))
			if err != nil {
				Debug("conn is closed for read, quit\n")
				return
			}
			frame := frameUnpack(frameRead[:n])
			if frame == nil {
				continue
			}
			//This parse is for debug only
			//pktParse(frame)
			// write thru TAP interface
			n, err = ifce.Write(frame)
			if err != nil {
				Debug("iface is closed for write, quit\n")
				return
			}

		}
	}()

	c.connState = nConnected
	// manually call an UI update
	Debug("Call UI update\n")
	(*c.mw).Changed()

	// get dhcp address for interface
	ctx, cancel := context.WithTimeout(context.Background(), dhcpTries*dhcpTimeout)
	defer cancel()

	var filteredIfs []netlink.Link
	ifs, err := netlink.LinkList()
	for _, iface := range ifs {
		if config.Name == iface.Attrs().Name {
			filteredIfs = append(filteredIfs, iface)
			break
		}
	}

	r := dhclient.SendRequests(ctx, filteredIfs, dhcpTimeout, dhcpTries, true, false)
	if r == nil {
		fmt.Printf("r is null\n")
		return
	} else {
		// After result back, dhclient will close chan r immediately.
		result := <-r
		if nil != result && result.Err == nil {
			Debug("result %v\n", result)
			result.Lease.Configure()
		}
	}

	for {
		select {
		case <-c.chanQuit:
			Debug("Quit connectivity\n")
			break
		case <-time.After(10 * time.Second):
			kaData := []byte{0x00, 0x11, 0x22, 0x33, 0x44}
			frameSent := framePack(KeepAliveMsg, len(kaData), kaData)
			//Debug("keep alive timer wake up\n")
			chanWrite <- frameSent
		}
	}
}
