// Copyright 2017-2019 ajee.cai@gmail.com. All rights reserved
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"bufio"
	"bytes"
	cryprand "crypto/rand"
	"crypto/sha1"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"io"
	"io/ioutil"
	"math/rand"
	"net"
	"net/http"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

const httpPackRandSizeMax = 1000

func getWatermarkData() (int, []byte) {
	c := rand.Intn(httpPackRandSizeMax)
	b := make([]byte, c)
	_, err := cryprand.Read(b)
	if err != nil {
		Debug("error:", err)
		return 0, nil
	}
	waterMark := append(waterMarkBase, b...)
	return (c + len(waterMarkBase)), waterMark
}
func hashTxt(txt, random string) []byte {
	h := sha1.New()
	io.WriteString(h, txt)
	//io.WriteString(h, random)
	return h.Sum(nil)
}

/*
SoftEtherVPN PackToBuf format, but it should use protobuf for better :
 number_elems (4) | Elem 1 | Elem 2 | ...|
Where Elem n as:
  len of name + 1 (4) | name | type (4) | num of items | item 1 | item 2 | ...|
Where item n as: (don't know how to tell if mixed, currently contains only 1 item)
  int or int64 or data (size|body) or string (size|str) or unistring (size|str)
*/
func parseData(body []byte) (map[string]interface{}, error) {
	Debug("Parsing data %v...\n", body)
	p := body[0:]
	elems := binary.BigEndian.Uint32(p)
	m := make(map[string]interface{})
	p = p[4:]
	for ; elems > 0; elems-- {
		var value interface{}
		nameLen := binary.BigEndian.Uint32(p)
		if nameLen <= 0 {
			return nil, errors.New("nameLen <= 0")
		}
		p = p[4:]
		name := string(p[0 : nameLen-1]) // nameLen is plus 1. slice is left close,right disclosure
		Debug("name %v\n", name)
		p = p[nameLen-1:]
		elemType := binary.BigEndian.Uint32(p)
		Debug("type %v\n", elemType)
		p = p[4:]
		numItems := binary.BigEndian.Uint32(p)
		p = p[4:]
		Debug("numItems %v\n", numItems)
		if numItems > 1 {
			return nil, errors.New("numItems > 1")
		}

		switch elemType {
		case 0: // int
			value = binary.BigEndian.Uint32(p)
			//log.Println("int value",value)
			p = p[4:]
		case 1: // data
			size := binary.BigEndian.Uint32(p)
			p = p[4:]
			//log.Println("data size",size)
			value = p[:size]
			//log.Println("value",value)
			p = p[size:]
		case 2: // str
			size := binary.BigEndian.Uint32(p)
			p = p[4:]
			//log.Println("str size",size)
			value = string(p[:size])
			//log.Println("str",value)
			p = p[size:]
		case 3: // unistr
			size := binary.BigEndian.Uint32(p)
			p = p[4:]
			//log.Println("unistr size",size)
			value = string(p[:size]) // TODO: ?
			//log.Println("unistr",value)
			p = p[size:]
		case 4: // int64
			value = binary.BigEndian.Uint64(p)
			//log.Println("int64 value",value)
			p = p[8:]
		default:
		}
		m[name] = value
	}
	//log.Println("m ",m)
	return m, nil
}

func addData(p []byte, m map[string]interface{}) ([]byte, error) {

	var tmp32 []byte = make([]byte, 4)

	//num of elems
	elems := len(m)
	binary.BigEndian.PutUint32(tmp32, uint32(elems))
	p = append(p, tmp32...)

	// loop for each elem
	for k, v := range m {
		//name len
		binary.BigEndian.PutUint32(tmp32, uint32(len(k)+1))
		p = append(p, tmp32...)
		//name str
		tmp := []byte(k)
		p = append(p, tmp...)

		Debug("k is %s, v type %T\n", k, v)

		switch v := v.(type) {
		case nil:
			return nil, errors.New("nil value")
		case int32:
			Debug("int\n")
			p = intHelper(p, uint32(v))
		case uint32:
			Debug("uint32\n")
			p = intHelper(p, uint32(v))
		case int: //can combine?
			Debug("int\n")
			p = intHelper(p, uint32(v))
		case uint: //can combine?
			Debug("uint\n")
			p = intHelper(p, uint32(v))
		case []byte:
			Debug("byte []\n")
			binary.BigEndian.PutUint32(tmp32, uint32(1)) // type
			p = append(p, tmp32...)
			binary.BigEndian.PutUint32(tmp32, uint32(1)) // numItems
			p = append(p, tmp32...)
			b_len := len(v)
			binary.BigEndian.PutUint32(tmp32, uint32(b_len))
			p = append(p, tmp32...)
			p = append(p, v...)
		case string:
			Debug("string\n")
			binary.BigEndian.PutUint32(tmp32, uint32(2)) // type
			p = append(p, tmp32...)
			binary.BigEndian.PutUint32(tmp32, uint32(1)) // numItems
			p = append(p, tmp32...)
			b_len := len(v)
			binary.BigEndian.PutUint32(tmp32, uint32(b_len))
			p = append(p, tmp32...)
			tmp = []byte(v)
			p = append(p, tmp...)

		default:
			Debug("Unreconized type %T\n", v)
			return nil, errors.New("Unrecognized type")
		}
	}

	return p, nil
}

func parseHttpResponse(conn *tls.Conn) ([]byte, error) {
	var readBuf = make([]byte, 4096)
	b, err := conn.Read(readBuf)
	if err != nil || b <= 0 {
		Debug("err: %v, b: %d\n", err, b)
		return nil, err
	}
	respReader := bufio.NewReader(bytes.NewReader(readBuf))
	resp, err := http.ReadResponse(respReader, nil)
	if err != nil {
		Debug("err: %v, b: %d\n", err, b)
		return nil, err
	}

	//Debug("b %d from server: %s\n", b, resp.Body);
	if resp.Proto != "HTTP/1.1" || resp.Status != "200 OK" || resp.Header.Get("Content-Type") != "application/octet-stream" {
		Debug("Not OK from server %v", resp)
		return nil, errors.New("HTTP heahder not good")
	}
	// Is it bad to do too much conversion? byte -> io -> byte
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		Debug("err: %v, b: %d\n", err, b)
		return nil, err
	}
	return body, nil
}

func pktParse(frame []byte) {
	packet := gopacket.NewPacket(frame, layers.LayerTypeEthernet, gopacket.Default)
	if arpLayer := packet.Layer(layers.LayerTypeARP); arpLayer != nil {
		Debug("This is an arpLayer packet!\n")

		arp := arpLayer.(*layers.ARP)
		Debug("ARP %v, from %v(%v) to %v(%v)\n", arp.Operation, net.IP(arp.SourceProtAddress), net.HardwareAddr(arp.SourceHwAddress), net.IP(arp.DstProtAddress), net.HardwareAddr(arp.DstHwAddress))

	} else if ipLayer := packet.Layer(layers.LayerTypeIPv4); ipLayer != nil {
		Debug("This is an ipLayer packet!\n")

		ip := ipLayer.(*layers.IPv4)

		Debug("iPv4 protocol %d, from %v to %v\n", ip.Protocol, net.IP(ip.SrcIP), net.IP(ip.DstIP))

	}
	return
}

// looks like combine int/uint/32 as one case will have error of
//"cannot convert v (type interface {}) to type uint32: need type assertion", so make a helper
func intHelper(p []byte, v uint32) []byte {
	var tmp32 []byte = make([]byte, 4)
	binary.BigEndian.PutUint32(tmp32, uint32(0)) // type
	p = append(p, tmp32...)
	binary.BigEndian.PutUint32(tmp32, uint32(1)) // numItems
	p = append(p, tmp32...)
	binary.BigEndian.PutUint32(tmp32, uint32(v))
	p = append(p, tmp32...)
	return p
}

/* data format:
   | number of blocks | block 1 | block 2 | ...|
   Where number of blocks = 0xfff...f is a special magic for keep-alive,
      = 0xfff...e is for control msg, since there won't be so large a block size.
   Then block is:
   | size of block | data |
*/
func framePack(numBlock, size_block int, data []byte) []byte {
	var frameSent []byte
	var tmp32 []byte = make([]byte, 4)
	binary.BigEndian.PutUint32(tmp32, uint32(numBlock)) // num of blocks
	frameSent = append(frameSent, tmp32...)
	binary.BigEndian.PutUint32(tmp32, uint32(size_block)) // size of block
	frameSent = append(frameSent, tmp32...)
	frameSent = append(frameSent, data...) //data
	return frameSent
}

/* TODO: only handle one block now ... */
func frameUnpack(data []byte) []byte {

	p := data[0:]
	numBlock := binary.BigEndian.Uint32(p)
	p = p[4:]
	if numBlock > 0xfff {
		Debug("This is control block, %x\n", numBlock)
		return nil
	}
	if numBlock > 1 {
		Debug("Currently only return 1 block, now it is %d\n", numBlock)
	}
	for i := 0; i < int(numBlock); i++ {
		sizeBlock := binary.BigEndian.Uint32(p)
		p = p[4:]
		return p[:sizeBlock]
	}

	return nil
}
