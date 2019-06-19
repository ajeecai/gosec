// Copyright 2017-2019 ajee.cai@gmail.com. All rights reserved
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"flag"
	"image"
	"image/color"
	"strconv"
	"strings"

	"crypto/tls"
	"github.com/songgao/water"

	"github.com/aarzilli/nucular"
	"github.com/aarzilli/nucular/label"
	"github.com/aarzilli/nucular/rect"
	nstyle "github.com/aarzilli/nucular/style"
	_ "golang.org/x/mobile/app"
	_ "golang.org/x/mobile/event/key"
)

const (
	uiWidth  = 380
	uiHigh   = 200
	errWidth = 300
	errHigh  = 120

	rowHigh   = 22
	sepHigh   = 2
	col1Width = 90
	col2Width = 255
)
const (
	nDisconnected = iota
	nConnecting
	nConnected
)
const (
	eNone = iota
	eConn
	ePerm
	ePsw
)

type vpnSetting struct {
	host   string
	usr    string
	passwd string

	hostEditor   nucular.TextEditor
	usrEditor    nucular.TextEditor
	passwdEditor nucular.TextEditor
	curEditor    *nucular.TextEditor

	chanQuit  chan struct{}
	conn      *tls.Conn
	ifce      *water.Interface
	connState int
	err       int
	mw        *nucular.MasterWindow
}

func main() {
	//app.Main(func(a app.App) {
	defer func() {
		if logFd != nil {
			logFd.Close()
		}
	}()
	var wnd nucular.MasterWindow
	var theme nstyle.Theme = nstyle.DarkTheme
	var scaling = 1.2
	var vpnDiag vpnSetting

	var debugOpt = flag.String("debug", "no", "1. no - no debug\n2. print - print to console"+
		"\n3. log - write log\n4. logserver host:port - write to logserver\n")

	var hostport = flag.String("host", "localhost:4433", "host:port when debug set to logserver")

	flag.Parse()
	switch *debugOpt {

	case "print":
		Debug = fmtPrintf
	case "log":
		Debug = logPrintf
	case "logserver":
		Debug = sendToLogServer
		logServer = *hostport
	default:
		Debug = nullPrintf
	}

	wnd = nucular.NewMasterWindowSize(0, "SoftEtherVPN", image.Point{uiWidth, uiHigh}, vpnDiag.uiFn)
	vpnDiag.mw = &wnd

	wnd.SetStyle(nstyle.FromTheme(theme, scaling))
	wnd.Main()
	//})
}

func (c *vpnSetting) uiFn(w *nucular.Window) {
	var isTab, isEnter bool

	w.Row(10).Static(col1Width, col2Width)

	w.Row(sepHigh).Static(col1Width, col2Width)
	w.Row(rowHigh).Static(col1Width, col2Width)
	w.Label("  Status:", "CC")

	switch c.connState {
	case nConnected:
		w.LabelColored("SoftEtherVPN is connected", "LC", color.RGBA{0x27, 0xB5, 0x17, 0xff})
	case nConnecting:
		w.LabelColored("SoftEtherVPN is connecting ...", "LC", color.RGBA{0xff, 0xff, 0x00, 0xff})
	case nDisconnected:
		switch c.err {
		case eNone:
			w.LabelColored("SoftEtherVPN is disconnected", "LC", color.RGBA{0xff, 0x00, 0x00, 0xff})
		case ePsw:
			w.LabelColored("User name or password error", "LC", color.RGBA{0xff, 0x00, 0x00, 0xff})
		case ePerm:
			w.LabelColored("Re-run with root permission", "LC", color.RGBA{0xff, 0x00, 0x00, 0xff})
		case eConn:
			w.LabelColored("Failed to connect to server", "LC", color.RGBA{0xff, 0x00, 0x00, 0xff})
		default:
			w.LabelColored("Unknown error:"+strconv.Itoa(c.err), "LC", color.RGBA{0xff, 0x00, 0x00, 0xff})
		}
	default:
		Debug("unknown connState")
		return

	}

	if w.Input().Keyboard.Pressed(43) { // code can't use vender
		Debug("Key tab pressed\n")
		isTab = true

		switch c.curEditor {
		case &c.hostEditor:
			c.curEditor = &c.usrEditor
		case &c.usrEditor:
			c.curEditor = &c.passwdEditor
		case &c.passwdEditor:
			c.curEditor = &c.hostEditor
		default:
			c.curEditor = &c.hostEditor
		}

		(*c.mw).ActivateEditor(c.curEditor)
	} else if w.Input().Keyboard.Pressed(40) {
		isEnter = true
		Debug("Key enter pressed\n")

	}

	w.Row(sepHigh).Static(col1Width, col2Width)

	w.Row(rowHigh).Static(col1Width, col2Width)
	w.Label("   HostName:", "LC")
	c.hostEditor.Flags = nucular.EditField
	c.hostEditor.Filter = nucular.FilterDefault
	c.hostEditor.Maxlen = 255
	c.hostEditor.Buffer = []rune(c.host)
	c.hostEditor.Edit(w)
	if !isTab {
		c.host = string(c.hostEditor.Buffer)

	}

	w.Row(sepHigh).Static(col1Width, col2Width)
	w.Row(rowHigh).Static(col1Width, col2Width)
	w.Label("   UserName:", "LC")
	c.usrEditor.Flags = nucular.EditField
	c.usrEditor.Filter = nucular.FilterDefault
	c.usrEditor.Maxlen = 255
	c.usrEditor.Buffer = []rune(c.usr)
	c.usrEditor.Edit(w)
	if !isTab {
		c.usr = string(c.usrEditor.Buffer)

	}

	w.Row(sepHigh).Static(col1Width, col2Width)
	w.Row(rowHigh).Static(col1Width, col2Width)
	w.Label("   Password:", "LC")
	c.passwdEditor.Flags = nucular.EditField
	c.passwdEditor.Filter = nucular.FilterDefault
	c.passwdEditor.Maxlen = 255
	c.passwdEditor.Buffer = []rune(strings.Repeat("*", len(c.passwd)))
	c.passwdEditor.Edit(w)
	if !isTab {
		//Here mimic password input box, no support to edit input midst, append only
		tmpPwd := string(c.passwdEditor.Buffer)
		lenTmpPwd := len(tmpPwd)
		lenCPwd := len(c.passwd)
		//Debug("tmpPass is %v\n",tmpPwd)
		if lenTmpPwd < lenCPwd { // backspace
			c.passwd = c.passwd[0:lenTmpPwd]
		} else if lenTmpPwd == (lenCPwd+1) && tmpPwd[lenTmpPwd-1] == '*' { // append a "*"
			c.passwd += "*"
		} else if p := strings.LastIndex(tmpPwd, "*"); p != -1 { // append new
			c.passwd += tmpPwd[p+1:]
			//Debug("tmpPwd[p:] is %v\n",tmpPwd[p:])
		} else { //first one
			c.passwd = tmpPwd
		}
	}

	//Debug("passwd is %v\n",c.passwd)

	w.Row(sepHigh).Static(col1Width, col2Width)
	w.Row(rowHigh).Static(col1Width, 80)
	w.Label("", "CC")

	//Debug("host is %v\n",c.host)
	switch c.connState {

	case nConnected:
		if w.Button(label.T("Disconnect"), false) || isEnter {
			c.ifce.Close()
			c.conn.Close()
			c.connState = nDisconnected
			c.err = 0
			c.chanQuit <- struct{}{}
		}

	case nDisconnected:
		if w.Button(label.T("Connect"), false) || isEnter {
			if c.host == "" || c.usr == "" || c.passwd == "" {
				w.Master().PopupOpen("Error", nucular.WindowBorder|nucular.WindowMovable|nucular.WindowTitle, rect.Rect{(uiWidth - errWidth) / 2, (uiHigh - errHigh) / 2, errWidth, errHigh}, true, c.errorSettingPopup)

				return
			}
			Debug("button pressed!\n")
			c.connState = nConnecting
			go c.startConnect()
		}

	case nConnecting:
		w.Button(label.T("Connecting"), false)
	}

}
func (c *vpnSetting) errorSettingPopup(w *nucular.Window) {
	w.Row(25).Dynamic(1)
	w.Label("You must set necessary information", "LC")
	w.Row(25).Dynamic(2)
	if w.Button(label.T("OK"), false) {
		w.Close()
	}
	if w.Button(label.T("Cancel"), false) {
		w.Close()
	}
}
