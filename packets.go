// Binary packet parser.
// Parses varios packets based on its packet_id.
// This binary parser is needed since we need to communicate with some legacy services.
package main

import "github.com/AesirWorld/global-server/packet"

// Aliases for each packet_id
const (
	// Packets from client
	PKT_ENTER     = 0x64   // Client request for authentication with server
	PKT_ENTER2    = 0x01dd // Client request for auth with hash password
	PKT_HEARTBEAT = 0x200  // Socket keep-alive/ping packet
	// Packets from char-server
	PKT_CHR_ENTER                 = 0x2710 // Char-server request for authentication
	PKT_CHR_HEARTBEAT             = 0x2719 // Socket keep-alive/ping packet
	PKT_CHR_REQAUTHTOKEN          = 0x2712 // Request to verify an valid auth token received from client
	PKT_CHR_USERCOUNT             = 0x272d // Receive list of all online accounts.
	PKT_CHR_ACKUSERCOUNT          = 0x2714 // Receive a request to update user count for char-server
	PKT_CHR_REQUPDATE_EMAIL       = 0x2715 // Request to update given user email
	PKT_CHR_REQCHANGE_EMAIL       = 0x2722 // Req email change
	PKT_CHR_REQACCDATA            = 0x2716 // Request account data
	PKT_CHR_REQUPDATE_ACCSTATE    = 0x2724 // Req update account state
	PKT_CHR_REQCHANGESEX          = 0x2727 // Req to change account sex
	PKT_CHR_REQBAN                = 0x2725 // Req to ban account
	PKT_CHR_REQUPDATE_REG2        = 0x2728 // Req to update reg
	PKT_CHR_REQUNBAN              = 0x272a // Req unban account
	PKT_CHR_REQSET_ACCOUNTONLINE  = 0x272b // Req to set account online
	PKT_CHR_REQSET_ACCOUNTOFFLINE = 0x272c // Req update account state
	PKT_CHR_REQACC2REG            = 0x272e // ?
	PKT_CHR_REQUPDATE_CHARIP      = 0x2736 // Req to update charip
	PKT_CHR_REQSETALLOFFLINE      = 0x2737 // Req to set all accounts offline
	PKT_CHR_REQUPDATE_PINGCODE    = 0x2738 // Req to update acc pincode
	PKT_CHR_PINCODE_AUTHFAIL      = 0x2739 // Pincode authentication fail
	PKT_CHR_BANKVAULT             = 0x2740 // ?
	PKT_CHR_REQVIPDATA            = 0x2742 // ?
)

// Client request for authentication with server
type PACKET_ENTER struct {
	version    uint32
	username   string
	password   string
	clienttype uint8
}

// Char-server connect request
type PACKET_CHR_ENTER struct {
	username string
	password string
	ip       uint32
	port     uint16
	name     string
	_type    uint16 // 0=normal, 1=maintenance, 2=over 18, 3=paying, 4=P2P
	_new     uint16 // should display as 'new'?
}

// Char-server req verify token
type PACKET_CHR_REQAUTHTOKEN struct {
	account_id uint32
	login_id1  uint32
	login_id2  uint32
	sex        uint8
	request_id uint32
}

// Char-server req verify token
type PACKET_CHR_REQACCDATA struct {
	aid uint32
}

// Set acc offline
type PACKET_CHR_REQSET_ACCOUNTOFFLINE struct {
	account_id uint32
}

// Acc2Reg
type PACKET_CHR_REQACC2REG struct {
	account_id uint32
	char_id    uint32
}

func (p *PACKET_ENTER) Read(buf []byte) {
	pkt := packet.Reader(buf)
	p.version = pkt.ReadUint32(2)
	p.username = pkt.ReadString(6, 24)
	p.password = pkt.ReadString(30, 24)
	p.clienttype = pkt.ReadUint8(54)
}

func (p *PACKET_CHR_ENTER) Read(buf []byte) {
	pkt := packet.Reader(buf)
	p.username = pkt.ReadString(2, 4)
	p.password = pkt.ReadString(26, 24)
	p.ip = pkt.ReadUint32(54)
	p.port = pkt.ReadUint16(58)
	p.name = pkt.ReadString(60, 20)
	p._type = pkt.ReadUint16(82)
	p._new = pkt.ReadUint16(84)
}

func (p *PACKET_CHR_REQAUTHTOKEN) Read(buf []byte) {
	pkt := packet.Reader(buf)
	p.account_id = pkt.ReadUint32(2)
	p.login_id1 = pkt.ReadUint32(6)
	p.login_id2 = pkt.ReadUint32(10)
	p.sex = pkt.ReadUint8(14)
	p.request_id = pkt.ReadUint32(19)
}

func (p *PACKET_CHR_REQACCDATA) Read(buf []byte) {
	pkt := packet.Reader(buf)
	p.aid = pkt.ReadUint32(2)
}

func (p *PACKET_CHR_REQSET_ACCOUNTOFFLINE) Read(buf []byte) {
	pkt := packet.Reader(buf)
	p.account_id = pkt.ReadUint32(2)
}

func (p *PACKET_CHR_REQACC2REG) Read(buf []byte) {
	pkt := packet.Reader(buf)
	p.account_id = pkt.ReadUint32(2)
	p.char_id = pkt.ReadUint32(6)
}
