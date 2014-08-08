// Char server packets handler functions
package main

import "log"
import "net"
import "encoding/binary"
import "github.com/AesirWorld/global-server/account"
import pkt "github.com/AesirWorld/global-server/packet"

// Char server handler
// Packet router
func handlerCharServer(c net.Conn, id int) {
	for {
		packet := make([]byte, 1024)

		length, _ := c.Read(packet)

		// Connection-closed
		if length == 0 {
			log.Println("Char-server disconnected")
			break
		}

		// First 2 bytes represent the packet_id
		packet_id := int(packet[0])<<0 | int(packet[1])<<8

		// Router
		switch packet_id {
		case PKT_CHR_HEARTBEAT:
			charServerHeartBeat(c, packet)
		case PKT_CHR_REQAUTHTOKEN:
			charServerReqAuth(c, packet)
		case PKT_CHR_REQACCDATA:
			charServerAccData(c, packet)
		case PKT_CHR_USERCOUNT:
			charServerOnlineCount(c, packet)
		case PKT_CHR_REQSET_ACCOUNTOFFLINE:
			charServerSetAccOffline(c, packet)
		case PKT_CHR_REQACC2REG:
			charServerAcc2Reg(c, packet)
		default:
			log.Printf("Abnormal packet received from authenticated char-server (%s): %#04x\n", c.RemoteAddr(), packet_id)
		}
	}
}

func charServerEnter(c net.Conn, packet []byte) {
	data := &PACKET_CHR_ENTER{}
	data.Read(packet)

	log.Printf("Authenticating char-server (%s) with (%s/%s)\n", c.RemoteAddr(), data.username, data.password)
	account_id := account.AuthServer(data.username, data.password)

	if account_id == 0 {
		log.Printf("Char-server connection request rejcted (%s)\n", c.RemoteAddr())
		res := make([]byte, 3)
		binary.LittleEndian.PutUint16(res, uint16(0x2711)) // Packet id
		res[2] = 1                                         // Type 0 = connection accepted.
		c.Write(res)
	} else {
		log.Printf("Char-server connection request accepted (%s) (%d)\n", c.RemoteAddr(), account_id)
		res := make([]byte, 3)
		binary.LittleEndian.PutUint16(res, uint16(0x2711)) // packet id
		res[2] = 0                                         // Type 0 = connection accepted.
		c.Write(res)
		handlerCharServer(c, account_id)
	}
}

func charServerHeartBeat(c net.Conn, packet []byte) {
	res := make([]byte, 2)
	binary.LittleEndian.PutUint16(res, uint16(0x2718))
	c.Write(res)
}

// Char server request to authenticate client conenction request
func charServerReqAuth(c net.Conn, packet []byte) {
	data := &PACKET_CHR_REQAUTHTOKEN{}
	data.Read(packet)

	account_id := data.account_id
	login_id1 := data.login_id1
	login_id2 := data.login_id2

	log.Printf("Char-server req auth (%d) (%d/%d)\n", account_id, login_id1, login_id2)

	auth := auth_db[int(account_id)]

	log.Println("Auth db match", auth.login_id1, auth.login_id2)

	if auth.login_id1 == login_id1 && auth.login_id2 == login_id2 {
		log.Println("Auth accepted")
		// Write pkt
		r := pkt.Writer(25)                // pkt length
		r.WriteUint16(0, 0x2713)           // packet id
		r.WriteUint32(2, account_id)       // account_id
		r.WriteUint32(6, data.login_id1)   // login id 1
		r.WriteUint32(10, data.login_id2)  // login id 2
		r.WriteUint8(14, data.sex)         // sex
		r.WriteUint8(15, 0)                // ok
		r.WriteUint32(16, data.request_id) // request_id
		r.WriteUint32(20, 25)              // version
		r.WriteUint8(24, 11)               // clienttype
		// Write response
		c.Write(r.Buffer())
	} else {
		log.Println("Auth rejected")
	}
}

// Receive a request for account data reply by sending all mmo_account information.
func charServerAccData(c net.Conn, packet []byte) {
	data := &PACKET_CHR_REQACCDATA{}
	data.Read(packet)

	r := pkt.Writer(79)
	r.WriteUint16(0, 0x2717)          // packet id
	r.WriteUint32(2, data.aid)        // aid
	r.WriteString(6, "a@a.com", 40)   // email
	r.WriteUint32(46, 0)              // expiration time
	r.WriteUint8(50, 0)               // group id
	r.WriteUint8(51, 9)               // char slots
	r.WriteString(52, "00/00/00", 11) // birth date
	r.WriteString(63, "", 5)          // pincode
	r.WriteUint32(68, 0)              // pin code change
	r.WriteUint32(72, 0)              // bank vault
	r.WriteUint8(76, 0)               // is vip
	r.WriteUint8(76, 0)               // char vip
	r.WriteUint8(78, 0)               //TODO create a config for this

	c.Write(r.Buffer())
}

// Set account_id to offline.
func charServerSetAccOffline(c net.Conn, packet []byte) {
	//data := &PACKET_CHR_REQSETACCOFFLINE{}
	//data.Read(packet)
	//data.account_id
}

// User online count in this char-server
// This func is void, just ignore it. User online count is made by the login-server now.
func charServerOnlineCount(c net.Conn, packet []byte) {

}

// I dont even know what the hell this does...
func charServerAcc2Reg(c net.Conn, packet []byte) {
	data := &PACKET_CHR_REQACC2REG{}
	data.Read(packet)

	r := pkt.Writer(13)               // pkt length
	r.WriteUint16(0, 0x2729)          // packet id
	r.WriteUint32(4, data.account_id) // account id
	r.WriteUint32(8, data.char_id)    // char id
	r.WriteUint8(12, 1)               //Type 1 for Account2 registry
	r.WriteUint16(2, 13)              // Offset TODO

	c.Write(r.Buffer())
}

/*
   case 0x2714:
       next = logchrif_parse_ackusercount(fd, cid)
       break
   case 0x2715:
       next = logchrif_parse_updmail(fd, cid, ip)
       break
       case 0x2722:
           next = logchrif_parse_reqchangemail(fd, cid, ip)
           break
       case 0x2724:
           next = logchrif_parse_requpdaccstate(fd, cid, ip)
           break
       case 0x2725:
           next = logchrif_parse_reqbanacc(fd, cid, ip)
           break
       case 0x2727:
           next = logchrif_parse_reqchgsex(fd, cid, ip)
           break
       case 0x2728:
           next = logchrif_parse_updreg2(fd, cid, ip)
           break
       case 0x272a:
           next = logchrif_parse_requnbanacc(fd, cid, ip)
           break
       case 0x272b:
           next = logchrif_parse_setacconline(fd, cid)
           break
   case 0x2736:
       next = logchrif_parse_updcharip(fd, cid)
       break
   case 0x2737:
       next = logchrif_parse_setalloffline(fd, cid)
       break
   case 0x2738:
       next = logchrif_parse_updpincode(fd)
       break
   case 0x2739:
       next = logchrif_parse_pincode_authfail(fd)
       break
   case 0x2740:
       next = logchrif_parse_bankvault(fd, cid, ip)
       break
   case 0x2742:
       next = logchrif_parse_reqvipdata(fd)
       break //Vip sys`
*/
