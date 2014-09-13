// Char server packets handler functions
package main

import "log"
import "net"
import "encoding/binary"
import "database/sql"
import "github.com/AesirWorld/global-server/auth_db"
import "github.com/AesirWorld/global-server/char_db"
import pkt "github.com/AesirWorld/global-server/packet"

// Authenticate char-server connection request
// After authenticating this char-server will have full access to all other routes!
func charServerEnter(c net.Conn, packet []byte) {
	data := &PACKET_CHR_ENTER{}
	data.Read(packet)

	log.Printf("Authenticating char-server (%s) with (%s/%s)\n", c.RemoteAddr(), data.username, data.password)

	account_id := 0

	err := db.QueryRow("SELECT account_id FROM login WHERE sex = 'S' AND account_id < 2000000 AND userid = ? AND user_pass = ? LIMIT 1",
		data.username, data.password).Scan(&account_id)

	switch {
	case err == sql.ErrNoRows:
		// User not found
	case err != nil:
		// Handler error
		log.Panicf(err.Error())
	default:
		// User found
	}

	if account_id == 0 {
		log.Printf("Char-server connection request rejcted (%s)\n", c.RemoteAddr())

		r := pkt.Writer(3)       // pkt length
		r.WriteUint16(0, 0x2711) // Packet id
		r.WriteUint8(2, 3)       // Type 3 = connection rejected.

		c.Write(r.Buffer())
	} else {
		// Check if this char-server is already connected
		_, exists := char_db.Get(account_id)

		if exists == true {
			log.Printf("Char-server (%d) already connected... Rejecting...\n", account_id)
			return
		}

		log.Printf("Char-server connection request accepted (%s) (%d)\n", c.RemoteAddr(), account_id)

		// Convert from network byte order to BigEndian, wtf :( ?
		// I dont even know whats happening anymore
		// We should be receiving the IP:PORT in network byte order (Big Endian)
		// And send it in LittleEndian, since our client uses it.
		// For some odd reason it sends us the IP in big endian and the PORT in little endian...
		buf := make([]byte, 6)
		binary.BigEndian.PutUint32(buf[0:], data.ip)
		binary.BigEndian.PutUint16(buf[4:], data.port)
		ip_htonl := binary.BigEndian.Uint32(buf[0:])
		port_htons := binary.LittleEndian.Uint16(buf[4:])

		// Add to char_db
		char := &char_db.CharDB{
			Name:  data.name,
			Ip:    ip_htonl,
			Port:  port_htons,
			Users: 0,
			Type:  data._type,
			New:   data._new,
		}

		char.Register(account_id)

		// Deregister
		defer func() {
			char_db.Delete(account_id)
		}()

		r := pkt.Writer(3)       // pkt length
		r.WriteUint16(0, 0x2711) // Packet id
		r.WriteUint8(2, 0)       // Type 0 = connection accepted.
		c.Write(r.Buffer())

		handlerCharServer(c, account_id)
	}
}

// Char server handler
// Packet router
func handlerCharServer(c net.Conn, id int) {
	packet := make([]byte, 1024)

	for {
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

	auth, ok := auth_db.Get(int(account_id))

	if ok == false {
		log.Println("Invalid auth")
		return
	}

	if auth.Login_id1 == login_id1 && auth.Login_id2 == login_id2 {
		// Write pkt
		r := pkt.Writer(25)                // pkt length
		r.WriteUint16(0, 0x2713)           // packet id
		r.WriteUint32(2, account_id)       // account_id
		r.WriteUint32(6, login_id1)        // login id 1
		r.WriteUint32(10, login_id2)       // login id 2
		r.WriteUint8(14, auth.Sex)         // sex
		r.WriteUint8(15, 0)                // ok
		r.WriteUint32(16, data.request_id) // request_id
		r.WriteUint32(20, auth.Version)    // version
		r.WriteUint8(24, auth.Clienttype)  // clienttype
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

	var email string
	var expiration_time uint32
	var group_id uint8
	var birthdate string
	var pincode string
	var pincode_change uint32
	var bank_vault uint32

	qry := db.QueryRow("SELECT email, expiration_time, group_id, CAST(birthdate AS char), pincode, pincode_change, bank_vault FROM login WHERE account_id = ?", data.aid)
	err := qry.Scan(&email, &expiration_time, &group_id, &birthdate, &pincode, &pincode_change, &bank_vault)

	if err != nil {
		log.Println(err)
		return
	}

	r := pkt.Writer(79)
	r.WriteUint16(0, 0x2717)           // packet id
	r.WriteUint32(2, data.aid)         // aid
	r.WriteString(6, email, 40)        // email
	r.WriteUint32(46, expiration_time) // expiration time
	r.WriteUint8(50, group_id)         // group id
	r.WriteUint8(51, 9)                // char slots
	r.WriteString(52, birthdate, 11)   // birth date
	r.WriteString(63, pincode, 5)      // pincode
	r.WriteUint32(68, pincode_change)  // pin code change
	r.WriteUint32(72, bank_vault)      // bank vault
	r.WriteUint8(76, 0)                // TODO: is vip
	r.WriteUint8(76, 0)                // TODO: char vip
	r.WriteUint8(78, 0)                //TODO: create a config for this (MAX_CHAR_BILLING)

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
