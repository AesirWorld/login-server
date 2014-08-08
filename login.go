// Client packet handlers
package main

import "log"
import "net"
import "math/rand"
import "database/sql"
import "github.com/AesirWorld/global-server/auth_db"
import pkt "github.com/AesirWorld/global-server/packet"

func clientEnter(c net.Conn, packet []byte) {
	data := &PACKET_ENTER{}
	data.Read(packet)

	log.Printf("Authenticating account (%s) from (%s)\n", data.username, c.RemoteAddr())

	account_id := 0
	sex := ""
	err := db.QueryRow("SELECT account_id, sex FROM login WHERE sex != 'S' AND userid = ? AND user_pass = ? LIMIT 1", data.username, data.password).Scan(&account_id, &sex)

	switch {
	case err == sql.ErrNoRows:
		// User not found
	case err != nil:
		// Handler error
	default:
		// User found
	}

	if account_id == 0 {
		//TODO failed
	} else {
		log.Printf("Account (%s) accepted.", data.username)

		// Sex to number
		// 0 Female : 1 Male : 2 Server
		sex_num := 0

		switch sex {
		case "M":
			sex_num = 1
		case "S":
			sex_num = 2
		}

		// Register client/player
		//client := &Client{c, account_id}

		// AuthCode
		login_id1 := uint32(rand.Int31() + 1)
		login_id2 := uint32(rand.Int31() + 1)

		// Add to auth db
		auth := &auth_db.AuthDB{
			Account_id: account_id,
			Login_id1:  login_id1,
			Login_id2:  login_id2,
			Sex:        uint8(sex_num),
			Version:    data.version,
			Clienttype: data.clienttype,
		}

		// Register to auth_db
		auth.Register(account_id)

		// Server num
		server_num := 1

		// Write response
		packet_len := 47 + 32*server_num // Packet_size + Server_list_packet_size * servers_qunt
		r := pkt.Writer(packet_len)
		r.WriteUint16(0, uint16(0x69))       // Packet id
		r.WriteUint16(2, uint16(packet_len)) // Server list array length
		r.WriteUint32(4, uint32(login_id1))  // Auth code part 1
		r.WriteUint32(8, uint32(account_id)) // Account id
		r.WriteUint32(12, uint32(login_id2)) // Auth code part 2
		r.WriteUint32(16, uint32(0))         // I'm not sure what the hell this is
		r.WriteString(20, "not sure", 26)    // This should be the last login date (length 26)
		r.WriteUint8(46, uint8(sex_num))     // Account sex

		if server_num > 0 {
			r.WriteUint32(47, uint32(16777343)) // Char-server ip_addr
			r.WriteUint16(51, uint16(6121))     // Char-server port
			r.WriteString(53, "Aesir", 20)      // Server name (length 20)
			r.WriteUint16(73, uint16(0))        // User count
			r.WriteUint16(75, uint16(0))        // maintence
			r.WriteUint16(77, uint16(0))        // server new?
		}
		c.Write(r.Buffer())
	}
}
