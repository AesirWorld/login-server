// Client packet handlers
package main

import "log"
import "net"
import "math/rand"
import "github.com/AesirWorld/global-server/account"
import pkt "github.com/AesirWorld/global-server/packet"

func clientEnter(c net.Conn, packet []byte) {
	data := &PACKET_ENTER{}
	data.Read(packet)

	log.Printf("Authenticating account (%s) from (%s)\n", data.username, c.RemoteAddr())
	account_id := account.Auth(data.username, data.password)

	if account_id == 0 {
		//TODO failed
	} else {
		log.Printf("Account (%s) accepted.", data.username)

		// Register player
		client := &Client{c, account_id, uint32(rand.Int31() + 1), uint32(rand.Int31() + 1)}

		log.Println("", client.login_id1, client.login_id2)

		// Add to auth db
		auth_db[account_id] = &AuthDB{client.login_id1, client.login_id2}

		// Server num
		server_num := 1

		// Write response
		packet_len := 47 + 32*server_num // Packet_size + Server_list_packet_size * servers_qunt
		r := pkt.Writer(packet_len)
		r.WriteUint16(0, uint16(0x69))              // Packet id
		r.WriteUint16(2, uint16(packet_len))        // Server list array length
		r.WriteUint32(4, uint32(client.login_id1))  // Auth code part 1
		r.WriteUint32(8, uint32(client.account_id)) // Account id
		r.WriteUint32(12, uint32(client.login_id2)) // Auth code part 2
		r.WriteUint32(16, uint32(0))                // I'm not sure what the hell this is
		r.WriteString(20, "not sure", 26)           // This should be the last login date (length 26)
		r.WriteUint8(46, 1)                         // Account sex

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
