// Client packet handlers
package main

import "log"
import "net"
import "encoding/binary"
import "math/rand"
import "github.com/AesirWorld/global-server/account"

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
        client := &Client{c, account_id, rand.Uint32() + 1, rand.Uint32() + 1}

        // Add to auth db
        auth_db[account_id] = &AuthDB{client.login_id1, client.login_id2}

        // Server num
        server_num := 1

        // Write response
        packet_len := 47 + 32*server_num // Packet_size + Server_list_packet_size * servers_qunt
        buf := make([]byte, packet_len)
        binary.LittleEndian.PutUint16(buf[0:], uint16(0x69))              // Packet id
        binary.LittleEndian.PutUint16(buf[2:], uint16(packet_len))        // Server list array length
        binary.LittleEndian.PutUint32(buf[4:], uint32(client.login_id1))  // Auth code part 1
        binary.LittleEndian.PutUint32(buf[8:], uint32(client.account_id)) // Account id
        binary.LittleEndian.PutUint32(buf[12:], uint32(client.login_id2)) // Auth code part 2
        binary.LittleEndian.PutUint32(buf[16:], uint32(0))                // I'm not sure what the hell this is
        copy(buf[20:20+26], []byte("not sure"))                           // This should be the last login date (length 26)
        copy(buf[46:46+1], []byte("M"))                                   // Account sex (length 1)

        if server_num > 0 {
            ip := 16777343
            binary.LittleEndian.PutUint32(buf[47:], uint32(ip))   // Char-server ip_addr
            binary.LittleEndian.PutUint16(buf[51:], uint16(6121)) // Char-server port
            copy(buf[53:53+20], []byte("Aesir"))                  // Server name (length 20)
            binary.LittleEndian.PutUint16(buf[73:], uint16(0))    // User count
            binary.LittleEndian.PutUint16(buf[75:], uint16(0))    // maintence
            binary.LittleEndian.PutUint16(buf[77:], uint16(0))    // server new?
        }
        c.Write(buf)
    }
}
