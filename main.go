package main

import "log"
import "net"
import "os"
import "encoding/binary"
import "math/rand"
import "strings"
import "github.com/AesirWorld/global-server/account"

type Client struct {
	conn       net.Conn
	account_id int
	login_id1  uint32
	login_id2  uint32
}

type AuthDB struct {
	login_id1 uint32
	login_id2 uint32
}

var auth_db = make(map[int]*AuthDB)

func main() {
	ln, err := net.Listen("tcp", ":6900")

	if err != nil {
		log.Println(err)
		os.Exit(1)
	}

	// Connect to account database
	account.Connect()

	// Accept connections
	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Println(err)
			continue
		}

		// Send conenction to some goroutine/handler
		go initConnection(conn)
	}
}

func initConnection(c net.Conn) {
	// TODO:
	// Check for ipbans, etc.

	defer func() {
		c.Close()
		log.Printf("Connection from %v closed.\n", c.RemoteAddr())
	}()

	// Receive packets
	for {
		packet := make([]byte, 1024)

		length, _ := c.Read(packet)

		// Connection-closed
		if length == 0 {
			log.Println("Len 0, conenction closed")
			break
		}

		// First 2 bytes represent the packet_id
		log.Println(packet)
		packet_id := int(packet[0])<<0 | int(packet[1])<<8

		log.Printf("Received packed_id: %d - %#04x\n", packet_id, packet_id)

		switch packet_id {
		// Heartbeet packet
		case 0x200:
			log.Println("Heartbeet request")
			c.Write([]byte("pong"))
			break

		// Login packets
		case
			0x64,   // Request client login
			0x01dd: // Request client login with encrypt
			userid := strings.TrimRight(string(packet[6:6+24]), "\x00")   // Offset 6, length 24
			passwd := strings.TrimRight(string(packet[30:30+24]), "\x00") // Offset 30, length 24

			log.Printf("Authenticating account (%s) from (%s)\n", userid, c.RemoteAddr())
			account_id := account.Auth(userid, passwd)

			if account_id == 0 {
				//TODO failed
			} else {
				log.Printf("Account (%s) accepted.", userid)

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

			return
		//case 0x1db: next = logclif_parse_reqkey(fd, sd); break;
		// Char-server login request
		case 0x2710:
			userid := strings.TrimRight(string(packet[2:2+24]), "\x00")   // Offset 6, length 24
			passwd := strings.TrimRight(string(packet[26:26+24]), "\x00") // Offset 30, length 24

			log.Printf("Authenticating char-server (%s) with (%s/%s)\n", c.RemoteAddr(), userid, passwd)
			account_id := account.AuthServer(userid, passwd)

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
				handleCharServer(c, account_id)
			}
			return
		default:
			log.Printf("Abnormal end of connection (ip: %s): Unknown packet 0x%x\n", c.RemoteAddr(), packet_id)
			return
		}
	}
}

func handleCharServer(c net.Conn, id int) {
	// Receive packets
	for {
		packet := make([]byte, 1024)

		length, _ := c.Read(packet)

		// Connection-closed
		if length == 0 {
			log.Println("Len 0, conenction closed")
			break
		}

		// First 2 bytes represent the packet_id
		packet_id := int(packet[0])<<0 | int(packet[1])<<8

		switch packet_id {
		case 0x2712:
			account_id := int(binary.LittleEndian.Uint32(packet[2:]))
			login_id1 := binary.LittleEndian.Uint32(packet[6:])
			login_id2 := binary.LittleEndian.Uint32(packet[10:])

			log.Printf("Char-server req auth (%d) (%d/%d)\n", account_id, login_id1, login_id2)

			auth := auth_db[account_id]

			log.Println("Auth db match", auth.login_id1, auth.login_id2)

			if auth.login_id1 == login_id1 && auth.login_id2 == login_id2 {
				log.Println("Auth accepted")
				res := make([]byte, 25)
				binary.LittleEndian.PutUint16(res, uint16(0x2713))
				c.Write(res)
			} else {

			}

			break
		/*
			case 0x2714:
				next = logchrif_parse_ackusercount(fd, cid)
				break
			case 0x2715:
				next = logchrif_parse_updmail(fd, cid, ip)
				break
			case 0x2716:
				next = logchrif_parse_reqaccdata(fd, cid, ip)
				break
		*/
		// Keep-alive (ping) from char-server
		case 0x2719:
			log.Printf("Responding to ping request from char-server (%d)\n", id)
			res := make([]byte, 2)
			binary.LittleEndian.PutUint16(res, uint16(0x2718))
			c.Write(res)
			break
			/*
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
				case 0x272c:
					next = logchrif_parse_setaccoffline(fd)
					break
			*/
		// User online count in this char-server
		// This func is void, just ignore it. User online count is made by the login-server now.
		case 0x272d:
			break
		/*
			case 0x272e:
				next = logchrif_parse_reqacc2reg(fd)
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
		default:
			log.Printf("Abnormal packet received from authenticated char-server (%s): %#04x\n", c.RemoteAddr(), packet_id)
			log.Println(packet)
		}
	}
}
