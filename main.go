package main

import "log"
import "net"
import "os"
import "encoding/binary"
import "strings"
import "github.com/AesirWorld/global-server/account"

type Client struct {
	conn net.Conn
}

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

	go func() {
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

				log.Printf("Authenticating account (%s/%s) from (%s)]\n", c.RemoteAddr(), userid, passwd)
				account_id := account.Auth(userid, passwd)

				if account_id == 0 {
					//TODO failed
				} else {
					//TODO sucess
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
					id := uint16(0x2711) // packet id
					res := make([]byte, 3)
					binary.LittleEndian.PutUint16(res, id)
					res[2] = 1 // Type 0 = connection accepted.
					c.Write(res)
				} else {
					log.Printf("Char-server connection request accepted (%s) (%d)\n", c.RemoteAddr(), account_id)
					id := uint16(0x2711) // packet id
					res := make([]byte, 3)
					binary.LittleEndian.PutUint16(res, id)
					res[2] = 0 // Type 0 = connection accepted.
					c.Write(res)
					handleCharServer(c)
				}
				return
			default:
				log.Printf("Abnormal end of connection (ip: %s): Unknown packet 0x%x\n", c.RemoteAddr(), packet_id)
				return
			}
		}
	}()
}

func handleCharServer(c net.Conn) {
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

		log.Println("Received packet from char-server", packet_id)

		switch packet_id {
		/*
			case 0x2712:
				next = logchrif_parse_reqauth(fd, cid, ip)
				break
			case 0x2714:
				next = logchrif_parse_ackusercount(fd, cid)
				break
			case 0x2715:
				next = logchrif_parse_updmail(fd, cid, ip)
				break
			case 0x2716:
				next = logchrif_parse_reqaccdata(fd, cid, ip)
				break
			case 0x2719:
				next = logchrif_parse_keepalive(fd)
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
			case 0x272c:
				next = logchrif_parse_setaccoffline(fd)
				break
			// User online count in this char-server
			case 0x272d:
				next = logchrif_parse_updonlinedb(fd, cid)
				break
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
