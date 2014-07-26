package main

import "log"
import "net"
import "os"

type Client struct {
	conn net.Conn
}

func main() {
	ln, err := net.Listen("tcp", ":6900")

	if err != nil {
		log.Println(err)
		os.Exit(1)
	}

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
			_, err := c.Read(packet)

			if err != nil {
				log.Println(err)
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
				break

			// Login packets
			case
				0x64,   // Request client login
				0x01dd: // Request client login with encrypt
				userid := string(packet[6 : 6+24])   // Offset 6, length 24
				passwd := string(packet[30 : 30+24]) // Offset 30, length 24
				log.Println("Login request from:", userid, passwd)
			}
		}
	}()
}
