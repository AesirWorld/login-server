package main

import "log"
import "net"
import "os"
import "database/sql"
import _ "github.com/ziutek/mymysql/godrv" // Go driver for database/sql package

// Database connection to global scope
var db *sql.DB

func main() {
	log.Println("Starting global-server...")

	ln, err := net.Listen("tcp", ":6900")

	if err != nil {
		log.Println("Failed to listen...")
		log.Println(err)
		os.Exit(1)
	}

	log.Println("Global-server listening on port", 6900)

	// Connect to database
	db, _ = sql.Open("mymysql", "tcp:127.0.0.1:3306*ragnarok/ragnarok/ragnarok")

	defer db.Close()

	// Test db connection
	err = db.Ping()

	if err != nil {
		log.Fatal(err)
	}

	// Accept connections
	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Println(err)
			continue
		}

		// Send conenction to some goroutine/handler
		go handleConnection(conn)
	}
}

func handleConnection(c net.Conn) {
	// TODO:
	// Check for ipbans, etc.

	defer func() {
		c.Close()
		log.Printf("Connection from %v closed.\n", c.RemoteAddr())
	}()

	// Wait for auth packet
	packet := make([]byte, 1024)

	_, err := c.Read(packet)

	if err != nil {
		log.Println(err)
		return
	}

	// First 2 bytes represent the packet_id
	packet_id := int(packet[0])<<0 | int(packet[1])<<8

	switch packet_id {
	// Client auth
	case
		PKT_ENTER,  // Request client login
		PKT_ENTER2: // Request client login with encrypt
		clientEnter(c, packet)
	// Char server auth
	case PKT_CHR_ENTER:
		charServerEnter(c, packet)
	default:
		log.Printf("Abnormal end of connection (ip: %s): Unknown packet 0x%x\n", c.RemoteAddr(), packet_id)
	}
}
