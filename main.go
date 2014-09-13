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
		go connectionHandler(conn)
	}
}
