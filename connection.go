package main

import "log"
import "net"

// Connection goroutine
func connectionHandler(c net.Conn) {
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
    case PKT_ENTER, PKT_ENTER2:
        clientEnter(c, packet)
    // Char server auth
    case PKT_CHR_ENTER:
        charServerEnter(c, packet)
    default:
        log.Printf("Abnormal end of connection (ip: %s): Unknown packet 0x%x\n", c.RemoteAddr(), packet_id)
    }
}
