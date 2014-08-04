// Char server packets handler functions
package main

import "log"
import "net"
import "encoding/binary"
import "github.com/AesirWorld/global-server/account"

// Char server handler
// Packet router
func handlerCharServer(c net.Conn, id int) {
    for {
        packet := make([]byte, 1024)

        length, _ := c.Read(packet)

        // Connection-closed
        if length == 0 {
            log.Println("Char-server disconnected")
            break
        }

        // First 2 bytes represent the packet_id
        packet_id := int(packet[0])<<0 | int(packet[1])<<8

        switch packet_id {
        case PKT_CHR_REQAUTHTOKEN: charServerReqAuth(c, packet)
        case PKT_CHR_HEARTBEAT: charServerHeartBeat(c, packet)
        case PKT_CHR_USERCOUNT: charServerOnlineCount(c, packet)
        default:
            log.Printf("Abnormal packet received from authenticated char-server (%s): %#04x\n", c.RemoteAddr(), packet_id)
            log.Println(packet)
        }
    }
}

func charServerEnter(c net.Conn, packet []byte) {
    data := &PACKET_CHR_ENTER{}
    data.Read(packet)

    log.Printf("Authenticating char-server (%s) with (%s/%s)\n", c.RemoteAddr(), data.username, data.password)
    account_id := account.AuthServer(data.username, data.password)

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
        handlerCharServer(c, account_id)
    }
}

func charServerReqAuth(c net.Conn, packet []byte) {
    data := &PACKET_CHR_REQAUTHTOKEN{}
    data.Read(packet)
    account_id := data.account_id
    login_id1 := data.login_id1
    login_id2 := data.login_id2

    log.Printf("Char-server req auth (%d) (%d/%d)\n", account_id, login_id1, login_id2)

    auth := auth_db[int(account_id)]

    log.Println("Auth db match", auth.login_id1, auth.login_id2)

    if auth.login_id1 == login_id1 && auth.login_id2 == login_id2 {
        log.Println("Auth accepted")
        res := make([]byte, 25)
        binary.LittleEndian.PutUint16(res, uint16(0x2713))
        c.Write(res)
    } else {

    }
}

func charServerHeartBeat(c net.Conn, packet []byte) {
    log.Printf("Responding to ping request from char-server\n")
    res := make([]byte, 2)
    binary.LittleEndian.PutUint16(res, uint16(0x2718))
    c.Write(res)
}

// User online count in this char-server
// This func is void, just ignore it. User online count is made by the login-server now.
func charServerOnlineCount(c net.Conn, packet []byte) {

}

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
