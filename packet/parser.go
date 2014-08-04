// Binary reader/writer.
// Helpers to read and write to packet.
// This binary parser is needed since we need to communicate with some legacy services.
// For some reason this services use LittleEndian :(
package packet

import "encoding/binary"
import "strings"

type Packet struct {
	buffer []byte
}

func Reader(buffer []byte) *Packet {
	return &Packet{buffer}
}

func (p *Packet) ReadUint8(offset int16) uint8 {
	return uint8(p.buffer[offset])
}

func (p *Packet) ReadUint16(offset int16) uint16 {
	return binary.LittleEndian.Uint16(p.buffer[offset:])
}

func (p *Packet) ReadUint32(offset int16) uint32 {
	return binary.LittleEndian.Uint32(p.buffer[offset:])
}

func (p *Packet) ReadString(offset int16, length int16) string {
	return strings.TrimRight(string(p.buffer[offset:offset+length]), "\x00")
}
