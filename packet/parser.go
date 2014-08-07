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

// Instanciates a new buffer and its reader funcs
func Reader(buffer []byte) *Packet {
	return &Packet{buffer}
}

func (p *Packet) ReadUint8(offset int16) uint8 {
	return uint8(p.buffer[offset])
}

func (p *Packet) ReadInt8(offset int16) int8 {
	return int8(p.buffer[offset])
}

func (p *Packet) ReadUint16(offset int16) uint16 {
	return binary.LittleEndian.Uint16(p.buffer[offset:])
}

func (p *Packet) ReadInt16(offset int16) int16 {
	return int16(binary.LittleEndian.Uint16(p.buffer[offset:]))
}

func (p *Packet) ReadUint32(offset int16) uint32 {
	return binary.LittleEndian.Uint32(p.buffer[offset:])
}

func (p *Packet) ReadInt32(offset int16) int32 {
	return int32(binary.LittleEndian.Uint32(p.buffer[offset:]))
}

func (p *Packet) ReadString(offset int16, length int16) string {
	return strings.TrimRight(string(p.buffer[offset:offset+length]), "\x00")
}

// Instanciates a new buffer and its writer funcs
func Writer(buffer []byte) *Packet {
	return &Packet{buffer}
}

func (p *Packet) WriteUint8(offset int16, payload uint8) {
	p.buffer[offset] = payload
}

func (p *Packet) WriteInt8(offset int16, payload int8) {
	p.buffer[offset] = uint8(payload)
}

func (p *Packet) WriteUint16(offset int16, payload uint16) {
	binary.LittleEndian.PutUint16(p.buffer[offset:], payload)
}

func (p *Packet) WriteInt16(offset int16, payload int16) {
	binary.LittleEndian.PutUint16(p.buffer[offset:], uint16(payload))
}

func (p *Packet) WriteUint32(offset int16, payload uint32) {
	binary.LittleEndian.PutUint32(p.buffer[offset:], payload)
}

func (p *Packet) WriteInt32(offset int16, payload int32) {
	binary.LittleEndian.PutUint32(p.buffer[offset:], uint32(payload))
}

func (p *Packet) WriteString(offset int16, payload string, length int16) {
	copy(p.buffer[offset:offset+length], payload)
}
