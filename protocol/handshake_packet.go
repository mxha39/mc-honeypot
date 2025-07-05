package protocol

import (
	"bytes"
)

type PacketHandshake struct {
	ProtocolVersion uint32
	Address         string
	Port            uint16
	NextState       byte
}

func (packet *PacketHandshake) From(data []byte) error {
	r := bytes.NewReader(data)
	var err error
	packet.ProtocolVersion, err = readVarInt(r)
	if err != nil {
		return err
	}

	packet.Address, err = ReadString(r)
	if err != nil {
		return err
	}

	packet.Port, err = readU16(r)
	if err != nil {
		return err
	}

	packet.NextState, err = r.ReadByte()
	return err
}
