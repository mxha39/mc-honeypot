package protocol

import (
	"bytes"
	"errors"
	"fmt"
	"io"
)

type Packet struct {
	Id   uint32
	Data []byte
}

func (p *Packet) ReadFrom(r io.Reader, expectedId uint32) error {
	length, err := readVarInt(r)
	if err != nil {
		return err
	}
	id, err := readVarInt(r)
	if err != nil {
		return err
	}

	length = length - uint32(varIntSize(id))
	p.Id = id
	p.Data = make([]byte, length)

	_, err = io.ReadFull(r, p.Data)
	if err != nil {
		return err
	}
	if p.Id != expectedId {
		return fmt.Errorf("unexpected packet id: received %d instead of %d", p.Id, expectedId)
	}
	return err
}

func (p *Packet) WriteTo(w io.Writer) error {
	buf := bytes.NewBuffer(nil)
	err := writeVarInt(buf, uint32(varIntSize(p.Id)+len(p.Data)))
	if err != nil {
		return err
	}

	err = writeVarInt(buf, p.Id)
	if err != nil {
		return err
	}

	_, err = buf.Write(p.Data)
	if err != nil {
		return err
	}
	_, err = w.Write(buf.Bytes())
	return err
}

func varIntSize(v uint32) int {
	switch {
	case v < 1<<7:
		return 1
	case v < 1<<14:
		return 2
	case v < 1<<21:
		return 3
	case v < 1<<28:
		return 4
	default:
		return 5
	}
}

func writeVarInt(w io.Writer, v uint32) error {
	buf := make([]byte, 5)
	num := uint32(v)
	i := 0
	for {
		b := num & 0x7F
		num >>= 7
		if num != 0 {
			b |= 0x80
		}
		buf[i] = byte(b)
		i++
		if num == 0 {
			break
		}
	}
	_, err := w.Write(buf[:i])
	return err
}

func readVarInt(r io.Reader) (uint32, error) {
	var result uint32
	var shift uint

	for i := 0; i < 5; i++ {
		var b [1]byte
		_, err := r.Read(b[:])
		if err != nil {
			return 0, err
		}

		result |= uint32(b[0]&0x7F) << shift

		if b[0]&0x80 == 0 {
			return result, nil
		}

		shift += 7
	}

	return 0, errors.New("VarInt is too long")
}

func ReadString(r io.Reader) (string, error) {
	length, err := readVarInt(r)
	if err != nil {
		return "", err
	}
	if length < 1 {
		return "", errors.New("invalid string length")
	}
	buf := make([]byte, length)
	_, err = io.ReadFull(r, buf)
	if err != nil {
		return "", err
	}

	return string(buf), nil
}

func WriteString(w io.Writer, str string) error {
	err := writeVarInt(w, uint32(len(str)))
	if err != nil {
		return err
	}
	_, err = w.Write([]byte(str))
	return err
}

func readU16(r io.Reader) (uint16, error) {
	var b [2]byte
	_, err := io.ReadFull(r, b[:])
	if err != nil {
		return 0, err
	}
	val := uint16(b[0])<<8 | uint16(b[1])
	return val, nil
}
