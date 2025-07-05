package main

import (
	"bytes"
	"fmt"
	"log"
	"mc-honeypot/protocol"
	"net"
	"net/http"
	"os"
	"time"
)

var (
	config struct {
		address,
		kick_message,
		motd,
		protocol_version,
		protocol_text,
		favicon,
		max_slots,
		webhook_ping,
		webhook_kick string
	}
	statusMessage, kickMessage []byte
)

func main() {
	listener, err := net.Listen("tcp", config.address)
	if err != nil {
		log.Fatalln(err)
	}
	defer listener.Close()
	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Fatalln("failed to accept connection:", err)
			return
		}
		go handleConn(conn)
	}
}

func handleConn(conn net.Conn) {
	defer conn.Close()

	var packet protocol.Packet
	err := packet.ReadFrom(conn) // handshake packet
	if err != nil {
		return
	}
	if packet.Id != 0 {
		return
	}

	var handshakePacket protocol.PacketHandshake
	err = handshakePacket.From(packet.Data)
	if err != nil {
		return
	}

	switch handshakePacket.NextState {
	case 1:
		err = packet.ReadFrom(conn) // status request
		if err != nil {
			fmt.Println(err)
			return
		}
		if packet.Id != 0x00 {
			return
		}

		packet.Data = statusMessage
		err = packet.WriteTo(conn)
		if err != nil {
			fmt.Println(err)
			return
		}

		err = packet.ReadFrom(conn)
		if err != nil {
			return
		}

		err = packet.WriteTo(conn)
		if err != nil {
			return
		}
		sendWebhook(config.webhook_ping, fmt.Sprintf(`{"embeds":[{"title":"Status","description":"IP: %s\nVersion: %d\nHostname: %s:%d\nTime: %s"}]}`, conn.RemoteAddr().String(), handshakePacket.ProtocolVersion, handshakePacket.Address, handshakePacket.Port, time.Now().Format(time.RFC822)))

	case 2, 3:

		err = packet.ReadFrom(conn)
		if err != nil {
			return
		}
		var name string
		name, err = protocol.ReadString(bytes.NewReader(packet.Data))
		if err != nil {
			return
		}

		packet.Id = 0
		packet.Data = kickMessage
		err = packet.WriteTo(conn)
		if err != nil {
			return
		}

		sendWebhook(config.webhook_kick, fmt.Sprintf(`{"embeds":[{"title":"Login Attempt","description":"IP: %s\nUsername: %s\nVersion: %d\nHostname: %s:%d\nTime: %s"}]}`, conn.RemoteAddr().String(), name, handshakePacket.ProtocolVersion, handshakePacket.Address, handshakePacket.Port, time.Now().Format(time.RFC822)))
	default:
		return
	}
}

func getEnv(key, fallback string) string {
	val := os.Getenv(key)
	if val == "" {
		return fallback
	}
	return val
}

func init() {
	config.address = getEnv("ADDRESS", "0.0.0.0:25565")
	config.kick_message = getEnv("KICK_MESSAGE", "You are not Whitelisted on this Server")
	config.motd = getEnv("MOTD", "A Minecraft Server")
	config.protocol_version = getEnv("PROTOCOL_VERSION", "772") // 1.21.1
	config.protocol_text = getEnv("PROTOCOL_TEXT", "1.21.7")
	config.favicon = getEnv("FAVICON", "")
	config.webhook_ping = getEnv("WEBHOOK_PING", "")
	config.webhook_kick = getEnv("WEBHOOK_KICK", "")
	config.max_slots = getEnv("MAX_SLOTS", "20")

	tmpBuf := bytes.NewBuffer(nil)
	err := protocol.WriteString(tmpBuf, fmt.Sprintf(`{"version":{"name":"%s","protocol":%s},"players":{"max":%s,"online":0},"description":{"text":"%s"}}`, config.protocol_text, config.protocol_version, config.max_slots, config.motd))
	if err != nil {
		log.Fatalln("failed to encode motd:", err)
	}
	statusMessage = tmpBuf.Bytes()

	tmpBuf = bytes.NewBuffer(nil)

	err = protocol.WriteString(tmpBuf, `{"text": "`+config.kick_message+`"}`)
	if err != nil {
		log.Fatalln("failed to encode motd:", err)
	}
	kickMessage = tmpBuf.Bytes()

}

func sendWebhook(url, msg string) {
	if url == "" {
		return
	}
	http.Post(url, "application/json", bytes.NewBuffer([]byte(msg)))
}
