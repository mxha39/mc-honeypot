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
		kickMessage,
		motd,
		protocolVersion,
		protocolText,
		maxSlots,
		webhookPing,
		webhookKick string
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
	err := packet.ReadFrom(conn, 0x00) // handshake packet
	if err != nil {
		return
	}

	var handshakePacket protocol.PacketHandshake
	err = handshakePacket.From(packet.Data)
	if err != nil {
		return
	}

	switch handshakePacket.NextState {
	case 1:
		err = packet.ReadFrom(conn, 0x00) // status request
		if err != nil {
			fmt.Println(err)
			return
		}
		sendWebhook(config.webhookPing, fmt.Sprintf(`{"embeds":[{"title":"Status","description":"IP: %s\nVersion: %d\nHostname: %s:%d\nTime: %s"}]}`, conn.RemoteAddr().String(), handshakePacket.ProtocolVersion, handshakePacket.Address, handshakePacket.Port, time.Now().Format(time.RFC822)))

		packet.Data = statusMessage
		err = packet.WriteTo(conn) // status response
		if err != nil {
			fmt.Println(err)
			return
		}

		err = packet.ReadFrom(conn, 1) // ping request
		if err != nil {
			return
		}

		err = packet.WriteTo(conn) // ping response
		if err != nil {
			return
		}
		
	case 2, 3:

		err = packet.ReadFrom(conn, 0) // login start
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
		err = packet.WriteTo(conn) // disconnect
		if err != nil {
			return
		}

		sendWebhook(config.webhookKick, fmt.Sprintf(`{"embeds":[{"title":"Login Attempt","description":"IP: %s\nUsername: %s\nVersion: %d\nHostname: %s:%d\nTime: %s"}]}`, conn.RemoteAddr().String(), name, handshakePacket.ProtocolVersion, handshakePacket.Address, handshakePacket.Port, time.Now().Format(time.RFC822)))
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
	config.kickMessage = getEnv("KICK_MESSAGE", "You are not Whitelisted on this Server")
	config.motd = getEnv("MOTD", "A Minecraft Server")
	config.protocolVersion = getEnv("PROTOCOL_VERSION", "772")
	config.protocolText = getEnv("PROTOCOL_TEXT", "1.21.7")
	config.webhookPing = getEnv("WEBHOOK_PING", "")
	config.webhookKick = getEnv("WEBHOOK_KICK", "")
	config.maxSlots = getEnv("MAX_SLOTS", "20")

	tmpBuf := bytes.NewBuffer(nil)
	err := protocol.WriteString(tmpBuf, fmt.Sprintf(`{"version":{"name":"%s","protocol":%s},"players":{"max":%s,"online":0},"description":{"text":"%s"}}`, config.protocolText, config.protocolVersion, config.maxSlots, config.motd))
	if err != nil {
		log.Fatalln("failed to encode motd:", err)
	}
	statusMessage = tmpBuf.Bytes()

	tmpBuf = bytes.NewBuffer(nil)

	err = protocol.WriteString(tmpBuf, `{"text": "`+config.kickMessage+`"}`)
	if err != nil {
		log.Fatalln("failed to encode kick message:", err)
	}
	kickMessage = tmpBuf.Bytes()

}

func sendWebhook(url, msg string) {
	if url == "" {
		return
	}
	http.Post(url, "application/json", bytes.NewBuffer([]byte(msg)))
}
