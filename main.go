package main

import (
	"bytes"
	"fmt"
	"log"
	"mc-honeypot/protocol"
	"net"
	"net/http"
	"os"
	"sync"
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
	counterPing                = make(map[string]uint32)
	counterJoin                = make(map[string]uint32)
	counterMux                 = &sync.Mutex{}
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

	ip := getIP(conn.RemoteAddr().String())

	switch handshakePacket.NextState {
	case 1:
		err = packet.ReadFrom(conn, 0x00) // status request
		if err != nil {
			fmt.Println(err)
			return
		}

		counterMux.Lock()
		counterPing[ip]++
		n := counterPing[ip]
		counterMux.Unlock()

		sendWebhook(config.webhookPing, fmt.Sprintf(`{"content": "Ping from [%s](https://ipinfo.io/%s/json) (%s:%d) v%d #%d"}`, conn.RemoteAddr().String(), ip, handshakePacket.Address, handshakePacket.Port, handshakePacket.ProtocolVersion, n))

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

		packet.WriteTo(conn) // ping response

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
		packet.WriteTo(conn) // disconnect

		counterMux.Lock()
		counterJoin[ip+name]++
		n := counterJoin[ip+name]
		counterMux.Unlock()

		sendWebhook(config.webhookKick, fmt.Sprintf(`{"content": "Join from [%s](<https://laby.net/@%s>) [%s](https://ipinfo.io/%s/json) (%s:%d) v%d #%d"}`, name, name, conn.RemoteAddr().String(), ip, handshakePacket.Address, handshakePacket.Port, handshakePacket.ProtocolVersion, n))
	}
}

func getIP(addr string) string {
	ip, _, err := net.SplitHostPort(addr)
	if err != nil {
		return addr
	}
	return ip
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
