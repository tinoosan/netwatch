package scan

import (
	"fmt"
	"net"
	"os"
	"time"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
)

const (
	ListenAddress = "0.0.0.0"
	IPv4Protocol  = 1
)


func PingHost(addr string, attempts int) error {

	dst, err := net.ResolveIPAddr("ip4", addr)
	if err != nil {
		return fmt.Errorf("failed to resolve to target address: %w", err)
	}

	// Open a raw socket
	conn, err := icmp.ListenPacket("ip4:icmp", ListenAddress)
	if err != nil {
		return fmt.Errorf("failed to create raw socket to listen for ICMP packets: %w", err)
	}

	defer conn.Close()

	for i := range attempts {

		message := icmp.Message{
			Type: ipv4.ICMPTypeEcho,
			Body: &icmp.Echo{
				ID:   os.Getpid() & 0xffff,
				Seq:  i,
				Data: []byte(""),
			},
		}

		bmessage, err := message.Marshal(nil)
		if err != nil {
			return fmt.Errorf("failed to marshal icmp message: %w", err)
		}

		start := time.Now()

		_, err = conn.WriteTo(bmessage, dst)
		if err != nil {
			return fmt.Errorf("failed to send ICMP message: %w", err)
		}

		breply := make([]byte, 512)
		n, peer, err := conn.ReadFrom(breply)
		if err != nil {
			return fmt.Errorf("failed to read ICMP response message: %w", err)
		}

		duration := start.Sub(start)

		parsedMessage, err := icmp.ParseMessage(IPv4Protocol, breply[:n])
		if err != nil {
			return fmt.Errorf("failed to parse ICMP message: %w", err)
		}

		echoType := parsedMessage.Type
		body := parsedMessage.Body.(*icmp.Echo)
		proto := parsedMessage.Type.Protocol()

		switch parsedMessage.Type {
		case ipv4.ICMPTypeEchoReply:
			fmt.Printf("%d bytes from %s: pid =%d, icmp_type=%v, icmp_seq=%d, data=%s, time:%dms\n", body.Len(proto), peer, body.ID, echoType, body.Seq, body.Data, duration)
		default:
			fmt.Printf("got %+v, from %v; want echo reply", parsedMessage, peer)
		}
		time.Sleep(1 * time.Second)
	}
	return nil

}
