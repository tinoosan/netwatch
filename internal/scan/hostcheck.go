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
	IPv4Protocol = 1
)

func Pingv4(address string) (*net.IPAddr, time.Duration, error) {

	// Open a raw socket
	conn, err := icmp.ListenPacket("ip4:icmp", ListenAddress)
	if err != nil {
		return nil, 0, err
	}

	defer conn.Close()

	message := icmp.Message{
		Type: ipv4.ICMPTypeEcho,
		Body: &icmp.Echo{
			ID: os.Getpid() & 0xffff,
			Seq: 1,
			Data: []byte(""),
		},
	}

	bmessage, err := message.Marshal(nil)
	if err != nil {
		return nil, 0, err
	}

	dst, err := net.ResolveIPAddr("ip4", address)
	if err != nil {
		return dst, 0, err
	}

	start := time.Now()

	_, err = conn.WriteTo(bmessage, dst)
	if err != nil {
		return dst, 0, err
	}

	breply := make([]byte, 1500)
	n, peer, err := conn.ReadFrom(breply)
	if err != nil {
		return dst, 0, err
	}

	duration := time.Since(start)

	reply, err := icmp.ParseMessage(IPv4Protocol, breply[:n])
	if err != nil {
		return nil, 0, err
	}

	switch reply.Type {
	case ipv4.ICMPTypeEchoReply:
		return dst, duration, nil
	default:
		return dst, 0, fmt.Errorf("got %+v, from %v; want echo reply", reply, peer) 
	}

}
