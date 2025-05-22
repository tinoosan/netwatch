package scan

import (
	"errors"
	"fmt"
	"net"
	"os"
	"time"

	"github.com/tinoosan/netwatch/internal/logger"
	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
)

const (
	ListenAddress = "0.0.0.0"
	IPv4Protocol  = 1
)

var (
	pingLogger       = logger.New("scan", "ping")
	ErrResolveIPAddr = errors.New("failed to resolve to target address %v: %w")
	ErrSocketConn    = errors.New("failed to create raw socket to listen for ICMP packets: %w")
	ErrMarshalMsg    = errors.New("failed to marshal icmp message: %w")
	ErrWrite         = errors.New("failed to send ICMP message: %w")
	ErrRead          = errors.New("failed to read ICMP response message: %w")
	ErrDeadline      = errors.New("failed to set read deadline: %w")
	ErrParse         = errors.New("failed to parse ICMP message: %w")
	ErrEchoReply     = errors.New("unexpected ICMP response: got type %v, expected echo reply")
	ErrParseSubnet   = errors.New("failed to parse subnet %v: %w")
	ErrMaskDecode    = errors.New("failed to decode mask %v: %w")
)

// toUint32 converts a 4-byte IP address or subnet mask into a 32-bit unsigned integer.
// Assumes the input slice is in big-endian order and has a length of 4
func toUint32(b []byte) uint32 {

	result := (uint32(b[0]) << 24) |
		(uint32(b[1]) << 16) |
		(uint32(b[2]) << 8) |
		(uint32(b[3]))

	return result
}

// toByte converts a 32-bit unsigned integer into a 4-byte representation of an IP address.
// The result is returned in big-endian order.
func toByte(ipUint32 uint32) []byte {
	b := make([]byte, 4)
	b[0] = (byte(ipUint32>>24) & 0xFF)
	b[1] = (byte(ipUint32>>16) & 0xFF)
	b[2] = (byte(ipUint32>>8) & 0xFF)
	b[3] = (byte(ipUint32) & 0xFF)
	return b
}

// GenerateHosts takes a CIDR subnet string (e.g. "192.168.0.0/24")
// and returns a slice of all usable host IPs within that subnet.
//
// The function excludes the network address (first IP) and broadcast address (last IP).
// It supports IPv4 only and returns an error for invalid CIDR input.
func GenerateHosts(subnet string) ([]net.IP, error) {
  ipList := make([]net.IP, 0)
	_, network, err := net.ParseCIDR(subnet)
	if err != nil {
		return nil, fmt.Errorf(ErrParseSubnet.Error(), subnet, err)
	}

	// Convert to 32-bit representation using bitshift (BE)
	maskUint32 := toUint32(network.Mask)
	networkIPUint32 := toUint32(network.IP)

	hosts := (^maskUint32 & 0xFFFFFFFF)

	for i := 1; i < int(hosts) ; i++ {
		ip := toByte(networkIPUint32 + uint32(i))
		ipList = append(ipList, net.IP(ip))
	}

	return ipList , nil
}


// PingHostV4 sends one or more ICMP Echo requests to a single IPv4 address.
// It prints the response details for each attempt to stdout.
//
// An error is returned if the packet cannot be sent, no valid reply is received,
// or the response cannot be parsed.
//
// The function increments the ICMP sequence number with each attempt.
// This implementation is IPv4-only and is intended for use with a single ho1t.
//
// Note: This function does not return structured result data. It is designed
// for use within higher-level scanning routines, which may handle concurrency,
// output formatting, and result storage externally.
func PingHostV4(addr string, attempts int) error {

	dst, err := net.ResolveIPAddr("ip4", addr)
	if err != nil {
		errMsg := fmt.Sprintf(ErrResolveIPAddr.Error(), addr, err)
		pingLogger.Log(errMsg)
		return fmt.Errorf(ErrResolveIPAddr.Error(), addr, err)
	}

	// Open a raw socket
	conn, err := icmp.ListenPacket("ip4:icmp", ListenAddress)
	if err != nil {
		errMsg := fmt.Sprintf(ErrSocketConn.Error(), err)
		pingLogger.Log(errMsg)
		return fmt.Errorf(ErrSocketConn.Error(), err)
	}

	connMsg := fmt.Sprintf("connection established with host %v", dst)
	if err = pingLogger.Log(connMsg); err != nil {
		fmt.Println(err)
	}
	fmt.Println(connMsg)

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
			errMsg := fmt.Sprintf(ErrMarshalMsg.Error(), err)
			pingLogger.Log(errMsg)
			return fmt.Errorf(ErrMarshalMsg.Error(), err)
		}

		start := time.Now()

		_, err = conn.WriteTo(bmessage, dst)
		if err != nil {
			errMsg := fmt.Sprintf(ErrWrite.Error(), err)
			pingLogger.Log(errMsg)
			return fmt.Errorf(ErrWrite.Error(), err)
		}

		err = conn.SetReadDeadline(time.Now().Add(10 * time.Second))
		if err != nil {
			errMsg := fmt.Sprintf(ErrDeadline.Error(), err)
			pingLogger.Log(errMsg)
			return fmt.Errorf(ErrDeadline.Error(), err)
		}

		breply := make([]byte, 512)
		n, peer, err := conn.ReadFrom(breply)
		if err != nil {
			errMsg := fmt.Sprintf(ErrRead.Error(), err)
			pingLogger.Log(errMsg)
			return fmt.Errorf(ErrRead.Error(), err)
		}

		duration := time.Since(start)

		parsedMessage, err := icmp.ParseMessage(IPv4Protocol, breply[:n])

		if err != nil {
			errMsg := fmt.Sprintf(ErrParse.Error(), err)
			pingLogger.Log(errMsg)
			return fmt.Errorf(ErrParse.Error(), err)
		}

		// Cannot assume that message recieved will be of type Echo Reply
		if parsedMessage.Type != ipv4.ICMPTypeEchoReply {
			echoReplyErrLog := fmt.Sprintf(ErrEchoReply.Error(), parsedMessage.Type)
			pingLogger.Log(echoReplyErrLog)
			return fmt.Errorf(ErrEchoReply.Error(), parsedMessage.Type)
		}

		echoType := parsedMessage.Type
		body := parsedMessage.Body.(*icmp.Echo)
		proto := parsedMessage.Type.Protocol()

		switch parsedMessage.Type {
		case ipv4.ICMPTypeEchoReply:
			echoReplyLog := fmt.Sprintf("%d bytes from %s: pid =%d, icmp_type=%v, icmp_seq=%d, data=%s, time:%v", body.Len(proto), peer, body.ID, echoType, body.Seq, body.Data, duration)
			pingLogger.Log(echoReplyLog)
			fmt.Printf("%d bytes from %s: pid =%d, icmp_type=%v, icmp_seq=%d, data=%s, time:%v\n", body.Len(proto), peer, body.ID, echoType, body.Seq, body.Data, duration)
		}
		time.Sleep(1 * time.Second)
	}
	pingLogger.File.Close()
	return nil

}
