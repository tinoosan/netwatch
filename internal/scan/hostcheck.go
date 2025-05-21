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
)

// PingHostV4 sends one or more ICMP Echo requests to a single IPv4 address.
// It prints the response details for each attempt to stdout.
//
// An error is returned if the packet cannot be sent, no valid reply is received,
// or the response cannot be parsed.
//
// The function increments the ICMP sequence number with each attempt.
// This implementation is IPv4-only and is intended for use with a single host.
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
