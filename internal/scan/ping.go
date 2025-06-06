package scan

import (
	"errors"
	"fmt"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/tinoosan/netwatch/internal/logger"
	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
)

//Target host holds all info for entire lifecyle so needs to persist throughout

type TargetHost struct {
	IP        net.IP
	Up        bool
	OpenPorts []PortScanResult
	ICMPErr       error
}

type PingJob struct {
	ID         int
	Target     *TargetHost
	ResultChan chan *PingResult
	SentAt     time.Time
	Attempts   int
	MaxRetries int
}

type PingResult struct {
	Err     error
}

type PingWorkerPool struct {
	Workers  int
	JobQueue chan *PingJob
	Jobs     map[int]*PingJob
	wg       *sync.WaitGroup
	logger   *logger.Logger
	conn     *icmp.PacketConn
	mu       *sync.Mutex
}

const (
	ListenAddress = "0.0.0.0"
	IPv4Protocol  = 1
)

var (
	ErrResolveIPAddr = errors.New("failed to resolve to target address %v: %w\n")
	ErrSocketConn    = errors.New("failed to create raw socket to listen for ICMP packets: %w\n")
	ErrMarshalMsg    = errors.New("failed to marshal icmp message: %w\n")
	ErrWrite         = errors.New("failed to send ICMP message: %w\n")
	ErrRead          = errors.New("failed to read ICMP response message: %w\n")
	ErrDeadline      = errors.New("failed to set read deadline: %w\n")
	ErrParse         = errors.New("failed to parse ICMP message: %w\n")
	ErrParseSubnet   = errors.New("failed to parse subnet %v: %w\n")
	ErrMaskDecode    = errors.New("failed to decode mask %v: %w\n")
	ErrPingTimeout   = errors.New("ping time out for host %v\n")
)

func NewPingWorkerPool(numOfWorkers int, jobQueue int, pingLogger *logger.Logger) *PingWorkerPool {
	wg := &sync.WaitGroup{}
	conn, err := icmp.ListenPacket("ip4:icmp", ListenAddress)
	if err != nil {
		fmt.Printf(ErrSocketConn.Error(), err)
	}
	return &PingWorkerPool{
		Workers:  numOfWorkers,
		JobQueue: make(chan *PingJob, jobQueue),
		wg:       wg,
		logger:   pingLogger,
		conn:     conn,
		Jobs:     make(map[int]*PingJob),
		mu:       &sync.Mutex{},
	}
}

func (wp *PingWorkerPool) Worker(id int) {
	defer wp.wg.Done()
	for job := range wp.JobQueue {
		replyReceived := false
		attempts := 1
		seq := 0
		for attempts <= job.MaxRetries && (!replyReceived) {
			job.Attempts = job.Attempts + 1
			//fmt.Printf("Attempt: %d Worker %d pinging IP %v with echoID %v\n", job.Attempts, id, job.Target, echoID)
			err := wp.SendPing(job, seq)
			if err != nil {
				result := &PingResult{
					Err: err,
				}
				job.ResultChan <- result
			}
			attempts++
			seq++

			select {
			case result := <-job.ResultChan:
				job.Target.Up = true
				job.Target.ICMPErr = result.Err
				replyReceived = true
			case <-time.After(2 * time.Second):
			}
		}

		if replyReceived {
			wp.mu.Lock()
			delete(wp.Jobs, job.ID)
			wp.mu.Unlock()
		} else {
			job.Target.Up = false
			job.Target.ICMPErr = fmt.Errorf(ErrPingTimeout.Error(), job.Target.IP)
		}
	}
}

func (wp *PingWorkerPool) AddJob(job *PingJob) {
	wp.JobQueue <- job
	wp.Jobs[job.ID] = job
}

func (wp *PingWorkerPool) Start() {

	for i := 1; i <= wp.Workers; i++ {
		wp.wg.Add(1)
		//time.Sleep(20 * time.Millisecond)
		go wp.Worker(i)
	}
}

func (wp *PingWorkerPool) Process() {
	if wp.conn != nil {
		for len(wp.JobQueue) > 0{
			parsedMessage, peer, err := wp.ReadReply()
			if err != nil {
				if isConnectionClosed(err) {
					return
				}
			}

			if parsedMessage != nil {
				if parsedMessage.Type == ipv4.ICMPTypeEchoReply {
					body := parsedMessage.Body.(*icmp.Echo)

					wp.mu.Lock()
					job, ok := wp.Jobs[body.ID]
					wp.mu.Unlock()

					if ok {
						duration := time.Since(job.SentAt)
						//fmt.Printf("checking type for reply for body ID %v\n", body.ID)
						proto := parsedMessage.Type.Protocol()
						echoReplyLog := fmt.Sprintf("%d bytes from %s: pid =%d, icmp_type=%v, icmp_seq=%d, data=%s, time=%s", body.Len(proto), peer, body.ID, parsedMessage.Type, body.Seq, body.Data, duration)
						wp.logger.Log(echoReplyLog)
						fmt.Printf("%d bytes from %s: pid =%d, icmp_type=%v, icmp_seq=%d, data=%s, time=%s\n", body.Len(proto), peer, body.ID, parsedMessage.Type, body.Seq, body.Data, duration)

						result := &PingResult{
							Err:     nil,
						}
						job.ResultChan <- result
					}
					continue
				}
				continue
			}
			continue
		}
	}
}

func (wp *PingWorkerPool) Wait() {
	defer wp.conn.Close()
	close(wp.JobQueue)
	wp.wg.Wait()
}

func isConnectionClosed(err error) bool {
	if err != nil && strings.Contains(err.Error(), "use of closed network connection") {
		return true
	}
	return false
}

func GenerateHosts(subnet string) ([]*TargetHost, error) {
	ipList := make([]net.IP, 0)
	_, network, err := net.ParseCIDR(subnet)
	if err != nil {
		return nil, fmt.Errorf(ErrParseSubnet.Error(), subnet, err)
	}

	// Convert to 32-bit representation using bitshift (BE)
	maskUint32 := toUint32(network.Mask)
	networkIPUint32 := toUint32(network.IP)

	hosts := (^maskUint32 & 0xFFFFFFFF)

	for i := 1; i < int(hosts); i++ {
		ip := toByte(networkIPUint32 + uint32(i))
		ipList = append(ipList, net.IP(ip))
	}
	//fmt.Println(ipList)
	var targetHosts []*TargetHost
	for _, ip := range ipList {
		targetHost := &TargetHost{IP: ip}
		targetHosts = append(targetHosts, targetHost)
	}
	return targetHosts, nil
}

func (wp *PingWorkerPool) SendPing(job *PingJob, seq int) error {

	msg := icmp.Message{
		Type: ipv4.ICMPTypeEcho,
		Body: &icmp.Echo{
			ID:   job.ID,
			Seq:  seq,
			Data: []byte(""),
		},
	}

	dst, err := net.ResolveIPAddr("ip4", job.Target.IP.String())
	if err != nil {
		errMsg := fmt.Sprintf(ErrResolveIPAddr.Error(), job.Target.IP.String(), err)
		wp.logger.Log(errMsg)
		return fmt.Errorf(ErrResolveIPAddr.Error(), job.Target.IP.String(), err)
	}

	bmessage, err := msg.Marshal(nil)
	if err != nil {
		return fmt.Errorf(ErrMarshalMsg.Error(), err)
	}

	job.SentAt = time.Now()

	_, err = wp.conn.WriteTo(bmessage, dst)
	if err != nil {
		return fmt.Errorf(ErrWrite.Error(), err)
	}

	return nil
}

func (wp *PingWorkerPool) ReadReply() (*icmp.Message, net.Addr, error) {
	var peer net.Addr
	err := wp.conn.SetReadDeadline(time.Now().Add(11 * time.Second))
	if err != nil {
		return nil, peer, fmt.Errorf(ErrDeadline.Error(), err)
	}

	breply := make([]byte, 512)
	n, peer, err := wp.conn.ReadFrom(breply)
	if err != nil {
		return nil, peer, fmt.Errorf(ErrRead.Error(), err)
	}

	parsedMessage, err := icmp.ParseMessage(IPv4Protocol, breply[:n])

	if err != nil {
		return nil, peer, fmt.Errorf(ErrParse.Error(), err)
	}

	return parsedMessage, peer, nil
}

func ipToUint32(ip net.IP) uint32 {
	ip = ip.To4()
	if ip == nil {
		return 0
	}
	return uint32(ip[0])<<24 | uint32(ip[1])<<16 | uint32(ip[2])<<8 | uint32(ip[3])
}

// toUint32 converts a 4-byte IP address or subnet mask into a 32-bit unsigned integer.
// Assumes the input slice is in big-endian order and has a length of 4
func toUint32(b []byte) uint32 {
	return (uint32(b[0]) << 24) | (uint32(b[1]) << 16) | (uint32(b[2]) << 8) | (uint32(b[3]))

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

func GenerateEchoID(ip net.IP, WorkerId int) int {
	return (os.Getpid() & 0xffff) ^ (WorkerId << 8) ^ (int(ipToUint32(ip)))&0xffff
}
