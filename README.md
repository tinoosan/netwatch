# Netwatch

Netwatch is a self-hosted CLI-based network monitoring tool written in Go. It performs high-speed ICMP (ping) scans to discover live hosts on a subnet and can optionally scan for open TCP ports on those hosts. It's designed for hands-on systems programming practice with a focus on concurrency, raw network operations, and structured output.

## Features

- Concurrent ICMP host discovery with custom echo ID tracking  
- Raw socket packet creation using `golang.org/x/net/icmp`  
- TCP port scanning with optional banner grabbing  
- CIDR parsing and host IP range generation  
- Worker pool architecture for parallelized scanning  
- Logs structured ping and port scan results to file  
- Supports human-readable and JSON output  

## Usage

### Ping scan only

```
netwatch scan --subnet 192.168.1.0/24
```

### Ping + TCP port scan

```
netwatch scan --subnet 192.168.1.0/24 --port 22,80,443
```

## Example Output

```
4 bytes from 192.168.0.1: pid=62291, icmp_type=echo reply, icmp_seq=0, data=, time=7.38ms  
4 bytes from 192.168.0.61: pid=46447, icmp_type=echo reply, icmp_seq=0, data=, time=22.05ms  
4 bytes from 192.168.0.57: pid=56683, icmp_type=echo reply, icmp_seq=0, data=, time=49.38ms  
4 bytes from 192.168.0.108: pid=65342, icmp_type=echo reply, icmp_seq=0, data=, time=237.53ms  
4 bytes from 192.168.0.208: pid=56194, icmp_type=echo reply, icmp_seq=0, data=, time=1.09ms  
4 bytes from 192.168.0.230: pid=42164, icmp_type=echo reply, icmp_seq=0, data=, time=8.67ms  
4 bytes from 192.168.0.243: pid=58017, icmp_type=echo reply, icmp_seq=0, data=, time=10.58ms  

Port 22 open on host 192.168.0.208  
Banner: SSH-2.0-OpenSSH_10.0

Port 22 open on host 192.168.0.230  
Banner: SSH-2.0-dropbear_2014.65
>U@Ǻpcurve25519-sha256@libssh.org,ecdh-sha2-nistp521,...,ssh-rsa,ssh-dss,...,hmac-sha1,hmac-md5,...none...
```

## Logging

Logs are saved to a file named `scan.log` using the internal `logger` package. Each successful ping response and relevant error is recorded.

## Planned Features

- Log filtering by IP or time  
- HTTP server mode for browser-based monitoring  
- Persistent database integration for tracking changes over time  

## Requirements

- Linux or Unix-like OS with raw socket support  
- Root privileges to send ICMP packets  

## Building

```
go build -o netwatch ./cmd
```

## License

MIT License

## Author

Tino Onyeme

---

This is a work in progress project built for hands-on systems development and learning. Expect unfinished components and ongoing refactoring.
