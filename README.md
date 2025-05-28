# Netwatch

Netwatch is a self-hosted CLI-based network monitoring tool built in Go. It performs ICMP (ping) scans over local subnets to identify active devices and log their availability.

It uses raw socket operations to send and receive ICMP echo requests concurrently using a worker pool architecture, providing high-speed scanning capabilities with low overhead.

## Features

- Concurrent ICMP scanning using Go worker pools  
- Raw socket packet creation and parsing with `golang.org/x/net/icmp`  
- CIDR block parsing and host IP generation  
- Unique echo ID coordination for matching replies to sent pings  
- Log output to file via internal logger  
- Structured result collection for later processing or display  

## Usage

Run a ping scan over a subnet:

```sh
netwatch scan --subnet 192.168.1.0/24
```

Default output is in human-readable text format. JSON output will be added in a future release.

### Example Output

```text
20 bytes from 192.168.1.5: pid=21345, icmp_type=0, icmp_seq=1, time=1.27ms
Host 192.168.1.5 is up with latency of 1.27ms!
```

## Design Overview

- **WorkerPool** manages a set of goroutines that each send ICMP echo requests and wait for responses.  
- Each job contains an IP target, a channel for the result, and retry settings.  
- The system tracks each ICMP packet sent by assigning a unique echo ID, which combines process ID, worker ID, and the target IP.  
- Incoming ICMP replies are parsed and matched against the echo ID to retrieve the original job metadata.  
- Hosts are generated from a parsed CIDR subnet using custom `toUint32` and `toByte` utilities to iterate over IPs.  

## Example Scan Flow

1. Subnet `192.168.1.0/24` is parsed to generate all host IPs.  
2. Each IP is wrapped in a `Job` and dispatched to the worker queue.  
3. Workers send ICMP echo requests with unique identifiers.  
4. A listener goroutine continuously reads ICMP replies and matches them to pending jobs.  
5. Results are passed through a channel and printed to the console.  
6. All ICMP messages and failures are logged to `scan.log`.

## Logging

Logs are saved to a file named `scan.log` using the internal `logger` package. Each successful ping response and relevant error is recorded.

## Planned Features

- TCP port scanning mode  
- JSON output support  
- Log filtering by IP or time  
- HTTP server mode for browser-based monitoring  
- Persistent database integration for tracking changes over time  

## Requirements

- Linux or Unix-like OS with raw socket support  
- Root privileges to send ICMP packets  

## Building

```sh
go build -o netwatch ./cmd
```

## License

MIT License

## Author

Tino Onyeme

---

This is a work in progress project built for hands-on systems development and learning. Expect unfinished components and ongoing refactoring.

