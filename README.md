
---

# Netwatch

Netwatch is a high-performance network scanning tool built in Go. It leverages raw socket operations and a worker pool model to perform concurrent ICMP ping scans, significantly reducing the time needed to map out live hosts within a subnet.

## Features

* **Concurrent ICMP Scanning**: Utilizes a worker pool to ping multiple IP addresses simultaneously, drastically reducing scan times.
* **Dynamic Worker Pool**: The number of workers scales with the number of hosts, enabling efficient resource utilization.
* **Structured Logging**: Logs are output in a consistent JSON format, making it easy to parse and store.
* **Modular Design**: Separation of concerns between pinging and reply handling, allowing for clean, maintainable code.
* **Extensible**: Designed with future enhancements in mind, such as adding TCP port scanning or integrating with a database.

## Installation

1. **Clone the repository:**

   ```bash
   git clone https://github.com/tinoosan/netwatch.git
   cd netwatch
   ```

2. **Build the binary:**

   ```bash
   go build -o netwatch
   ```

3. **Run the binary with appropriate flags (note: flags are still a work in progress):**

   ```bash
   ./netwatch scan --subnet 192.168.1.0/24 --output json
   ```

## Usage

To perform a ping scan on a given subnet:

```bash
./netwatch scan --subnet 192.168.1.0/24 --output json
```

### Flags

* `--subnet` (`-s`): CIDR block of the subnet to scan (default: `192.168.1.0/24`).
* `--output` (`-o`): Output format, either `text` or `json` (default: `text`).

## Example

Scanning a subnet using `netwatch`:

```bash
./netwatch scan --subnet 192.168.0.0/16 --output json
```

---

