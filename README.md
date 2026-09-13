[README.md](https://github.com/user-attachments/files/32157738/README.md)
# TCP Port Scanner (C / Winsock2)

A multithreaded TCP connect-scan port scanner written in C for Windows, built to understand how tools like Nmap work under the hood by implementing the core scanning logic from raw sockets rather than wrapping an existing tool.

## What it does

Given a target IP or hostname and a port range, the scanner checks each port for an active TCP listener and reports which ones are open, along with a best-guess service name (SSH, HTTP, SMB, RPC, etc.) for well-known ports.

```
PS> .\scanner.exe 127.0.0.1 1 65535
Scanning 127.0.0.1 (127.0.0.1) ports 1-65535 ...

Port 135    open  (RPC)
Port 445    open  (SMB)
Port 4096   open  (unknown)
Port 5040   open  (unknown)
Port 5357   open  (unknown)
Port 7070   open  (unknown)
Port 7681   open  (unknown)
Port 12423  open  (unknown)
Port 26769  open  (unknown)
Port 26770  open  (unknown)
Port 27275  open  (unknown)
Port 49664  open  (unknown)
Port 49665  open  (unknown)
Port 49666  open  (unknown)
Port 49667  open  (unknown)
Port 49668  open  (unknown)
Port 49670  open  (unknown)
Port 50131  open  (unknown)
Port 62251  open  (unknown)

Scan complete.
```

## How it works

- **TCP connect scan**: for each port, the scanner opens a non-blocking socket, initiates `connect()`, and uses `select()` with a timeout to determine whether the connection succeeds (port open), is refused (port closed), or times out (port filtered/no response).
- **Multithreading**: ports are distributed across a pool of worker threads (Windows threads via `CreateThread`), each pulling the next port to scan from a shared, atomically-incremented counter (`InterlockedIncrement`). This lets a full 65535-port scan complete in a reasonable amount of time instead of scanning sequentially.
- **Service name lookup**: a small static table maps common ports (21, 22, 80, 443, 445, etc.) to service names for more readable output.
- **Hostname resolution**: `getaddrinfo()` is used so the tool accepts both raw IPs and hostnames.

## Build

Requires MinGW/gcc.

```
gcc scanner.c -o scanner.exe -lws2_32
```

## Usage

```
scanner.exe <target_ip_or_host> <start_port> <end_port>
```

Example — full port range scan against localhost:

```
scanner.exe 127.0.0.1 1 65535
```

You can also scan a narrower range for a faster result, e.g. `scanner.exe 127.0.0.1 1 1024` for just the well-known ports.

## Design decision: connect scan vs. SYN scan

This tool uses a **TCP connect scan** (completes the full three-way handshake) rather than a **SYN scan** (half-open, doesn't complete the handshake). Connect scans are simpler to implement with standard sockets and don't require elevated privileges, but they're more easily logged by the target since a full connection is established. A SYN scan would require raw sockets and administrator privileges (and on Windows, typically a packet capture driver like Npcap), which was intentionally out of scope for this version — but understanding that tradeoff is part of what this project was meant to teach.

## Debugging notes

An early version of the scanner used a 300ms timeout with up to 100 concurrent threads, and consistently produced **false negatives** — genuinely open ports (verified independently with `Test-NetConnection` and `netstat -ano`) weren't being detected. Adding temporary debug output (`select()` / `SO_ERROR` return values per port) showed the connect/select logic itself was correct in isolation, which pointed to thread contention: with too many sockets competing to connect simultaneously, many legitimate connections weren't completing within the timeout window.

Reducing the thread pool to 40 and increasing the timeout to 800ms resolved it — a practical tradeoff between scan speed and accuracy under load.

## Verification

Results were cross-checked against `netstat -ano` and PowerShell's `Test-NetConnection` to confirm the scanner's findings matched what the OS itself reported as listening. A full 1-65535 scan against localhost correctly identified every port `netstat -ano` showed in a `LISTENING` state, including both well-known ports (135 - RPC, 445 - SMB) and the higher ephemeral/dynamic ports Windows assigns to background services (4096, 5040, 5357, 7070, 7681, 12423, 26769, 26770, 27275, 49664-49670, 50131, 62251). See `screenshots/` for the side-by-side comparison between the scanner's output and `netstat -ano`.

## Possible future improvements

- Implement SYN scanning using raw sockets for a stealthier, faster scan
- Add banner grabbing to identify service versions on open ports
- Export results to JSON/CSV for integration with other tools
