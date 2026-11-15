# Hardware Verification & Test Matrix

Comprehensive verification of `wg-obfuscator v1.6+-nolibc` was conducted on physical hardware across different CPU architectures and network topologies to validate zero-heap operation, the dual-stack epoll event loop, and all ingress/egress cross-family bridging combinations.

## Hardware & Environment

- **Client Device**:
  - Hardware: Xiaomi Wi-Fi Router (MediaTek MT7621 / MT7628 MIPS32r2 Little-Endian)
  - Firmware: Padavan Linux
  - Binary: `wg-obfuscator-nolibc-mips32el` (~24 KB)
- **Server Node**:
  - Hardware: Cloud VPS (x86_64 Linux)
  - Binary: `wg-obfuscator-nolibc-x86_64` (~25 KB)
- **IPv6 Transit Network**:
  - Native IPv6 and encrypted overlay mesh
- **WireGuard Overlay**:
  - Subnet: `10.8.0.0/24` (`10.8.0.1` server, `10.8.0.2` client)

---

## Test Matrix & Results

### Test 1: Dual-Stack Ingress on Server + IPv4 Client (IPv4-Mapped Address Handling)

- **Topology**:
  - Client (MIPS32el router): IPv4 WAN connection -> Server `203.0.113.10:38472`
  - Server: `source-if = [::]`, `target = 127.0.0.1:51820`
- **Verified Mechanisms**:
  - Server listening socket opened as `WS_AF_INET6` with `IPV6_V6ONLY = 0`.
  - Inbound IPv4 datagrams received via Linux kernel IPv4-mapped notation (`::ffff:198.51.100.25`).
  - DPI-safe STUN handling: automatic detection of `::ffff:0:0/96` prefix emitting standard 4-byte STUN `XOR-MAPPED-ADDRESS` (family `0x01`).
  - Payloads decoded and forwarded to local IPv4 WireGuard daemon (`127.0.0.1:51820`).
- **Result**: Handshake established immediately. ICMP ping across WireGuard (`10.8.0.1`): **0% packet loss**, proxy traffic verified.

---

### Test 2: Cross-Family Local Bridge (IPv4 WAN Ingress -> IPv6 WireGuard Egress)

- **Topology**:
  - Client (MIPS32el router): Connects via IPv4 WAN `203.0.113.10:38472`
  - Server: `source-if = [::]`, `target = [::1]:51820` (IPv6 Loopback)
- **Verified Mechanisms**:
  - Ingress packet arrives over public IPv4.
  - Server decodes packet and transmits payload into kernel WireGuard listening strictly on IPv6 loopback (`[::1]:51820`).
  - Reverse datagram from WireGuard returned over IPv6 loopback, re-obfuscated, and dispatched back to the IPv4 WAN client.
  - Verified via `wg show` on the server: endpoint registered as `[::1]:46902`.
- **Result**: Handshake established. ICMP ping: **0% packet loss**, bidirectional tunnel transparent.

---

### Test 3: Full IPv6 WAN Transit (IPv4 Local Client -> Native IPv6 WAN -> IPv4 Local Server)

- **Topology**:
  - Client (MIPS32el router): `source-if = 127.0.0.1`, `target = [2001:db8:server::1]:38472` (IPv6 Transit)
  - Server: `source-if = [::]`, `target = 127.0.0.1:51820`
- **Verified Mechanisms**:
  - Correct parsing of `[IPv6]:port` syntax in configuration and CLI.
  - Router obfuscator receives local IPv4 datagrams from WireGuard kernel module (`127.0.0.1:13255`), obfuscates them, and encapsulates into native IPv6 UDP packets.
  - Server receives native IPv6 packets from client `[2001:db8:client::2]`.
  - STUN responder generates 16-byte `XOR-MAPPED-ADDRESS` (family `0x02`, 128-bit XOR with Magic Cookie and Transaction ID).
  - Server forwards decoded payloads to IPv4 WireGuard endpoint (`127.0.0.1:51820`).
- **Server Log Excerpt**:
  ```text
  wg-obfuscator[11289]: [main][I] Handshake established with [2001:db8:client::2]:18628 (direct, local port 42157)
  ```
- **Result**: ICMP ping to `10.8.0.1`: **0% packet loss** (RTT ~97-105 ms over transit mesh), continuous traffic stable.

---

### Test 4: Dual-Stack Ingress on Client + IPv6 Transit + IPv6 Egress on Server

- **Topology**:
  - Client (MIPS32el router): `source-if = [::]`, `target = [2001:db8:server::1]:38472`
  - Server: `source-if = [::]`, `target = [::1]:51820`
- **Verified Mechanisms**:
  - Router listens on `[::]:13255` accepting any local family.
  - WAN transport runs over native IPv6.
  - Server forwards decoded datagrams to `[::1]:51820`.
- **Result**: Full address family decoupling functioning on both endpoints simultaneously. **0% packet loss**.

---

### Test 5: Domain Name Resolution for IPv6 (`target = hostname:port`)

- **Topology**:
  - `/etc/hosts` entry on router: `2001:db8:server::1 vps-endpoint.local`
  - Client config: `target = vps-endpoint.local:38472`
- **Verified Mechanisms**:
  - Freestanding `nolibc` resolver without libc/glibc successfully parsed `/etc/hosts`, resolved the hostname to an IPv6 literal, and initiated socket communication to the target node.
- **Router Log Excerpt**:
  ```text
  [main][I] WireGuard obfuscator v1.6+-nolibc started on [0:0:0:0:0:0:0:0]:13255 -> [2001:db8:server::1]:38472
  ```
- **Result**: Handshake established. ICMP ping across tunnel: **0% packet loss**.

---

## Summary

All five operational configurations of Ingress/Egress Family Decoupling and IPv4/IPv6 protocol translation have been validated on physical MIPS32el router hardware and x86_64 Linux servers with zero packet loss, zero memory leaks, and stable long-running throughput.
