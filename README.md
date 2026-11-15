<sub>*If someone on the internet hurts your feelings, tell your mom or dad.*</sub>

# wg-obfuscator v1.6+-nolibc (Dual-Stack Edition)

Compact freestanding C port of the WireGuard obfuscator for Linux and OpenWrt routers (MIPS32el, MIPS32be, x86_64).
Built directly on top of the Linux kernel via `nolibc.h` and the `wsock.h` networking layer (whitehttpd architecture).

## Key Features

- 100% wire-protocol compatibility with ClusterM/wg-obfuscator v1.6.
- Ingress/Egress address family decoupling: zero-cost application-level bridge between IPv4 and IPv6.
- Full IPv4 and IPv6 Dual-Stack support (`[::]` listening socket with `IPV6_V6ONLY = 0`).
- RFC 5389 STUN XOR-MAPPED-ADDRESS handling (family 0x01 for IPv4/mapped and 0x02 for native IPv6).
- `[IPv6]:port` syntax support in CLI and config files, built-in non-blocking DNS A and AAAA queries.
- Zero-Heap: no `malloc`/`free` calls. All state is statically allocated in `.bss` (~31 KB).
- Zero-libc: compiled with `-nostdlib`. Final stripped binary is ~24 KB.
- Optimized for constrained MIPS CPUs: single 256-byte CRC8 LUT (GF(2) equivalence) and 1-row 2 KB keystream cache fitting in L1 D-cache.

---

## Building

To build for MIPS32 Little-Endian (routers based on MT7628, MT7621, etc.):

```bash
make mips32el
```

To verify the ELF structure (NX stack, LOAD segments):

```bash
make check-elf
```

To build natively for x86_64:

```bash
make x86_64
```

To clean build artifacts:

```bash
make clean
```

The build process uses `tools/sstrip.py` to remove the ELF section header table, retaining only the program segments required by the Linux kernel loader.

---

## Command Line Options

```text
Usage: wg-obfuscator [OPTION...]

  -c, --config=<file>             Read configuration from file
  -i, --source-if=<ip>            IP to listen on (default: [::] Dual-Stack)
  -p, --source-lport=<port>       Local port to listen on
  -t, --target=<host:port>        Target WireGuard IP/host and port
  -k, --key=<key>                 Obfuscation key (1-255 characters)
  -a, --masking=<type>            Masking type: NONE, STUN, AUTO (default: AUTO)
  -b, --static-bindings=<list>    Static bindings: ip:port:localport,...
  -m, --max-clients=<num>         Maximum client sessions (default: 64)
  -l, --idle-timeout=<sec>        Idle timeout in seconds (default: 300)
  -n, --in-timeout=<sec>          Incoming traffic timeout in seconds (default: 180)
  -d, --max-dummy=<bytes>         Maximum dummy padding bytes for data packets (default: 4)
  -f, --fwmark=<mark>             Firewall mark (fwmark) for outgoing sockets
  -e, --allow-clean               Allow clean (unobfuscated) WireGuard packets
  -v, --verbose=<level>           Log level: ERRORS, WARNINGS, INFO, DEBUG, TRACE
  -L, --log-file=<path>           Write logs to file
  -T, --log-timestamps            Add timestamps to log lines
  -R, --resolve-interval=<sec>    Periodic DNS re-resolve interval (default: 0)
  -?, --help                      Show help list
  -V, --version                   Show program version
```

---

## Ingress/Egress Family Decoupling (Zero-Cost IPv4 <-> IPv6 Bridge)

Unlike the original IPv4-only implementation, `wg-obfuscator v1.6+-nolibc` completely decouples the public-facing listener socket from outgoing target connections. This provides a transparent, bidirectional application-level bridge between IPv4 and IPv6 without requiring kernel NAT64, SIIT, tayga, clatd, or complex iptables/nftables packet mangling.

### Architectural Decoupling
- **Dual-Stack Ingress**: The public listener socket binds to `[::]` with `IPV6_V6ONLY = 0`. It accepts both native IPv6 datagrams and IPv4 datagrams (delivered by the Linux kernel as IPv4-mapped IPv6 addresses `::ffff:a.b.c.d`).
- **Target-Specific Egress**: When a client session is initiated, `c->server_sock` is created strictly matching the address family of the target WireGuard endpoint (`g_cfg.forward_addr.sa.sa_family`).
- **Stateless Cross-Family Forwarding**: Payloads decoded from the listening socket are forwarded directly into `server_sock`, and reverse responses from `server_sock` are obfuscated and routed back to the client's source address via `ws_sendto()`.

### Practical Deployment Scenarios
1. **IPv6 Client to IPv4 WireGuard (6-to-4 translation)**:
   - *Scenario*: A mobile carrier or remote ISP provides IPv6-only connectivity, while the target WireGuard server runs on traditional IPv4 localhost (`127.0.0.1:51820`).
   - *Operation*: The obfuscator listens on public `[::]:443` and delivers decoded packets to `127.0.0.1:51820`. The WireGuard daemon requires no IPv6 setup or dual-stack configuration.
2. **IPv4 Client to IPv6 WireGuard (4-to-6 translation)**:
   - *Scenario*: The host server is behind Carrier-Grade NAT (CGNAT) with no routable public IPv4 address, but possesses a globally reachable IPv6 subnet. The connecting client only has legacy IPv4.
   - *Operation*: Incoming client IPv4 traffic is received by the obfuscator and forwarded seamlessly to the target IPv6 WireGuard endpoint without encapsulation overhead.
3. **Native Transit (IPv4-to-IPv4 and IPv6-to-IPv6)**:
   - Wire-speed forwarding without protocol translation when families match.

---

## Usage Examples

### 1. Server: Dual-Stack listening (IPv4 + IPv6) forwarding to local WireGuard (IPv4)

```bash
./wg-obfuscator-nolibc-mips32el \
    -p 443 \
    -t 127.0.0.1:51820 \
    -k MySecretKey123 \
    -a AUTO \
    -v INFO
```

### 2. Client: Connect to server over IPv6 with STUN masking

```bash
./wg-obfuscator-nolibc-mips32el \
    -i 127.0.0.1 \
    -p 51820 \
    -t [2001:db8:1234::1]:443 \
    -k MySecretKey123 \
    -a STUN \
    -v INFO
```

### 3. Running with a config file

Create `/etc/wg-obfuscator.conf`:

```ini
[main]
source-lport = 443
target = 127.0.0.1:51820
key = MySecretKey123
masking = AUTO
verbose = INFO
log-timestamps = true
```

Run:

```bash
./wg-obfuscator-nolibc-mips32el -c /etc/wg-obfuscator.conf
```

---

## Hardware Verification & Real-World Tests

All operational modes (including the 5 combinations of Ingress/Egress Family Decoupling, IPv4-mapped address handling, and IPv6 transit) have been verified on physical hardware:
- **Client Node**: Xiaomi Wi-Fi Router (MIPS32r2 Little-Endian, Padavan Linux firmware).
- **Server Node**: Cloud VPS (x86_64 Linux).

See [TESTS.md](TESTS.md) for the complete test matrix, topology details, and sanitized verification logs.

---

## Author's Note & Security Advisory

Any traffic masking or obfuscation scheme published openly inevitably becomes a known signature for Deep Packet Inspection (DPI) operators and automated traffic classifiers. While cryptographic integrity remains intact through standard encryption keys, the structural fingerprints of public masking implementations significantly reduce their long-term resilience against targeted censorship.

If you need advisory, custom protocol designs, or private censorship-resistant traffic masking architectures tailored for constrained embedded hardware, feel free to get in touch:

- Email: `ivansvarkovsky@gmail.com`
- GitHub: [@Svarkovsky](https://github.com/Svarkovsky)

---

## License & Credits

- This project is licensed under the **GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later)**. See `LICENSE`.
- Freestanding architecture, `wsock.h` networking layer, optimizations, and IPv6 Dual-Stack:
  **Ivan Svarkovsky** <ivansvarkovsky@gmail.com>, [whitehttpd](https://github.com/Svarkovsky/whitehttpd).
- Original WireGuard obfuscator protocol and concepts:
  **ClusterM** ([ClusterM/wg-obfuscator](https://github.com/ClusterM/wg-obfuscator), GNU GPLv3).
- Combined under the terms of **Section 13 of GNU GPLv3** and **Section 13 of GNU AGPLv3**.
- Linux kernel `nolibc.h`: Willy Tarreau / Linux kernel contributors (LGPL-2.1 OR MIT).
