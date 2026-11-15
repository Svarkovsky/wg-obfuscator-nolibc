# wg-obfuscator v1.6+-nolibc

WireGuard MyST-based obfuscator ported to freestanding C (`nolibc` + `wsock.h`) without libc, malloc, or dynamic heap allocations.

Designed for resource-constrained network hardware and embedded routers (MIPS32 Little/Big Endian, x86_64).

## Binaries & Sizes
- `wg-obfuscator-nolibc-mips32el`: MIPS32r2 Little-Endian (~24 KB)
- `wg-obfuscator-nolibc-mips32be`: MIPS32r2 Big-Endian (~24 KB)
- `wg-obfuscator-nolibc-x86_64`: x86_64 Freestanding (~25 KB)

## Key Features & Architecture
- Dual-Stack IPv4 / IPv6 socket support in a single epoll event loop (`[::]` with `IPV6_V6ONLY = 0`).
- Ingress/Egress address family decoupling: zero-cost application-level bridge between IPv4 and IPv6 without NAT64 or kernel packet translation.
- Zero-Heap design: 0 bytes dynamic allocation (`malloc`/`free`), all state lives in static `.bss` (~31 KB total).
- L1 cache-friendly: single-row MRU keystream buffer (2 KB) and unified 256-byte CRC8 table.
- DPI-safe dual-stack STUN: automatically detects IPv4-mapped IPv6 and emits standard 4-byte STUN mapped-address attributes.
- Section-header stripping via `tools/sstrip.py` for minimal binary footprint.

## License
GNU AGPLv3 (port, nolibc and wsock layers by Ivan Svarkovsky; original obfuscation protocol by Alexey Cluster).
Author: Ivan Svarkovsky <ivansvarkovsky@gmail.com>
