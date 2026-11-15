#!/usr/bin/env python3
"""
Integration test for wg-obfuscator-nolibc-mips32el (IPv4 & IPv6 Dual-Stack):
Tests interoperability with the original ClusterM/wg-obfuscator x86_64 binary
as well as IPv6 Dual-Stack, STUN family 0x02 (128-bit XOR-MAPPED-ADDRESS),
and transparent IPv6 <-> IPv4 bridging.
"""
import socket
import struct
import subprocess
import time
import os
import sys

ORIG_BIN = os.path.abspath("../wg-obfuscator/wg-obfuscator")
NOLIBC_BIN = os.path.abspath("./wg-obfuscator-nolibc-mips32el")
QEMU = "qemu-mipsel-static"
KEY = "SecretSharedKey123"

def make_wg_packet(ptype, length):
    pkt = bytearray(length)
    pkt[0] = ptype
    pkt[1] = 0x00
    pkt[2] = 0x00
    pkt[3] = 0x00
    for i in range(4, length):
        pkt[i] = (i * 37 + ptype) & 0xFF
    return bytes(pkt)

def run_test_pair(server_cmd, client_cmd, s_port, c_port, wg_port, test_name, client_v6=False):
    print(f"\n--- Running: {test_name} ---")
    mock_server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    mock_server.bind(("127.0.0.1", wg_port))
    mock_server.settimeout(3.0)

    print(f"Starting server: {' '.join(server_cmd)}")
    srv_proc = subprocess.Popen(server_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    time.sleep(0.4)

    print(f"Starting client: {' '.join(client_cmd)}")
    cli_proc = subprocess.Popen(client_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    time.sleep(0.4)

    try:
        if client_v6:
            mock_client = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
            dest = ("::1", c_port)
        else:
            mock_client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            dest = ("127.0.0.1", c_port)
        mock_client.settimeout(3.0)

        hs_init = make_wg_packet(1, 148)
        mock_client.sendto(hs_init, dest)

        rx_pkt, srv_peer = mock_server.recvfrom(4096)
        assert rx_pkt == hs_init, f"Handshake Init mismatch! len={len(rx_pkt)}"
        print("[PASS] Handshake Init received correctly by WG server (148 bytes)")

        hs_resp = make_wg_packet(2, 92)
        mock_server.sendto(hs_resp, srv_peer)

        rx_cli, _ = mock_client.recvfrom(4096)
        assert rx_cli == hs_resp, f"Handshake Response mismatch! len={len(rx_cli)}"
        print("[PASS] Handshake Response received correctly by WG client (92 bytes)")

        data_c2s = make_wg_packet(4, 1420)
        mock_client.sendto(data_c2s, dest)
        rx_data_s, srv_peer2 = mock_server.recvfrom(4096)
        assert rx_data_s == data_c2s, f"Data packet C->S mismatch! len={len(rx_data_s)}"
        print("[PASS] Transport Data C->S received correctly (1420 bytes)")

        data_s2c = make_wg_packet(4, 1420)
        mock_server.sendto(data_s2c, srv_peer2)
        rx_data_c, _ = mock_client.recvfrom(4096)
        assert rx_data_c == data_s2c, f"Data packet S->C received correctly (1420 bytes)"
        print("[PASS] Transport Data S->C received correctly (1420 bytes)")

        print(f"*** {test_name}: ALL CHECKS PASSED ***")
        return True
    finally:
        cli_proc.terminate()
        srv_proc.terminate()
        cli_proc.wait(timeout=1.0)
        srv_proc.wait(timeout=1.0)
        mock_server.close()

def main():
    # Test 1: nolibc MIPS server + original x86_64 client (STUN mode)
    cmd_srv_mips = [QEMU, NOLIBC_BIN, "-p", "5002", "-t", "127.0.0.1:5001", "-k", KEY, "-a", "STUN", "-v", "DEBUG"]
    cmd_cli_orig = [ORIG_BIN, "-p", "5003", "-t", "127.0.0.1:5002", "-k", KEY, "-a", "STUN", "-v", "DEBUG"]
    assert run_test_pair(cmd_srv_mips, cmd_cli_orig, 5002, 5003, 5001, "MIPS Server (nolibc) <-> Original Client (x86_64) [STUN]")

    # Test 2: original x86_64 server + nolibc MIPS client (STUN mode)
    cmd_srv_orig = [ORIG_BIN, "-p", "5004", "-t", "127.0.0.1:5001", "-k", KEY, "-a", "STUN", "-v", "DEBUG"]
    cmd_cli_mips = [QEMU, NOLIBC_BIN, "-p", "5005", "-t", "127.0.0.1:5004", "-k", KEY, "-a", "STUN", "-v", "DEBUG"]
    assert run_test_pair(cmd_srv_orig, cmd_cli_mips, 5004, 5005, 5001, "Original Server (x86_64) <-> MIPS Client (nolibc) [STUN]")

    # Test 3: nolibc MIPS server (IPv6 -> IPv4 bridge) + nolibc MIPS client (Dual-Stack -> IPv6 STUN)
    cmd_srv_v6 = [QEMU, NOLIBC_BIN, "-i", "[::1]", "-p", "5006", "-t", "127.0.0.1:5001", "-k", KEY, "-a", "AUTO", "-v", "DEBUG"]
    cmd_cli_v6 = [QEMU, NOLIBC_BIN, "-p", "5007", "-t", "[::1]:5006", "-k", KEY, "-a", "STUN", "-v", "DEBUG"]
    assert run_test_pair(cmd_srv_v6, cmd_cli_v6, 5006, 5007, 5001, "MIPS IPv6 STUN <-> IPv4 Bridge [Dual-Stack]", client_v6=True)

    print("\n===========================================")
    print("  ALL INTEROPERABILITY TESTS PASSED 100%!  ")
    print("===========================================")

if __name__ == "__main__":
    main()
