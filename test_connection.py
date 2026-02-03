#!/usr/bin/env python3
"""Simple SSH connection test for MiragePot diagnostics."""

import sys
import socket
import time


def test_tcp_connection(host, port):
    """Test basic TCP connectivity."""
    print(f"\n[TEST] Testing TCP connection to {host}:{port}...")
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        result = sock.connect_ex((host, port))
        sock.close()

        if result == 0:
            print(f"[PASS] TCP connection successful to {host}:{port}")
            return True
        else:
            print(f"[FAIL] TCP connection failed with error code: {result}")
            return False
    except Exception as e:
        print(f"[FAIL] TCP connection exception: {e}")
        return False


def test_ssh_handshake(host, port):
    """Test SSH protocol handshake."""
    print(f"\n[TEST] Testing SSH handshake with {host}:{port}...")
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(10)
        sock.connect((host, port))

        # Read SSH banner
        print("[INFO] Connected, waiting for SSH banner...")
        banner = sock.recv(1024)
        print(
            f"[INFO] Received banner: {banner.decode('utf-8', errors='ignore').strip()}"
        )

        # Send our client banner
        client_banner = b"SSH-2.0-OpenSSH_8.1 Test Client\r\n"
        print(f"[INFO] Sending client banner: {client_banner.decode('utf-8').strip()}")
        sock.send(client_banner)

        # Wait for key exchange init
        print("[INFO] Waiting for key exchange...")
        time.sleep(2)

        try:
            data = sock.recv(4096)
            if data:
                print(f"[INFO] Received {len(data)} bytes during key exchange")
                print("[PASS] SSH handshake progressing normally")
            else:
                print("[WARN] No data received during key exchange")
        except socket.timeout:
            print("[WARN] Timeout waiting for key exchange response")

        sock.close()
        return True

    except socket.timeout:
        print("[FAIL] Socket timeout during SSH handshake")
        return False
    except Exception as e:
        print(f"[FAIL] SSH handshake exception: {e}")
        return False


def main():
    """Run connection tests."""
    print("=" * 60)
    print("MiragePot SSH Connection Diagnostic Test")
    print("=" * 60)

    # Test localhost
    host_local = "127.0.0.1"
    port = 2222

    print(f"\nTesting localhost ({host_local})...")
    tcp_ok = test_tcp_connection(host_local, port)

    if tcp_ok:
        test_ssh_handshake(host_local, port)

    # Test network interface
    try:
        # Get local IP
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
        s.close()

        print(f"\n\nTesting local network IP ({local_ip})...")
        tcp_ok = test_tcp_connection(local_ip, port)

        if tcp_ok:
            test_ssh_handshake(local_ip, port)
    except Exception as e:
        print(f"\n[WARN] Could not determine local IP: {e}")

    print("\n" + "=" * 60)
    print("Test Complete")
    print("=" * 60)
    print("\nCheck MiragePot server logs for detailed diagnostics.")
    print("Look for these log messages:")
    print("  - === SOCKET ACCEPT === (confirms TCP connection)")
    print("  - === _handle_client() ENTRY === (confirms handler called)")
    print("  - Rate limiter: ALLOWING (confirms not blocked)")
    print("  - Starting SSH server negotiation (confirms SSH handshake started)")
    print("  - SSH negotiation FAILED (if connection fails)")


if __name__ == "__main__":
    main()
