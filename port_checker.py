#!/usr/bin/env python3
"""Port Status Checker

Checks whether a TCP port on a given host is open, closed or filtered.

Usage:
    python port_checker.py                  # interactive prompts
    python port_checker.py 80               # check port 80 on localhost
    python port_checker.py 443 example.com  # check port 443 on example.com
    python port_checker.py 22 192.168.1.1 -t 3

Only check systems you own or have permission to test.
"""

import argparse
import errno
import socket
import sys


def get_service_name(port: int) -> str:
    """Return the well-known service name for a port (e.g. 80 -> http)."""
    try:
        return socket.getservbyport(port, "tcp")
    except OSError:
        return "unknown"


def check_port(host: str, port: int, timeout: float = 2.0) -> str:
    """Return 'open', 'closed' or 'filtered' for a TCP port.

    open     - a service accepted the connection
    closed   - the host answered, but nothing is listening on the port
    filtered - no answer (timeout), usually a firewall dropping packets
    """
    try:
        # Resolve once so a bad hostname gives a clear error.
        family, _, _, _, addr = socket.getaddrinfo(
            host, port, type=socket.SOCK_STREAM)[0]
    except socket.gaierror:
        raise ValueError(f"Could not resolve host '{host}'.")

    with socket.socket(family, socket.SOCK_STREAM) as sock:
        sock.settimeout(timeout)
        try:
            result = sock.connect_ex(addr)
        except socket.timeout:
            return "filtered"
        except OSError:
            return "filtered"

    if result == 0:
        return "open"
    if result == errno.ECONNREFUSED:
        return "closed"
    return "filtered"  # timeout, unreachable, etc.


def parse_port(value: str) -> int:
    try:
        port = int(value)
    except ValueError:
        raise ValueError("Port must be a number.")
    if not 1 <= port <= 65535:
        raise ValueError("Port must be between 1 and 65535.")
    return port


MESSAGES = {
    "open": "OPEN - a service is listening and accepting connections.",
    "closed": "CLOSED - the host is reachable but nothing is listening on this port.",
    "filtered": "FILTERED - no response (timeout). A firewall may be blocking it, "
                "or the host is unreachable.",
}


def main() -> int:
    parser = argparse.ArgumentParser(description="Check if a TCP port is open or closed.")
    parser.add_argument("port", nargs="?", help="port number (1-65535)")
    parser.add_argument("host", nargs="?", default=None,
                        help="hostname or IP (default: localhost)")
    parser.add_argument("-t", "--timeout", type=float, default=2.0,
                        help="timeout in seconds (default: 2)")
    args = parser.parse_args()

    port_text, host = args.port, args.host
    if port_text is None:  # interactive mode
        port_text = input("Enter port number (1-65535): ").strip()
        host = input("Enter host [localhost]: ").strip() or "localhost"
    host = host or "localhost"

    try:
        port = parse_port(port_text)
        status = check_port(host, port, args.timeout)
    except ValueError as e:
        print(f"Error: {e}")
        return 2

    print(f"\nHost:    {host}")
    print(f"Port:    {port} ({get_service_name(port)})")
    print(f"Status:  {MESSAGES[status]}\n")
    return 0 if status == "open" else 1


if __name__ == "__main__":
    sys.exit(main())
  
