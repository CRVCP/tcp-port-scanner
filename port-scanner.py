#!/usr/bin/env python3
"""
TCP Port Scanner

A command-line tool for scanning TCP ports on a target host.
Features:
- Scans specified port range
- Identifies open ports
- Maps ports to common services
- Uses multithreading for faster scanning
"""

import socket
import argparse
import concurrent.futures
import ipaddress
import sys
from datetime import datetime

# Dictionary of common ports and their services
COMMON_SERVICES = {
    20: "FTP-DATA",
    21: "FTP",
    22: "SSH",
    23: "TELNET",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    115: "SFTP",
    119: "NNTP",
    123: "NTP",
    143: "IMAP",
    161: "SNMP",
    194: "IRC",
    443: "HTTPS",
    445: "SMB",
    465: "SMTPS",
    587: "SMTP (submission)",
    993: "IMAPS",
    995: "POP3S",
    1080: "SOCKS",
    1194: "OpenVPN",
    1433: "MSSQL",
    1521: "Oracle DB",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    5900: "VNC",
    6379: "Redis",
    8080: "HTTP-ALT",
    8443: "HTTPS-ALT",
    27017: "MongoDB"
}

def get_service_name(port):
    """
    Return the service name for a given port number.
    
    Args:
        port (int): The port number to look up
        
    Returns:
        str: The service name if known, otherwise "Unknown"
    """
    return COMMON_SERVICES.get(port, "Unknown")

def scan_port(ip, port, timeout=1):
    """
    Attempt to connect to a specific port on the target IP.
    
    Args:
        ip (str): Target IP address
        port (int): Port number to scan
        timeout (float): Connection timeout in seconds
        
    Returns:
        tuple: (port, is_open, service_name)
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    
    try:
        # Attempt to connect to the port
        result = sock.connect_ex((ip, port))
        is_open = (result == 0)
        
        if is_open:
            service = get_service_name(port)
            return port, True, service
        
    except socket.error:
        pass
    finally:
        sock.close()
    
    return port, False, None

def scan_ports(ip, port_range, timeout=1, max_threads=100):
    """
    Scan multiple ports on the target IP using multithreading.
    
    Args:
        ip (str): Target IP address
        port_range (tuple): Range of ports to scan (start, end)
        timeout (float): Connection timeout in seconds
        max_threads (int): Maximum number of concurrent threads
        
    Returns:
        list: List of tuples (port, service_name) for open ports
    """
    start_port, end_port = port_range
    ports_to_scan = range(start_port, end_port + 1)
    open_ports = []
    
    print(f"\nScanning {ip} for open ports from {start_port} to {end_port}...")
    print(f"Using {min(max_threads, end_port - start_port + 1)} threads with {timeout}s timeout")
    print("-" * 60)
    
    start_time = datetime.now()
    
    # Use ThreadPoolExecutor to scan ports concurrently
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_threads) as executor:
        # Create a future for each port scan
        future_to_port = {
            executor.submit(scan_port, ip, port, timeout): port 
            for port in ports_to_scan
        }
        
        # Process results as they complete
        for i, future in enumerate(concurrent.futures.as_completed(future_to_port)):
            port, is_open, service = future.result()
            
            # Show progress every 100 ports
            if (i + 1) % 100 == 0 or i + 1 == len(ports_to_scan):
                sys.stdout.write(f"\rProgress: {i + 1}/{len(ports_to_scan)} ports scanned")
                sys.stdout.flush()
                
            if is_open:
                open_ports.append((port, service))
    
    end_time = datetime.now()
    duration = end_time - start_time
    
    print(f"\nScan completed in {duration.total_seconds():.2f} seconds")
    
    return open_ports

def validate_ip(ip):
    """
    Validate if the provided string is a valid IP address.
    
    Args:
        ip (str): IP address to validate
        
    Returns:
        bool: True if valid, False otherwise
    """
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False

def parse_arguments():
    """
    Parse command-line arguments.
    
    Returns:
        argparse.Namespace: Parsed arguments
    """
    parser = argparse.ArgumentParser(
        description="TCP Port Scanner - Scan for open ports on a target host",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )
    
    parser.add_argument(
        "target",
        help="Target IP address to scan"
    )
    
    parser.add_argument(
        "-p", "--ports",
        default="1-1024",
        help="Port range to scan (e.g., '1-1024' or '80,443,8080')"
    )
    
    parser.add_argument(
        "-t", "--timeout",
        type=float,
        default=1.0,
        help="Timeout in seconds for each connection attempt"
    )
    
    parser.add_argument(
        "-T", "--threads",
        type=int,
        default=100,
        help="Maximum number of threads to use"
    )
    
    return parser.parse_args()

def parse_port_range(port_arg):
    """
    Parse the port range argument.
    
    Args:
        port_arg (str): Port range string (e.g., "1-1024" or "80,443,8080")
        
    Returns:
        tuple: (start_port, end_port)
        
    Raises:
        ValueError: If port range is invalid
    """
    try:
        # Check if it's a range (e.g., "1-1024")
        if "-" in port_arg:
            start, end = map(int, port_arg.split("-"))
            if start < 1 or end > 65535 or start > end:
                raise ValueError("Invalid port range")
            return start, end
            
        # Check if it's a list of ports (e.g., "80,443,8080")
        elif "," in port_arg:
            ports = list(map(int, port_arg.split(",")))
            if any(p < 1 or p > 65535 for p in ports):
                raise ValueError("Invalid port number")
            return min(ports), max(ports)
            
        # Check if it's a single port
        else:
            port = int(port_arg)
            if port < 1 or port > 65535:
                raise ValueError("Invalid port number")
            return port, port
            
    except (ValueError, TypeError):
        raise ValueError("Invalid port specification")

def main():
    """
    Main function to run the port scanner.
    """
    args = parse_arguments()
    
    # Validate IP address
    if not validate_ip(args.target):
        print(f"Error: '{args.target}' is not a valid IP address")
        sys.exit(1)
    
    try:
        # Parse port range
        port_range = parse_port_range(args.ports)
    except ValueError as e:
        print(f"Error: {e}")
        print("Port range must be between 1-65535 (e.g., '1-1024' or '80,443,8080')")
        sys.exit(1)
    
    try:
        # Perform the scan
        open_ports = scan_ports(
            args.target,
            port_range,
            timeout=args.timeout,
            max_threads=args.threads
        )
        
        # Display results
        if open_ports:
            print("\nOpen ports:")
            print("-" * 60)
            print(f"{'PORT':<10} {'SERVICE':<20}")
            print("-" * 60)
            
            for port, service in sorted(open_ports):
                print(f"{port:<10} {service:<20}")
        else:
            print("\nNo open ports found in the specified range.")
            
    except socket.gaierror:
        print(f"Error: Could not resolve hostname '{args.target}'")
        sys.exit(1)
    except socket.error as e:
        print(f"Error: {e}")
        sys.exit(1)
    except KeyboardInterrupt:
        print("\nScan aborted by user.")
        sys.exit(0)

if __name__ == "__main__":
    main()