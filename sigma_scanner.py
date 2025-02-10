import ipaddress
import sys
import subprocess
import socket
import argparse
from typing import List, Tuple, Optional

# Dictionary of common ports and their typical services for quick reference
COMMON_PORTS = {
    80: "HTTP",
    443: "HTTPS",
    22: "SSH",
    21: "FTP",
    3306: "MySQL",
    5432: "PostgreSQL"
}

def parse_port_argument(port_str: str) -> List[int]:
    # Convert a port string argument into a list of ports to scan
    ports = []
    try:
        # Split the input string by comma to handle multiple port specifications
        for part in port_str.split(','):
            if '-' in part:
                # Handle port range format (e.g., 1-100)
                start, end = map(int, part.split('-'))
                
                # Validate port range values
                if not (0 < start <= 65535 and 0 < end <= 65535):
                    raise ValueError("Ports must be between 1 and 65535")
                if start > end:
                    raise ValueError("Invalid port range: start port greater than end port")
                
                # Add all ports in the range to our list
                ports.extend(range(start, end + 1))
            else:
                # Handle single port format
                port = int(part)
                if not (0 < port <= 65535):
                    raise ValueError("Ports must be between 1 and 65535")
                ports.append(port)
    except ValueError as e:
        print(f"Error parsing ports: {str(e)}")
        sys.exit(1)
    
    # Remove duplicates and sort the port list
    return sorted(list(set(ports)))

def scan_port(ip: str, port: int, timeout: float = 3.0) -> Tuple[bool, Optional[str]]:
    # Attempt to connect to a specific port on the target IP address
    # Returns a tuple of (is_open, service_name)
    
    # Create a new TCP socket for this scan
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)  # Set connection timeout
    
    try:
        # Attempt to connect to the port
        # connect_ex() returns 0 if connection successful, errno otherwise
        result = sock.connect_ex((ip, port))
        
        if result == 0:
            # Port is open, try to identify the service
            try:
                service = socket.getservbyport(port)
            except (socket.error, OSError):
                service = "unknown"
            return True, service
        return False, None
        
    except socket.gaierror:
        # DNS resolution failed
        print(f"Error: Hostname could not be resolved for {ip}")
        return False, None
    except socket.error as e:
        # Other socket-related errors
        print(f"Error scanning {ip}:{port} - {str(e)}")
        return False, None
    finally:
        # Close the socket
        sock.close()

def cidr_to_bin_submask(cidr_input: str) -> str:
    # Convert CIDR notation to binary subnet mask
    cidr = int(cidr_input.split('/')[1])
    binary_submask = '1' * cidr + '0' * (32 - cidr)
    return binary_submask

def parse_ip_address(cidr_input: str) -> List[str]:
    # Extract IP address from CIDR notation and split into octets
    ip_str = cidr_input.split('/')[0]
    octets = ip_str.split('.')
    return octets

def ip_to_bin(octets: List[str]) -> List[str]:
    # Convert IP address octets to their binary representation
    binary_octets = [format(int(octet), '08b') for octet in octets]
    return binary_octets

def apply_subnet_mask(bin_ip: List[str], binary_submask: str) -> str:
    # Apply the subnet mask to the binary IP address to get the network address
    # Combines the binary IP and performs bitwise AND with the subnet mask
    
    # Join binary octets into a single string
    bin_ip_str = ''.join(bin_ip)
    
    # Perform bitwise AND between IP and subnet mask
    network_bits = ''.join(['1' if bin_ip_str[i] == '1' and binary_submask[i] == '1' else '0' for i in range(32)])
    
    # Split result back into octets
    network_octets = [network_bits[i:i+8] for i in range(0, 32, 8)]
    
    # Convert binary network address back to decimal format
    network_address = '.'.join([str(int(octet, 2)) for octet in network_octets])
    return network_address

def calculate_network_range(cidr_input: str, network_address: str) -> Tuple[str, str]:
    # Calculate the usable IP range for the network
    # Returns the first and last usable IP addresses
    
    # Calculate number of host bits and total addresses
    cidr = int(cidr_input.split('/')[1])
    host_bits = 32 - cidr
    total_addresses = 2 ** host_bits
    
    # Convert network address to integer for arithmetic
    network_int = int(ipaddress.IPv4Address(network_address))
    broadcast_int = network_int + total_addresses - 1
    
    # Calculate first and last usable addresses (excluding network and broadcast)
    start_ip = str(ipaddress.IPv4Address(network_int + 1))
    broadcast_ip = str(ipaddress.IPv4Address(broadcast_int - 1))
    
    print("Network Range (excluding first and last):", start_ip, "-", broadcast_ip)
    return start_ip, broadcast_ip

def ping_and_scan_network(start_ip: str, broadcast_ip: str, ports: Optional[List[int]] = None) -> None:
    # Perform network discovery via ping and optional port scanning on responsive hosts
    print("Scanning network range...")
    
    # Iterate through all IP addresses in the range
    for i in range(int(ipaddress.IPv4Address(start_ip)), int(ipaddress.IPv4Address(broadcast_ip)) + 1):
        ip = str(ipaddress.IPv4Address(i))
        try:
            # Attempt to ping the host
            result = subprocess.run(
                ["ping", "-c", "1", "-W", "1", ip],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            
            if result.returncode == 0:
                # Host responded to ping
                response_time = "N/A"
                
                # Extract ping response time if available
                for line in result.stdout.splitlines():
                    if "time=" in line:
                        try:
                            part = line.split("time=")[1]
                            response_time = part.split()[0]
                        except Exception:
                            response_time = "N/A"
                        break
                
                print(f"\n{ip} (UP) - Response time: {response_time} ms")
                
                # Perform port scanning if ports were specified
                if ports:
                    open_ports = []
                    for port in ports:
                        # Scan each specified port
                        is_open, service = scan_port(ip, port)
                        if is_open:
                            service_info = f" ({service})" if service else ""
                            print(f"  - Port {port:<6} (OPEN){service_info}")
                            open_ports.append(port)
                    
                    if not open_ports:
                        print("  - No open ports found")
            else:
                # Host did not respond to ping
                error_message = result.stderr.strip() or "(No response)"
                print(f"{ip} (DOWN) - {error_message}")
                
        except Exception as e:
            print(f"{ip} - ERROR: {str(e)}")
            continue

if __name__ == "__main__":
    # Set up command-line argument parsing
    parser = argparse.ArgumentParser(description='Network and Port Scanner')
    parser.add_argument('cidr', help='CIDR address (e.g., 192.168.1.0/24)')
    parser.add_argument('-p', '--ports', help='Ports to scan (e.g., 80 or 1-100 or 80,443,3306)')
    
    args = parser.parse_args()

    # Validate the CIDR input
    try:
        network = ipaddress.ip_network(args.cidr, strict=False)
    except ValueError:
        print("Invalid CIDR format. Please enter a valid CIDR address.")
        sys.exit(1)

    # Parse and validate port arguments if provided
    ports = None
    if args.ports:
        try:
            ports = parse_port_argument(args.ports)
            print(f"Scanning ports: {args.ports}")
        except ValueError as e:
            print(f"Error parsing ports: {str(e)}")
            sys.exit(1)

    # Process network scanning steps
    binary_submask = cidr_to_bin_submask(args.cidr)
    octets = parse_ip_address(args.cidr)
    bin_ip = ip_to_bin(octets)
    network_address = apply_subnet_mask(bin_ip, binary_submask)
    start_ip, broadcast_ip = calculate_network_range(args.cidr, network_address)
    
    # Execute the network and port scanning
    ping_and_scan_network(start_ip, broadcast_ip, ports)