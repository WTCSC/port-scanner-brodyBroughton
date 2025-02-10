# Network and Port Scanner

⚠️ **SECURITY WARNING** ⚠️
```
IMPORTANT: Network and port scanning without explicit permission can be illegal in many jurisdictions 
and could result in severe legal consequences. This tool should ONLY be used on networks and 
systems you own or have explicit written permission to test. The authors are not responsible 
for any misuse or damage caused by this tool.
```

A Python tool that performs network discovery using CIDR notation and can scan for open ports on active hosts. The tool converts CIDR notation into binary formats, calculates network ranges, performs ping sweeps, and can identify open ports on responsive hosts.

[Rest of the README remains exactly the same...]

## Features
### Network Discovery
- CIDR to binary subnet mask conversion
- Network range calculation
- Active host detection via ping
- Response time measurement for active hosts

### Port Scanning
- Support for scanning specific ports on active hosts
- Multiple port scanning formats:
  - Single port (e.g., `-p 80`)
  - Port range (e.g., `-p 1-100`)
  - Multiple specific ports (e.g., `-p 80,443,3306`)
- Service identification for open ports
- Sequential scanning with timeout protection

## Prerequisites
- Python 3
- Network access permissions (for executing ping commands)

## Installation
1. Clone the repository:
    ```
    git clone https://github.com/WTCSC/port-scanner-brodyBroughton.git
    ```
2. Change directory:
    ```
    cd port-scanner-brodyBroughton
    ```

## Usage
### Basic Network Scan
Run the script with a CIDR address to perform a network scan:
```
python3 ip_addressigma.py 192.168.1.0/24
```

### Port Scanning
Add the `-p` argument to scan for open ports on active hosts:
```
# Scan single port
python3 ip_addressigma.py -p 80 192.168.1.0/24

# Scan port range
python3 ip_addressigma.py -p 1-100 192.168.1.0/24

# Scan specific ports
python3 ip_addressigma.py -p 80,443,3306 192.168.1.0/24
```

## Error Handling
The script includes robust error handling for common scenarios:

### Network Scanning Errors
```
# Invalid CIDR format
$ python3 ip_addressigma.py 192.168.1/24
Invalid CIDR format. Please enter a valid CIDR address.

# Network unreachable
192.168.1.10 - ERROR: Network is unreachable
```

### Port Scanning Errors
```
# Invalid port number
$ python3 ip_addressigma.py -p 65536 192.168.1.0/24
Error parsing ports: Ports must be between 1 and 65535

# Invalid port range
$ python3 ip_addressigma.py -p 100-1 192.168.1.0/24
Error parsing ports: Invalid port range: start port greater than end port

# Connection timeout
192.168.1.10 - Port 80 - ERROR: Connection timed out
```

## How It Works
1. **Network Discovery**:
   - Converts CIDR notation to binary subnet mask
   - Calculates network range excluding network and broadcast addresses
   - Performs ping sweep to identify active hosts

2. **Port Scanning** (when `-p` option is used):
   - Only scans hosts that respond to ping
   - Uses TCP connection attempts to identify open ports
   - Attempts service identification for open ports
   - Implements 3-second timeout per port scan

[Screenshot placeholder]