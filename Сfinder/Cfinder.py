import requests
import urllib3
import argparse

# Suppress only the specific InsecureRequestWarning
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ASCII Art Header
def print_header():
    header = r"""
 ██████╗███████╗██╗███╗   ██╗██████╗ ███████╗██████╗ 
██╔════╝██╔════╝██║████╗  ██║██╔══██╗██╔════╝██╔══██╗
██║     █████╗  ██║██╔██╗ ██║██║  ██║█████╗  ██████╔╝
██║     ██╔══╝  ██║██║╚██╗██║██║  ██║██╔══╝  ██╔══██╗
╚██████╗██║     ██║██║ ╚████║██████╔╝███████╗██║  ██║
 ╚═════╝╚═╝     ╚═╝╚═╝  ╚═══╝╚══════╝╚═╝  ╚═╝
                                                     
    """
    print(header)
    print("CFINDER - What are you hiding behind your Cloudflare?\n")

# Function to parse command-line arguments
def parse_arguments():
    parser = argparse.ArgumentParser(description='Script to check HTTP/HTTPS services behind Cloudflare.')
    parser.add_argument(
        '-i', '--ip_ports', 
        required=True, 
        help='File containing a list of IP:port combinations, one per line.'
    )
    parser.add_argument(
        '-u', '--url_hosts', 
        required=True, 
        help='File containing a list of hostnames, one per line.'
    )
    return parser.parse_args()

# Function to read lists from files
def read_list_from_file(file_path):
    with open(file_path, 'r') as file:
        return [line.strip() for line in file.readlines()]

# Dictionary to store results for grouping
results = {}

# Function to perform the HTTP request
def check_host(ip_port, url_host):
    try:
        # Split IP and port, skip if format is incorrect
        ip, port = ip_port.split(':')
    except ValueError:
        print(f"Skipping invalid IP:port format: '{ip_port}'")
        return

    protocol = 'https' if port in ['443', '8443'] else 'http'
    url = f"{protocol}://{ip}:{port}"

    headers = {
        'Host': url_host
    }

    try:
        # Disable automatic redirects by setting allow_redirects=False
        response = requests.get(url, headers=headers, timeout=5, verify=False, allow_redirects=False)
        status_code = response.status_code
        response_size = len(response.content)
        
        # Grouping key based on IP, Port, Status, and Response Size
        key = (ip, port, status_code, response_size)
        if key not in results:
            results[key] = []
        results[key].append(url_host)
    except Exception as e:
        # Handle errors separately using a unique key for errors
        key = (ip, port, 'Error', str(e))
        if key not in results:
            results[key] = []
        results[key].append(url_host)

# Main function
def main():
    # Print header
    print_header()

    args = parse_arguments()

    # Read IP:ports and hostnames from files
    ip_ports = read_list_from_file(args.ip_ports)
    url_hosts = read_list_from_file(args.url_hosts)

    # Iterate over the IP:ports
    processed_ips = set()  # Track processed IP:port combinations
    for ip_port in ip_ports:
        # Skip invalid IP:port formats
        if ':' not in ip_port:
            print(f"Skipping invalid IP:port format: '{ip_port}'")
            continue

        ip, port = ip_port.split(':')
        # Print the processing message only once per unique IP:port combination
        if (ip, port) not in processed_ips:
            print(f"Processing IP: {ip}, Port: {port}...")
            processed_ips.add((ip, port))  # Mark as processed

        for url_host in url_hosts:
            check_host(ip_port, url_host)

    # Print grouped results
    print("\nFinal Grouped Results:\n")
    divider = "=" * 50  # Divider for separating different IP:port groups
    # Extract unique IP and port combinations
    ip_port_keys = set((key[0], key[1]) for key in results.keys())
    
    for ip_port_key in ip_port_keys:
        ip, port = ip_port_key
        print(f"{divider}")
        print(f"IP: {ip:<15} Port: {port:<5}")
        print(f"{divider}")

        # Group hosts by their status and size for the same IP and port
        grouped_hosts = {}
        for key, hosts in results.items():
            if key[0] == ip and key[1] == port:
                status = key[2]
                size = key[3]
                group_key = (status, size)
                if group_key not in grouped_hosts:
                    grouped_hosts[group_key] = []
                grouped_hosts[group_key].extend(hosts)

        # Print the grouped hosts for the current IP and port
        for (status, size), hosts in grouped_hosts.items():
            if len(hosts) == len(url_hosts):
                # All hosts for this IP:port have the same status and size
                print(f"Status: {status:<6} Size: {size}")
                print(f"  For all tested host headers")
            else:
                # Print each host individually if they are not all the same
                print(f"Status: {status:<6} Size: {size}")
                for host in hosts:
                    print(f"  Host: {host}")
        print("\n")

if __name__ == "__main__":
    main()
