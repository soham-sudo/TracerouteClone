
from scapy.all import IP, ICMP, sr1
import sys
import argparse
from datetime import datetime

def traceroute(destination, max_hops=30, timeout=1):
    """
    Implements traceroute functionality using Scapy.
    
    Args:
        destination (str): The destination IP address
        max_hops (int): Maximum number of hops to try
        timeout (int): Timeout for each probe in seconds
        
    Returns:
        None: Prints the traceroute results to stdout
    """
    print(f"\nTraceroute to {destination}, maximum {max_hops} hops:\n")
    print(f"{'Hop':^5} {'IP Address':^20} {'Response Time':^15} {'Status':^10}")
    print("-" * 55)
    
    # Loop from TTL 1 to max_hops
    for ttl in range(1, max_hops + 1):
        # Create an IP packet with the current TTL and ICMP echo request
        packet = IP(dst=destination, ttl=ttl) / ICMP()
        
        # Record the start time
        start_time = datetime.now()
        
        # Send the packet and wait for a response
        reply = sr1(packet, timeout=timeout, verbose=0)
        
        # Calculate response time
        response_time = (datetime.now() - start_time).total_seconds() * 1000  # in ms
        
        if reply is None:
            # No response received within timeout
            print(f"{ttl:^5} {'*':^20} {'--':^15} {'Timeout':^10}")
        elif reply.type == 0:
            # ICMP Echo Reply (type 0) - reached the destination
            print(f"{ttl:^5} {reply.src:^20} {response_time:.2f} ms {'Reached':^10}")
            print(f"\nDestination reached after {ttl} hops.")
            break
        elif reply.type == 11:
            # ICMP Time Exceeded (type 11) - intermediate router
            print(f"{ttl:^5} {reply.src:^20} {response_time:.2f} ms {'Router':^10}")
        else:
            # Other ICMP message
            print(f"{ttl:^5} {reply.src:^20} {response_time:.2f} ms {'Unknown':^10}")
    
    print("\nTraceroute complete.")

def main():
    # Set up command line arguments
    parser = argparse.ArgumentParser(description='Traceroute implementation using Scapy')
    parser.add_argument('destination', help='Destination IP address')
    parser.add_argument('--max-hops', type=int, default=30, help='Maximum number of hops')
    parser.add_argument('--timeout', type=int, default=1, help='Timeout in seconds')
    
    args = parser.parse_args()
    
    try:
        traceroute(args.destination, args.max_hops, args.timeout)
    except KeyboardInterrupt:
        print("\nTraceroute interrupted by user.")
    except Exception as e:
        print(f"\nError: {e}")
        print("Note: This script requires root/administrator privileges to run.")

if __name__ == "__main__":
    # Check if running with root/admin privileges
    if sys.platform.startswith('win'):
        # On Windows, just warn the user
        print("Warning: This script may require administrator privileges to run.")
    elif os.geteuid() != 0:
        print("Error: This script requires root privileges to run.")
        print("Please run with sudo or as root.")
        sys.exit(1)
        
    main()