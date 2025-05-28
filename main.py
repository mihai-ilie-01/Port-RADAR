import sys
import argparse
import socket
from scan import ThreadedPortScanner
import os
from tqdm import tqdm
import datetime

def parse_port_range(port_range):
    """Parse port range string into start and end ports"""
    if '-' in port_range:
        start, end = port_range.split('-')
        return int(start), int(end)
    elif ',' in port_range:
        # For comma-separated ports, return min and max
        ports = [int(p.strip()) for p in port_range.split(',')]
        return min(ports), max(ports)
    else:
        # Single port
        port = int(port_range)
        return port, port

def validate_ip(ip):
    """Validate IP address format test"""
    try:
        socket.inet_aton(ip)
        return True
    except socket.error:
        return False

def get_user_input():
    Asciiart = r"""
                                 ⠀⠀⠀⠀⠀⠀⠀⠀⠀⣴⣧⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
                                 ⠀⠀⠀⠀⠀⠀⠀⠀⣼⣿⣿⣿⡄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
                                 ⠀⠀⠀⠀⠀⠀⠀⣸⣿⣿⣿⣿⣿⣄⠀⠀⠀⠀⠀⠀⠀⠀⢀⣴⣦⡄⠀
                                 ⠀⠀⠀⠀⠀⠀⠀⣿⣿⣿⣿⣿⣿⣿⣆⠀⠀⠀⠀⣀⣀⣤⣼⣿⣿⡟⠀
                                 ⠀⠀⠀⠀⠀⠀⠀⣿⣿⣿⣿⣿⣿⣿⣿⣆⠐⢾⣿⣿⣿⠟⠁⠈⠉⠀⠀
                                 ⠀⠀⠀⠀⣤⣤⠀⣿⣿⣿⣿⣿⣿⣿⣿⣿⣧⠈⠿⠟⠁⠀⠀⠀⠀⠀⠀
                                 ⠀⠀⠀⠀⢸⣿⡄⢹⣿⣿⣿⣿⣿⣿⣿⣿⣿⣧⡀⠀⠀⠀⠀⠀⠀⠀⠀
                                 ⠀⠀⠀⠀⣸⣿⣷⡀⢻⣿⣿⣿⣿⣿⣿⣿⣿⣿⣷⡀⠀⠀⠀⠀⠀⠀⠀
                                 ⠀⠀⢰⣾⣿⣿⣿⣷⡀⠻⣿⣿⣿⣿⣿⣿⣿⣿⣿⣷⣄⠀⠀⠀⠀⠀⠀
                                 ⠀⠀⠀⠛⠉⠁⣼⣿⡁⠀⠈⠻⢿⣿⣿⣿⣿⣿⣿⣿⣿⣆⠀⠀⠀⠀⠀
                                 ⠀⠀⠀⠀⣠⡾⠋⣈⣻⣷⣶⡖⠀⠉⠛⠿⢿⣿⣿⣿⣿⣿⡦⠀⠀⠀⠀
                                 ⠀⠀⢀⣴⠿⣿⣟⣋⠉⠀⠉⠛⢷⣤⣷⡆⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
                                 ⠀⣠⡾⠃⢀⣀⣨⣽⣿⠶⣶⣾⣋⠉⢻⡇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
                                 ⠘⠛⠛⠛⠛⠉⠉⠀⠀⠀⠀⠈⠙⠛⠛⠃⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀

 /$$$$$$$                       /$$           /$$$$$$$                  /$$                    
| $$__  $$                     | $$          | $$__  $$                | $$                    
| $$  \ $$ /$$$$$$   /$$$$$$  /$$$$$$        | $$  \ $$  /$$$$$$   /$$$$$$$  /$$$$$$   /$$$$$$ 
| $$$$$$$//$$__  $$ /$$__  $$|_  $$_/        | $$$$$$$/ |____  $$ /$$__  $$ |____  $$ /$$__  $$
| $$____/| $$  \ $$| $$  \__/  | $$          | $$__  $$  /$$$$$$$| $$  | $$  /$$$$$$$| $$  \__/
| $$     | $$  | $$| $$        | $$ /$$      | $$  \ $$ /$$__  $$| $$  | $$ /$$__  $$| $$      
| $$     |  $$$$$$/| $$        |  $$$$/      | $$  | $$|  $$$$$$$|  $$$$$$$|  $$$$$$$| $$      
|__/      \______/ |__/         \___/        |__/  |__/ \_______/ \_______/ \_______/|__/ 


                                  PYTHON PORT SCANNER                                                                                 
                             BECODE - Mihai, Jeremie, Bilal                                                                           
"""
    print(Asciiart)
    print("=" * 60)
    print()

    # Target selection
    print("TARGET CONFIGURATION")
    print("-" * 20)
    while True:
        target = input("Enter the IP address to scan: ").strip()
        if validate_ip(target):
            break
        else:
            print("Invalid IP address format. Please try again.")
    print()

    # Port configuration with default
    print("PORT CONFIGURATION")
    print("-" * 18)
    while True:
        try:
            port_range = input("Enter port range to scan (default 1-65535): ").strip()
            if not port_range:
                port_range = "1-65535"
            start_port, end_port = parse_port_range(port_range)
            if 1 <= start_port <= 65535 and 1 <= end_port <= 65535 and start_port <= end_port:
                break
            else:
                print("Invalid port range. Ports must be between 1-65535 and start <= end.")
        except ValueError:
            print("Invalid port format. Use format like '1-1024' or '80'.")
    print()

    # Threading configuration with default
    print("PERFORMANCE SETTINGS")
    print("-" * 19)
    default_threads = os.cpu_count() * 100
    while True:
        try:
            threads_input = input(f"Enter number of threads to use (default {default_threads} (CPU bound), max 10000): ").strip()
            if not threads_input:
                threads = default_threads
                break
            threads = int(threads_input)
            if 1 <= threads <= 10000:
                break
            else:
                print("Number of threads must be between 1 and 10000.")
        except ValueError:
            print("Invalid input. Please enter a number.")

    # Timeout configuration with default
    while True:
        try:
            timeout_input = input("Enter connection timeout in seconds (default 1): ").strip()
            if not timeout_input:
                timeout = 1.0
                break
            timeout = float(timeout_input)
            if 0.1 <= timeout <= 10:
                break
            else:
                print("Timeout must be between 0.1 and 10 seconds.")
        except ValueError:
            print("Invalid input. Please enter a number.")
    print()

    # Rate limiting question
    print("SECURITY SETTINGS")
    print("-" * 17)
    rate_limit_choice = input("Do you want to enable rate limiting to avoid detection? (Y/N, default N): ").strip().upper()
    if not rate_limit_choice:
        rate_limit_choice = 'N'
    
    delay = 0
    if rate_limit_choice == 'Y':
        while True:
            try:
                delay_input = input("Enter delay between scans in seconds (default 0.1): ").strip()
                if not delay_input:
                    delay = 0.1
                    break
                delay = float(delay_input)
                if 0 <= delay <= 5:
                    break
                else:
                    print("Delay must be between 0 and 5 seconds.")
            except ValueError:
                print("Invalid input. Please enter a number.")
    print()

    # Log saving question
    log_choice = input("Do you want to save scan results to a CSV log file? (Y/N, default N): ").strip().upper()
    if not log_choice:
        log_choice = 'N'
    log_enabled = log_choice == 'Y'

    # Create logs directory if logging is enabled
    if log_enabled and not os.path.exists('./logs'):
        os.makedirs('./logs')
        print("Created logs directory.")

    print()

    # Confirmation
    print("SCAN CONFIGURATION SUMMARY")
    print("=" * 60)
    print(f"Target: {target}")
    print(f"Port Range: {start_port}-{end_port}")
    print(f"Total Ports: {end_port - start_port + 1}")
    print(f"Threads: {threads}")
    print(f"Timeout: {timeout} seconds")
    print(f"Rate Limiting: {'Yes' if delay > 0 else 'No'}")
    if delay > 0:
        print(f"Scan Delay: {delay} seconds")
    print(f"Save Logs: {'Yes' if log_enabled else 'No'}")
    print("=" * 60)

    confirm = input("\nProceed with scan? (Y/N): ").strip().upper()
    if confirm and confirm != "Y":
        print("Scan cancelled by user")
        sys.exit(0)

    return {
        'target': target,
        'start_port': start_port,
        'end_port': end_port,
        'threads': threads,
        'timeout': timeout,
        'rate_limit': delay,
        'log': log_enabled
    }

def parse_command_line():
    """Parse command line arguments as alternative to interactive mode"""
    parser = argparse.ArgumentParser(description='Python Port Scanner CLI Interface')
    parser.add_argument('target', nargs='?', help='Target IP address')
    parser.add_argument('-p', '--ports', default='1-65535', help='Port range (e.g., 1-65535 or 80)')
    parser.add_argument('-t', '--threads', type=int, default=os.cpu_count()*100, help='Number of threads (max 10000)')
    parser.add_argument('-T', '--timeout', type=float, default=1.0, help='Connection timeout (0.1-10 seconds)')
    parser.add_argument('-d', '--delay', type=float, default=0, help='Rate limiting delay between scans (0-5 seconds)')
    parser.add_argument('--log', action='store_true', help='Save results to CSV log file')
    parser.add_argument('--interactive', action='store_true', help='Force interactive mode')

    return parser.parse_args()

def main():
    """Main entry point for the CLI interface"""
    args = parse_command_line()

    # Check if we should use interactive mode
    if args.interactive or not args.target:
        config = get_user_input()
    else:
        # Validate command line arguments
        if not validate_ip(args.target):
            print(f"Error: Invalid IP address '{args.target}'")
            sys.exit(1)

        try:
            start_port, end_port = parse_port_range(args.ports)
        except ValueError:
            print(f"Error: Invalid port range '{args.ports}'")
            sys.exit(1)

        # Validate ranges
        if not (1 <= args.threads <= 10000):
            print("Error: Number of threads must be between 1 and 10000")
            sys.exit(1)

        if not (0.1 <= args.timeout <= 10):
            print("Error: Timeout must be between 0.1 and 10 seconds")
            sys.exit(1)

        if not (0 <= args.delay <= 5):
            print("Error: Delay must be between 0 and 5 seconds")
            sys.exit(1)

        # Create logs directory if logging is enabled
        if args.log and not os.path.exists(f'./logs/'):
            os.makedirs(f'./logs/')
        

        config = {
            'target': args.target,
            'start_port': start_port,
            'end_port': end_port,
            'threads': args.threads,
            'timeout': args.timeout,
            'rate_limit': args.delay,
            'log': args.log
        }

    print("\nStarting port scanner with the following configuration:")
    print(f"Target: {config['target']}")
    print(f"Ports: {config['start_port']}-{config['end_port']}")
    print(f"Threads: {config['threads']}")
    print(f"Timeout: {config['timeout']}s")
    if config['rate_limit'] > 0:
        print(f"Rate Limit: {config['rate_limit']}s delay")
    if config['log']:
        print("Logging: Enabled")
    print()

    # Initialize and run the scanner
    scanner = ThreadedPortScanner(
        ip=config['target'],
        start_port=config['start_port'],
        end_port=config['end_port'],
        num_threads=config['threads'],
        timeout=config['timeout'],
        rate_limit=config['rate_limit'],
        log=config['log']
    )

    scanner.scan()

if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print("\n\nScan interrupted by user. Exiting...")
        sys.exit(1)
    except Exception as e:
        print(f"\nError: {e}")
        sys.exit(1)
