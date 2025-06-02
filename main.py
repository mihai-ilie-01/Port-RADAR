import sys
import argparse
import os
import re
from scan import ThreadedPortScanner

default_ip = '127.0.0.1'

min_port = 1
max_port = 65535

min_threads = 1
max_threads = 10000
default_threads = min(os.cpu_count() * 100, 1000)

min_timeout = 0.0
max_timeout = 10.0
default_timeout = 1.0

min_delay = 0.0
max_delay = 5.0
default_delay = 0.1

yes = "Y"
no = "N"

ipv4_pattern = r"^(25[0-5]|2[0-4]\d|1\d{2}|[1-9]?[0-9]?)(\.(25[0-5]|2[0-4]\d|1\d{2}|[1-9]?[0-9]?)){3}$"
domain_pattern = r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b'

default_scan_type = "connect"
valid_scan_types = ["connect", "syn"]

log_directory = './logs'

Asciiart = r"""
    
                               .:^~~^^^^^~~:                 
                             .^~^^:.........!!                
                           :~~:..............J!               
            .^!^.       .^!^:...::...........7?:              
            ?77~!JJJ?77J??!!!!!~!!: .........?^7              
            ^!?J7?55!77!~~!!!!~~~~~^^^::::..^7.?              
              .P557J?^. .......::::^^^~~~!!!J:.7.             
               J^7?~..........           . !~..?.             
               7!~?7......   ...          ~!.::?              
               ~Y: ~?:      :!7!^:^~~.   ~!.:.!~              
              .?J.. :?^    .7?7~~!J7?!~ ~!.:.:?               
             .7:J:   .7!    .:!J???7!?~!~.::.??!^.            
             7: 7~     !7.    ^J??7!77!^.:.:??^:~!!:          
            ~!  ~?      ~?:   .^!7!!!~:::.^JJ!~:::^77         
            ?.  :Y.      :?^     .~~:.:.:!J?!~~~~^:^7!        
            ?   .!:       .7!  .~!^...:!JJ?7~~~~~~~~~J        
            7               !7~~:..:^7YJ?7!~~~~~~~~~?^        
            ?.           .:^~~:::^!J5PYYY?!~~~~~~~!?^         
            .!:.    ..:^~!!~~~~~^:.:~YYJJYYY?7!!!7!.          
              :^~!!7777!~~^^:.       7J77????Y...             
                                 :!77YYJJJJJJ577!~.           
                                 ?7!!!??JJJ???7?JY~           
                            .~!77Y?~^^~!~~!!!!!7JY?!77~.      
                          .~!:::::~!!77???????77!!~~~^~7^     
                         ^!^.::::......7~^^^^^^:^^^^^^^^!!.   
                       :!~:.:::::::::::7^^^^^^^^^^^^^^^^^~7^  
                      !!:...:::::::::.~!^^^^^^^^^^^^^^^^^^^!~ 
                      :^~~~^^::...:::.7~^^^^^^^^^^^^^^^^^~~~7?
                          .:^^~~^^::.:7^^^^^^^~~~~~~~~~~^^::..
                               .:^^~~7?~!!!~~^^::...  


 /$$$$$$$                       /$$           /$$$$$$$                  /$$                    
| $$__  $$                     | $$          | $$__  $$                | $$                    
| $$  \ $$ /$$$$$$   /$$$$$$  /$$$$$$        | $$  \ $$  /$$$$$$   /$$$$$$$  /$$$$$$   /$$$$$$ 
| $$$$$$$//$$__  $$ /$$__  $$|_  $$_/        | $$$$$$$/ |____  $$ /$$__  $$ |____  $$ /$$__  $$
| $$____/| $$  \ $$| $$  \__/  | $$          | $$__  $$  /$$$$$$$| $$  | $$  /$$$$$$$| $$  \__/
| $$     | $$  | $$| $$        | $$ /$$      | $$  \ $$ /$$__  $$| $$  | $$ /$$__  $$| $$      
| $$     |  $$$$$$/| $$        |  $$$$/      | $$  | $$|  $$$$$$$|  $$$$$$$|  $$$$$$$| $$      
|__/      \______/ |__/         \___/        |__/  |__/ \_______/ \_______/ \_______/|__/ 


                                  PYTHON PORT SCANNER                                                                                 
                             BECODE - Mihai, Jeremie, Bilel                                                                           
"""


def validate_ip(ip):
    """Validate IP address format test"""
    if re.match(ipv4_pattern, ip) or re.match(domain_pattern, ip):
        return True
    else:
        return False
    
def validate_scan_type(scan_type_choice):
    """Validate scan type choice"""
    try:
        if not scan_type_choice:
            return default_scan_type
        
        scan_type = scan_type_choice.lower().strip()
        if scan_type not in valid_scan_types:
            print(f"Invalid scan type: {scan_type_choice}. Valid options are: {', '.join(valid_scan_types)}")
            raise ValueError
        
        return scan_type
    except (ValueError, TypeError):
        raise ValueError

def validate_port_choice(port_choice):
    try:    
        if not port_choice:
            return {'start_port' : min_port, 'end_port' : max_port, 'selected_ports' : None}
        contains_dash, contains_comma = '-' in port_choice, ',' in port_choice
        if (contains_dash and contains_comma) or port_choice.count('-') > 1:
            print(f"Invalid Format: {port_choice}, input cannot contain both ',' and '-' ormore than one '-'.")
            raise ValueError
        
        if contains_dash:
            start_port, end_port = map(int,port_choice.split('-'))
            if not (1 <= start_port <= max_port and 1 <= end_port <= max_port and start_port <= end_port):
                print(f"Invalid port range: {port_choice}, the desired port range must be between {min_port} and {max_port}.")
                raise ValueError
            return {'start_port' : int(start_port), 'end_port' : int(end_port), 'selected_ports' : None}
        
        elif contains_comma:
            selected_ports = [int(p.strip()) for p in port_choice.split(',')]
            if not all(min_port <= port <= max_port for port in selected_ports):
                print(f"Invalid ports: {port_choice}, each port must be between {min_port} and {max_port}.")
                raise ValueError
            return {'start_port' : None, 'end_port' : None, 'selected_ports' : selected_ports}
        
        else:
            port = int(port_choice)
            if not min_port <= port <= max_port:
                print(f"Invalid port range: {port_choice}, the desired port range must be between {min_port} and {max_port}.")
                raise ValueError
            return {'start_port' : port, 'end_port' : port, 'selected_ports' : None}
    
    except (ValueError, TypeError):
        raise ValueError
    

def validate_thread_choice(thread_choice):
    try:    
        if not thread_choice:
            return default_threads
        
        if not min_threads <= int(thread_choice) <= max_threads:
            print(f"Threads must be between {min_threads} and {max_threads}.")
            raise ValueError
        
        else: 
            return int(thread_choice)

    except (TypeError, ValueError):
        raise ValueError


def validate_timeout_choice(timeout_choice):
    try:
        if not timeout_choice:
            return default_timeout

        if not min_timeout <= float(timeout_choice) <= max_timeout:
            print(f"Timeout must be between {min_timeout} seconds and {max_timeout} seconds.")
            raise ValueError
        
        else:
            return float(timeout_choice)
    
    except (ValueError, TypeError):
        raise ValueError


def validate_yes_no(yes_no):
    try:
        if not yes_no or yes_no == no:
            return False
        if yes_no not in [yes, no]:
            raise ValueError
        return True
    except (ValueError, TypeError):
        raise ValueError


def validate_delay(delay_choice):
    try:
        if not delay_choice:
            return default_delay
        if not min_delay <= float(delay_choice) <= max_delay:
            print(f"Invalid delay: {delay_choice}, delay must be between {min_delay} seconds and {max_delay} seconds.")
            raise ValueError
        else:
            return float(delay_choice)
    except (ValueError, TypeError):
        raise ValueError
    

def create_log_directory():
    if not os.path.exists(log_directory):
        os.makedirs(log_directory)


def get_user_input():
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
            print("Invalid IP address format. Please try again.\n")
    print()

    # Port configuration with default
    print("PORT CONFIGURATION")
    print("-" * 18)
    while True:
        try:
            input_ports = input("Enter port range to scan (default 1-65535): ").strip()
            data_ports = validate_port_choice(input_ports)
            break
        except ValueError:
            print("Please try again. Valid formats are '443', '1-1024' or '1,23,8080,443'.\n")
    print()
    
    # Scan type configuration
    print("SCAN TYPE CONFIGURATION")
    print("-" * 23)
    while True:
        try:
            input_scan_type = input(f"Enter scan type (connect/syn, default {default_scan_type}): ").strip()
            data_scan_type = validate_scan_type(input_scan_type)
            break
        except ValueError:
            print("Please enter 'connect' or 'syn'.\n")

    # Warning for SYN scan
    if data_scan_type == "syn":
        print("⚠️  WARNING: SYN scan requires:")
        print("   - Root/Administrator privileges")
        print("   - Scapy library (pip install scapy)")
        print("   - Will fallback to connect scan if requirements not met")
    print()

    # Threading configuration with default
    print("PERFORMANCE SETTINGS")
    print("-" * 19)
    while True:
        try:
            input_threads = input(f"Enter number of threads to use (default {default_threads} (CPU bound), max 10000): ").strip()
            data_threads = validate_thread_choice(input_threads)
            break
        except ValueError:
            print("Please enter a valid number to try again.\n")
    print()
    # Timeout configuration with default
    while True:
        try:
            input_timeout = input("Enter connection timeout in seconds (default 1): ").strip()
            data_timeout = validate_timeout_choice(input_timeout)
            break
        except ValueError:
            print("Please enter a valid number to try again.\n")
    print()

    # Rate limiting question
    print("SECURITY SETTINGS")
    print("-" * 17)
    while True:
        try:
            input_rate_limit_choice = input("Do you want to enable rate limiting to avoid detection? (Y/N, default N): ").strip().upper()
            rate_limit_choice = validate_yes_no(input_rate_limit_choice)
            if rate_limit_choice == False:
                data_delay= min_delay
                break
            else:
                print()
                while True:
                    try:
                        input_delay = input("Enter delay between scans in seconds (default 0.1): ").strip()
                        data_delay = validate_delay(input_delay)
                        break
                    except ValueError:
                        print(f"Please input a number between {min_delay} and {max_delay} to try again.\n")
            break
        except ValueError:
            print("Please input Y or N.\n")
    print()

    # Log saving question
    while True:
        try:
            input_log_choice = input("Do you want to save scan results to a CSV log file? (Y/N, default N): ").strip().upper()
            log_choice = validate_yes_no(input_log_choice)
            break
        except ValueError:
            print("Please input Y or N.\n")

    # Create logs directory if logging is enabled
    if log_choice:
        create_log_directory()
    
    print()

    # Confirmation
    print("SCAN CONFIGURATION SUMMARY")
    print("=" * 60)
    print(f"Target: {target}")
    print(f"Scan Type: {data_scan_type.upper()}") 
    if data_ports['selected_ports'] is None:
        print(f"Port Range: {data_ports['start_port']}-{data_ports['end_port']}")
        print(f"Total Ports: {data_ports['end_port'] - data_ports['start_port'] + 1}")
    else:
        print(f"Selected Ports: {data_ports['selected_ports']}")
        print(f"Total Ports: {len(data_ports['selected_ports'])}")
    print(f"Threads: {data_threads}")
    print(f"Timeout: {data_timeout} seconds")
    print(f"Rate Limiting: {'Yes' if data_delay > 0 else 'No'}")
    if data_delay > 0:
        print(f"Scan Delay: {data_delay} seconds")
    print(f"Save Logs: {'Yes' if log_choice else 'No'}")
    print("=" * 60)

    confirm = input("\nProceed with scan? (Y/N, default Y): ").strip().upper()
    if confirm and confirm != yes:
        print("Scan cancelled by user")
        sys.exit(0)
        
    return {
        'target': target,
        'start_port': data_ports['start_port'],
        'end_port': data_ports['end_port'],
        'scan_type': data_scan_type,
        'selected_ports' : data_ports['selected_ports'],
        'threads': data_threads,
        'timeout': data_timeout,
        'rate_limit': data_delay,
        'log': log_choice
    }

def parse_command_line():
    """Parse command line arguments as alternative to interactive mode"""
    parser = argparse.ArgumentParser(description='Python Port Scanner CLI Interface')
    parser.add_argument('target', nargs='?', help='Target IP address')
    parser.add_argument('-p', '--ports', default=f'{min_port}-{max_port}', help='Port range (e.g., 1-65535 or 80)')
    parser.add_argument('-s', '--scan-type', choices=['connect', 'syn'], default=default_scan_type, help='Scan type: connect or syn')
    parser.add_argument('-t', '--threads', type=int, default=default_threads, help='Number of threads (max 10000)')
    parser.add_argument('-T', '--timeout', type=float, default=default_timeout, help='Connection timeout (0.1-10 seconds)')
    parser.add_argument('-d', '--delay', type=float, default=default_delay, help='Rate limiting delay between scans (0-5 seconds)')
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
            data_ports = validate_port_choice(args.ports)
        except ValueError:
            print(f"Error: Invalid port range '{args.ports}'")
            sys.exit(1)

        try:
            data_scan_type = validate_scan_type(args.scan_type)
        except ValueError:
            print(f"Error: Invalid scan type '{args.scan_type}'")
            sys.exit(1)

        # Validate other parameters
        try:
            data_threads = validate_thread_choice(args.threads)
        except ValueError:
            print(f"Error: Number of threads must be between {min_threads} and {max_threads}")
            sys.exit(1)
        
        try:
            data_timeout = validate_timeout_choice(args.timeout)
        except ValueError:
            print(f"Error: Timeout must be between {min_timeout} and {max_timeout} seconds")
            sys.exit(1)
        
        try:
            data_delay = validate_delay(args.delay)
        except ValueError:
            print(f"Error: Delay must be between {min_delay} and {max_delay} seconds")
            sys.exit(1)
        
        # Create logs directory if logging is enabled
        if args.log:
            create_log_directory()
        
        config = {
            'target': args.target,
            'scan_type': data_scan_type,
            'start_port': data_ports['start_port'],
            'end_port': data_ports['end_port'],
            'selected_ports': data_ports['selected_ports'],
            'threads': data_threads,
            'timeout': data_timeout,
            'rate_limit': data_delay,
            'log': args.log
        }

    print("\nStarting port scanner with the following configuration:")
    print(f"Target: {config['target']}")
    print(f"Scan Type: {config['scan_type'].upper()}")
    if config['selected_ports'] is not None:
        print(f"Selected Ports: {config['selected_ports']}")
    else:
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
        selected_ports=config['selected_ports'],
        num_threads=config['threads'],
        timeout=config['timeout'],
        rate_limit=config['rate_limit'],
        log=config['log'],
        scan_type=config['scan_type']
    )

    scanner.scan(config['scan_type'])
    
if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print("\n\nScan interrupted by user. Exiting...")
        sys.exit(1)
    except Exception as e:
        print(f"\nError: {e}")
        sys.exit(1)