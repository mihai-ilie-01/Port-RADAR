import socket
import time
import threading
from threading import Thread, Lock
import queue
from queue import Queue, Empty
import os
from datetime import datetime
import pandas as pd
import errno
from tqdm import tqdm
import scapy.all as scapy

class ThreadedPortScanner:
    
    def __init__(self, ip, start_port=1, end_port=65535, selected_ports=None, num_threads=os.cpu_count()*100, timeout=1,rate_limit=0.1, log=False, scan_type="connect"):
        # Parameter initialized instances
        self.ip = ip
        self.start_port = start_port
        self.end_port = end_port
        self.scan_type = scan_type
        self.selected_ports = selected_ports
        self.num_threads = num_threads
        self.timeout = timeout
        self.rate_limit = rate_limit
        self.log = log
        self.scapy_lock = threading.Lock()
        
        # Internally initialized instances
        self.open_ports = []
        self.error_ports = []
        self.closed_ports = []
        self.port_queue = Queue()
        self.print_lock = Lock()
        self.startime = datetime.now().strftime("%Y-%m-%d_%H%M%S")
        
        self.ERROR_CODES = {
        errno.ECONNREFUSED: ("Connection refused", "Port is closed"),
        errno.ETIMEDOUT: ("Connection timed out", "Port may be filtered"),
        errno.EHOSTUNREACH: ("Host unreachable", "Host is down or unreachable"),
        errno.ENETUNREACH: ("Network unreachable", "Network routing issue"),
        errno.ECONNRESET: ("Connection reset", "Connection was reset by peer")
        }

        if selected_ports is None:
            self.total_ports= end_port - start_port + 1
        else:
            self.total_ports= len(selected_ports)
        self.progress_bar = None
        self.completed_ports = 0

        if selected_ports:
            for port in selected_ports:    # Fill the queue with ports to scan
                self.port_queue.put(port)
        else:
            for port in range(start_port, end_port + 1):    # Fill the queue with ports to scan
                self.port_queue.put(port)

    def scan_port(self, port):
        """
        Tries to establish a TCP connection with the specified port.    
        port : the port we try to establish a connection with
        """
        try:
            if self.rate_limit > 0:
                time.sleep(self.rate_limit)     
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(self.timeout)
                result = s.connect_ex((self.ip, port))              
                timestamp = datetime.now().strftime("%H:%M:%S")             
                with self.print_lock:
                    if result == 0:
                        # Port is open
                        self.open_ports.append((timestamp, self.ip, port, "tcp", "open"))
                        tqdm.write(f"[{timestamp}] Found open port: {port}")
                        if self.progress_bar:
                            self.progress_bar.set_description(f"Scanning ports (Found: {len(self.open_ports)} open)")                   
                    elif result == errno.ECONNREFUSED:
                        self.closed_ports.append((timestamp, self.ip, port, "tcp", "Connection refused - port is closed"))                  
                    elif result in self.ERROR_CODES:
                        _, error_msg = self.ERROR_CODES[result]
                        self.error_ports.append((timestamp, self.ip, port, "tcp", f"{error_msg} on port {port}"))                   
                    else:
                        error_name = errno.errorcode.get(result, f"UNKNOWN_ERROR_{result}")
                        self.error_ports.append((timestamp, self.ip, port, "tcp", f"{error_name}: Port scan failed on {port}"))     
        except Exception as e:
            with self.print_lock:
                timestamp = datetime.now().strftime("%H:%M:%S")
                self.error_ports.append((timestamp, self.ip, port, "tcp", f"Exception error for port {port}: {str(e)}"))        
        finally:
            with self.print_lock:
                self.completed_ports += 1
                if self.progress_bar:
                    self.progress_bar.update(1)


    def worker(self):
        """Worker thread function"""
        while not self.port_queue.empty():
            try:
                port = self.port_queue.get(timeout=1)

                if self.scan_type == "syn":
                    self.syn_scan_port(port)
                else:
                    self.scan_port(port)

                self.port_queue.task_done()
            except queue.Empty:
                break

    def syn_scan_port(self, port):
        """Perform SYN scan on a specific port with thread safety"""
        try:
            import scapy.all as scapy

            with self.scapy_lock:  # Serialize all Scapy operations
                # Create SYN packet
                packet = scapy.IP(dst=self.ip) / scapy.TCP(dport=port, flags="S")

                # Send packet and wait for response
                response = scapy.sr1(packet, timeout=self.timeout, verbose=0)

                if response and response.haslayer(scapy.TCP):
                    if response[scapy.TCP].flags == 18:  # SYN-ACK
                        # Send RST to close connection cleanly
                        rst_packet = scapy.IP(dst=self.ip) / scapy.TCP(dport=port, flags="R")
                        scapy.send(rst_packet, verbose=0)
                        result = "open"
                    elif response[scapy.TCP].flags == 4:  # RST
                        result = "closed"
                    else:
                        result = "unknown"
                elif response and response.haslayer(scapy.ICMP):
                    result = "filtered"
                else:
                    result = "filtered"

            # Handle results outside the lock
            timestamp = datetime.now().strftime("%H:%M:%S")
            with self.print_lock:
                if result == "open":
                    self.open_ports.append((timestamp, self.ip, port, "syn", "open"))
                    tqdm.write(f"[{timestamp}] Found open port: {port}")
                elif result == "closed":
                    self.closed_ports.append((timestamp, self.ip, port, "syn", "closed"))
                else:
                    self.closed_ports.append((timestamp, self.ip, port, "syn", result))

            return result

        except Exception as e:
            timestamp = datetime.now().strftime("%H:%M:%S")
            with self.print_lock:
                self.error_ports.append((timestamp, self.ip, port, "syn", f"Exception: {str(e)}"))
            return f"error: {str(e)}"
        finally:
            with self.print_lock:
                if self.progress_bar:
                    self.progress_bar.update(1)

    
    def scan(self, scan_type="connect"):
        """
        Start the port scanning

        Args:
            scan_type (str): Type of scan to perform ("connect" or "syn")
        """
        # Check if SYN scan is requested and validate requirements
        if scan_type == "syn":
            try:
                # Check for root privileges on Unix-like systems
                try:
                    if os.geteuid() != 0:
                        print("Warning: SYN scan requires root privileges. Falling back to connect scan.")
                        scan_type = "connect"
                except AttributeError:
                    # Windows doesn't have geteuid, try alternative check
                    import ctypes
                    try:
                        is_admin = ctypes.windll.shell32.IsUserAnAdmin()
                        if not is_admin:
                            print("Warning: SYN scan requires administrator privileges. Falling back to connect scan.")
                            scan_type = "connect"
                    except:
                        print("Warning: Cannot verify privileges. Attempting SYN scan anyway.")
            except ImportError:
                print("Warning: scapy library not found. Install with 'pip install scapy'. Falling back to connect scan.")
                scan_type = "connect"

        # Store scan type for worker threads to use
        self.scan_type = scan_type

        # Display scan information
        if self.selected_ports is None:
            print(f"Scanning {self.ip} from port {self.start_port} to {self.end_port}")
        else:
            print(f"Scanning {self.selected_ports} from ip {self.ip}")

        print(f"Using {self.num_threads} threads with {self.timeout}s timeout")
        print(f"Scan type: {scan_type.upper()}")

        if self.rate_limit > 0:
            print(f"Rate limiting enabled : {self.rate_limit} seconds delay between scans")

        start_time = time.time()

        # Initialize progress bar
        self.progress_bar = tqdm(
            total=self.total_ports,
            desc=f"Scanning ports ({scan_type})",
            unit="ports",
            ncols=100,
            bar_format='{l_bar}{bar}| {n_fmt}/{total_fmt} [{elapsed}, {rate_fmt}]'
        )

        # Create and start worker threads
        threads = []
        for _ in range(self.num_threads):
            t = Thread(target=self.worker)
            t.daemon = True
            t.start()
            threads.append(t)

        # Wait for all threads to complete
        for t in threads:
            t.join()

        self.progress_bar.close()

        end_time = time.time()

        print(f"\nScan completed in {end_time - start_time:.2f} seconds")

        # Display results
        if self.log == False:
            if len(self.open_ports) > 0:
                print(f"Found {len(self.open_ports)} port(s) for target : {self.ip}, open ports: {[elem[2] for elem in self.open_ports]}.")
            if len(self.closed_ports) > 0:
                print(f"Found {len(self.closed_ports)} closed ports.")
            if len(self.error_ports) > 0:
                print(f"Found {len(self.error_ports)} errors while scanning ports.")
        else:
            # Logging enabled - save results to CSV files
            if len(self.open_ports) > 0:
                print(f"Found {len(self.open_ports)} port(s) for target : {self.ip}, open ports: {[elem[2] for elem in self.open_ports]} (see {self.startime}_openports.csv)")
            if len(self.closed_ports) > 0:
                print(f"Found {len(self.closed_ports)} closed ports (see {self.startime}_closedports.csv for more details)")
            if len(self.error_ports) > 0:
                print(f"Found {len(self.error_ports)} errors while scanning ports (see {self.startime}_errorlogs.csv for more details)")

            # Create logs directory
            try:
                os.makedirs(f"./logs/{self.startime}", exist_ok=True)
            except Exception as e:
                print(f"Warning: Could not create log directory: {e}")

            # Save open ports
            if len(self.open_ports) > 0:
                try:
                    port_df = pd.DataFrame(sorted(self.open_ports), columns=["TIME", "IP", "PORT", "TYPE", "STATUS"])
                    port_df.to_csv(f"./logs/{self.startime}/{self.startime}_scannedports.csv", index=False)
                except Exception as e:
                    print(f"Warning: Could not save open ports log: {e}")

            # Save error ports
            if len(self.error_ports) > 0:
                try:
                    error_df = pd.DataFrame(sorted(self.error_ports), columns=["TIME", "IP", "PORT", "TYPE", "ERROR"])
                    error_df.to_csv(f"./logs/{self.startime}/{self.startime}_errorlogs.csv", index=False)
                except Exception as e:
                    print(f"Warning: Could not save error log: {e}")

            # Save closed ports
            if len(self.closed_ports) > 0:
                try:
                    closed_df = pd.DataFrame(sorted(self.closed_ports), columns=["TIME", "IP", "PORT", "TYPE", "STATUS"])
                    closed_df.to_csv(f"./logs/{self.startime}/{self.startime}_closedports.csv", index=False)
                except Exception as e:
                    print(f"Warning: Could not save closed ports log: {e}")
