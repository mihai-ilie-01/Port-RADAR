import socket
import time
from threading import Thread, Lock
import queue
from queue import Queue, Empty
import os
from datetime import datetime
import pandas as pd
import errno
from tqdm import tqdm

class ThreadedPortScanner:
    
    def __init__(self, ip, start_port=1, end_port=65535, selected_ports=None, num_threads=os.cpu_count()*100, timeout=1,rate_limit=0.1, log=False):
        # Parameter initialized instances
        self.ip = ip
        self.start_port = start_port
        self.end_port = end_port
        self.selected_ports = selected_ports
        self.num_threads = num_threads
        self.timeout = timeout
        self.rate_limit = rate_limit
        self.log = log

        # Internally initialized instances
        self.open_ports = []
        self.error_ports = []
        self.closed_ports = []
        self.port_queue = Queue()
        self.print_lock = Lock()
        self.startime = datetime.now().strftime("%Y-%m-%d_%H%M%S")
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
                self.scan_port(port)
                self.port_queue.task_done()
            except queue.Empty:
                break
    
    def scan(self):
        """Start the port scanning"""
        if self.selected_ports is None:
            print(f"Scanning {self.ip} from port {self.start_port} to {self.end_port}")
        else:
            print(f"Scanning {self.selected_ports} from ip {self.ip}")
        print(f"Using {self.num_threads} threads with {self.timeout}s timeout")
        if self.rate_limit > 0:
            print(f"Rate limiting enabled : {self.rate_limit} seconds delay between scans")
        start_time = time.time()
        
        # Initialize progress bar
        self.progress_bar = tqdm(
            total=self.total_ports,
            desc="Scanning ports",
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
        if self.log == False:
            if len(self.open_ports) > 0:
                print(f"Found {len(self.open_ports)} port(s) for target : {self.ip}, open ports: {[elem[2] for elem in self.open_ports]}.")
            if len(self.closed_ports) > 0:
                print(f"Found {len(self.closed_ports)} closed ports.")
            if len(self.error_ports) > 0:
                print(f"Found {len(self.error_ports)} errors while scanning ports.")

        else:
            if len(self.open_ports) > 0:
                print(f"Found {len(self.open_ports)} port(s) for target : {self.ip}, open ports: {[elem[2] for elem in self.open_ports]} (see {self.startime}_openports.cvs)")
            if len(self.closed_ports) > 0:
                print(f"Found {len(self.closed_ports)} closed ports (see {self.startime}_closedports.csv for more details)")
            if len(self.error_ports) > 0:
                print(f"Found {len(self.error_ports)} errors while scanning ports (see _{self.startime}_errorlogs.csv for more details)")
            os.mkdir(f"./logs/{self.startime}")
            if len(self.open_ports) > 0:
                port_df = pd.DataFrame(sorted(self.open_ports), columns=["TIME", "IP", "PORT", "TYPE", "STATUS"])
                port_df.to_csv(f"./logs/{self.startime}/{self.startime}_scannedports.csv", index=False)
            if len(self.error_ports) > 0:
                error_df = pd.DataFrame(sorted(self.error_ports), columns=["TIME", "IP", "PORT", "TYPE", "ERROR"])
                error_df.to_csv(f"./logs/{self.startime}/{self.startime}_errorlogs.csv", index=False)
            if len(self.closed_ports) > 0:
                closed_df = pd.DataFrame(sorted(self.closed_ports), columns=["TIME", "IP", "PORT", "TYPE", "ERROR"])
                closed_df.to_csv(f"./logs/{self.startime}/{self.startime}_closedports.csv", index=False)