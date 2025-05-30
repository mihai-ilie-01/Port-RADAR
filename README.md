```
 /$$$$$$$                       /$$           /$$$$$$$                  /$$                    
| $$__  $$                     | $$          | $$__  $$                | $$                    
| $$  \ $$ /$$$$$$   /$$$$$$  /$$$$$$        | $$  \ $$  /$$$$$$   /$$$$$$$  /$$$$$$   /$$$$$$ 
| $$$$$$$//$$__  $$ /$$__  $$|_  $$_/        | $$$$$$$/ |____  $$ /$$__  $$ |____  $$ /$$__  $$
| $$____/| $$  \ $$| $$  \__/  | $$          | $$__  $$  /$$$$$$$| $$  | $$  /$$$$$$$| $$  \__/
| $$     | $$  | $$| $$        | $$ /$$      | $$  \ $$ /$$__  $$| $$  | $$ /$$__  $$| $$      
| $$     |  $$$$$$/| $$        |  $$$$/      | $$  | $$|  $$$$$$$|  $$$$$$$|  $$$$$$$| $$      
|__/      \______/ |__/         \___/        |__/  |__/ \_______/ \_______/ \_______/|__/
'
```
A fast, multi-threaded TCP port scanner written in Python with support for both TCP connect and SYN scanning. Scan single hosts or ranges of ports with customizable performance and logging options, either interactively or via command-line.

---

## Features

- **Dual scan modes**: TCP connect scan and SYN scan (stealth scanning)
- Multi-threaded scanning for high speed (default: 100 × CPU cores)
- Customizable port ranges and thread counts
- Adjustable connection timeout and rate limiting (delay between scans)
- Interactive and command-line interfaces
- CSV logging of open ports, closed ports, and errors
- Progress bar with real-time results display
- Cross-platform compatibility (Windows, Linux, macOS)

---

## Requirements

- Python 3.7+
- [tqdm](https://pypi.org/project/tqdm/)
- [pandas](https://pypi.org/project/pandas/)
- [scapy](https://pypi.org/project/scapy/) (for SYN scanning)

Install dependencies with:

```
pip install -r requirements.txt
```

**For SYN scanning:**
- Root/Administrator privileges required
- Scapy library: `pip install scapy`

---

## Usage

You can run the scanner in **interactive mode** (guided prompts) or **command-line mode** (direct arguments).

### Interactive Mode

Start the program without arguments, or use `--interactive`:

```
python main.py
# or
python main.py --interactive
```

You will be prompted for:

- Target IP address
- Scan type (connect or syn)
- Port range (e.g., `1-1024`, `80`, or `22,80,443`)
- Number of threads (default: 100 × CPU cores)
- Connection timeout (default: 1 second)
- Rate limiting (delay between scans, optional)
- Whether to save logs to CSV

### Command-Line Mode

```
python main.py TARGET_IP [options]
```

**Options:**

| Option           | Description                                       | Default              |
|------------------|---------------------------------------------------|----------------------|
| `-p`, `--ports`  | Port range (e.g. `1-65535`, `80`, `22,80,443`)    | `1-65535`            |
| `-s`, `--scan-type` | Scan type: `connect` or `syn`                  | `connect`            |
| `-t`, `--threads`| Number of threads (max 10000)                     | `100 × CPU cores`    |
| `-T`, `--timeout`| Connection timeout (seconds, 0.1–10)              | `1.0`                |
| `-d`, `--delay`  | Delay between scans (seconds, 0–5)                | `0`                  |
| `--log`          | Save results to CSV log file                      | Off                  |
| `--interactive`  | Force interactive mode                            | Off                  |

**Examples:**

```
# TCP connect scan
python main.py 192.168.1.1 -p 1-1024 -t 500 -T 2 --log

# SYN scan (requires root privileges)
sudo python main.py 192.168.1.1 -p 1-1000 -s syn -t 200

# Scan specific ports with rate limiting
python main.py 10.0.0.1 -p 22,80,443,8080 -s connect -d 0.5
```

---

## Scan Types

### TCP Connect Scan (Default)
- **Speed**: Very fast with multithreading
- **Stealth**: Low (completes full TCP handshake)
- **Privileges**: No special privileges required
- **Detection**: Easily detected by firewalls/IDS

### SYN Scan (Stealth)
- **Speed**: Moderate (serialized due to threading constraints)
- **Stealth**: High (half-open connections)
- **Privileges**: Requires root/administrator access
- **Detection**: Harder to detect, more stealthy

**Note**: SYN scanning automatically falls back to connect scan if:
- Scapy library is not installed
- Insufficient privileges
- Threading conflicts occur

---

## Output

- Open ports are displayed in real-time during scanning
- Progress bar shows scan completion status
- On completion, summary statistics are displayed
- If logging is enabled, results are saved in the `logs/` directory:
  - `scannedports_.csv` — Open ports
  - `errorlogs_.csv` — Errors and timeouts
  - `closedports_.csv` — Closed/filtered ports

---

## Performance Notes

- **Connect scans**: Typically 10x faster due to full multithreading
- **SYN scans**: Use threading locks to prevent Scapy conflicts (slower but stealthier)
- **Thread optimization**: SYN scans may use fewer threads automatically
- **Rate limiting**: Use `-d` option to avoid detection by security systems

---

## Example Output

```
$ sudo python main.py 192.168.1.1 -p 1-1000 -s syn -t 100 --log

Scanning 192.168.1.1 from port 1 to 1000
Using 100 threads with 1.0s timeout
Scan type: SYN

