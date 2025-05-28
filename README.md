---
 /$$$$$$$                       /$$           /$$$$$$$                  /$$                    
| $$__  $$                     | $$          | $$__  $$                | $$                    
| $$  \ $$ /$$$$$$   /$$$$$$  /$$$$$$        | $$  \ $$  /$$$$$$   /$$$$$$$  /$$$$$$   /$$$$$$ 
| $$$$$$$//$$__  $$ /$$__  $$|_  $$_/        | $$$$$$$/ |____  $$ /$$__  $$ |____  $$ /$$__  $$
| $$____/| $$  \ $$| $$  \__/  | $$          | $$__  $$  /$$$$$$$| $$  | $$  /$$$$$$$| $$  \__/
| $$     | $$  | $$| $$        | $$ /$$      | $$  \ $$ /$$__  $$| $$  | $$ /$$__  $$| $$      
| $$     |  $$$$$$/| $$        |  $$$$/      | $$  | $$|  $$$$$$$|  $$$$$$$|  $$$$$$$| $$      
|__/      \______/ |__/         \___/        |__/  |__/ \_______/ \_______/ \_______/|__/ 

---

A fast, multi-threaded TCP port scanner written in Python. Scan single hosts or ranges of ports with customizable performance and logging options, either interactively or via command-line.

---

## Features

- Multi-threaded scanning for high speed (default: 100 × CPU cores)
- Customizable port ranges and thread counts
- Adjustable connection timeout and rate limiting (delay between scans)
- Interactive and command-line interfaces
- CSV logging of open ports and errors
- Progress bar with real-time results display

---

## Requirements

- Python 3.7+
- [tqdm](https://pypi.org/project/tqdm/)
- [pandas](https://pypi.org/project/pandas/)

Install dependencies with:

```bash
pip install -r requirements.txt
```

---

## Usage

You can run the scanner in **interactive mode** (guided prompts) or **command-line mode** (direct arguments).

### Interactive Mode

Start the program without arguments, or use `--interactive`:

```bash
python main.py
# or
python main.py --interactive
```

You will be prompted for:

- Target IP address
- Port range (e.g., `1-1024`, `80`, or `22,80,443`)
- Number of threads (default: 100 × CPU cores)
- Connection timeout (default: 1 second)
- Rate limiting (delay between scans, optional)
- Whether to save logs to CSV

### Command-Line Mode

```bash
python main.py TARGET_IP [options]
```

**Options:**

| Option           | Description                                       | Default              |
|------------------|---------------------------------------------------|----------------------|
| `-p`, `--ports`  | Port range (e.g. `1-65535`, `80`, `22,80,443`)    | `1-65535`            |
| `-t`, `--threads`| Number of threads (max 10000)                     | `100 × CPU cores`    |
| `-T`, `--timeout`| Connection timeout (seconds, 0.1–10)              | `1.0`                |
| `-d`, `--delay`  | Delay between scans (seconds, 0–5)                | `0`                  |
| `--log`          | Save results to CSV log file                      | Off                  |
| `--interactive`  | Force interactive mode                            | Off                  |

**Example:**

```bash
python main.py 192.168.1.1 -p 1-1024 -t 500 -T 2 --log
```

---

## Output

- Open ports are displayed in real-time.
- On completion, summary statistics are shown.
- If logging is enabled, results are saved in the `logs/` directory:
  - `scannedports_.csv` — Open ports
  - `errorlogs_.csv` — Errors and timeouts

---

## Example

```bash
python main.py 10.0.0.5 -p 22,80,443 -t 200 --log
```

Sample output:

```
Scanning 10.0.0.5 from port 22 to 443
Using 200 threads with 1.0s timeout
Found 2 open ports: [22, 80]
Scan completed in 3.12 seconds
Results saved to ./logs/
```

---

## Notes

- Only IPv4 addresses are supported.
- High thread counts can increase speed but may be limited by your OS or network.
- Use rate limiting to avoid detection or throttling by intrusion detection systems.
- Ensure you have permission to scan the target host.

---

## Authors

- Mihai
- Jeremie
- Bilal

_BeCode Python Port Scanner Project_

---

## License

This project is provided for educational and authorized security testing purposes only. Unauthorized scanning may be illegal.

---

## Troubleshooting

- **Permission denied / logs not saved:** Ensure you have write access to the `logs/` directory.
- **Scan interrupted:** Press `Ctrl+C` to stop at any time.
- **Errors:** See the error log CSV for details if logging is enabled.

---

Happy scanning!

