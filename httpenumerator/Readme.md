# http-scout — quick HTTP/HTTPS discovery on arbitrary ports

A tiny Bash + `curl` script that probes host lists on chosen ports (HTTP & HTTPS) and writes a clean CSV with status, header size, redirect, and a truncated body.

## Usage
```bash
./http-scout.sh -f hosts.txt -o output.csv -p 80,443,8080
# -f  host list file (one per line)
# -o  output CSV path
# -p  comma-separated ports
