# CFINDER — identify real origins behind Cloudflare (Host-header probe)

Sends HTTP/HTTPS requests to each `IP:port` with different `Host` headers, then **groups results by (status, size)** to spot shared backends and misconfigurations behind Cloudflare. Redirects are not followed; TLS verification is disabled for probing.

## Usage
```bash
python3 cfinder.py -i ip_ports.txt -u hosts.txt
# -i  file with IP:port per line (e.g., 203.0.113.10:80)
# -u  file with hostnames per line (e.g., www.example.com)
