#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""

  python3 map_match_ultra.py hosts.txt 185.178.49.0/24
  python3 map_match_ultra.py hosts.txt 185.178.49.140 185.178.49.141

"""

import sys, ipaddress, socket, ssl, time, os, threading, math, random
from datetime import datetime, timezone
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse


TIMEOUT = 2.7
PORTS = (443, 444, 8443, 9443, 10443)
CONCURRENCY_BASE = max(16, (os.cpu_count() or 4) * 8)
PROGRESS_EVERY = 200
PRINT_MEDIUM = True
SHOW_REASONS = True
OK_STAT = {200, 301, 302, 303, 307, 308, 401, 403}
RETRIES = 2               
BACKOFF = 0.45           
SUMMARY_TOP = 3          

def eprint(*a, **k): print(*a, file=sys.stderr, **k)
_dns_cache = {}
_cert_cache = {}
_ptr_cache = {}
_lock = threading.Lock()
def cache_get(d, k):
    with _lock: return d.get(k)
def cache_put(d, k, v):
    with _lock: d[k] = v


def dns_forward(hostname):
    key = ("fwd", hostname)
    cached = cache_get(_dns_cache, key)
    if cached is not None: return cached
    A, AAAA = [], []
    try:
        for fam in (socket.AF_INET, socket.AF_INET6):
            try:
                infos = socket.getaddrinfo(hostname, None, fam, socket.SOCK_STREAM)
            except socket.gaierror:
                infos = []
            for af, st, pr, cn, sa in infos:
                ip = sa[0]
                if af == socket.AF_INET and ip not in A: A.append(ip)
                elif af == socket.AF_INET6 and ip not in AAAA: AAAA.append(ip)
    except Exception:
        pass
    cache_put(_dns_cache, key, (A, AAAA))
    return A, AAAA

def dns_ptr(ip):
    key = ("ptr", ip)
    cached = cache_get(_ptr_cache, key)
    if cached is not None: return cached
    try:
        name, _, _ = socket.gethostbyaddr(ip)
        name = name.rstrip(".")
    except Exception:
        name = None
    cache_put(_ptr_cache, key, name)
    return name

def fcrdns(ptr_name, target_ips):
    if not ptr_name: return False
    A, _ = dns_forward(ptr_name)
    return any(ip in target_ips for ip in A)


def tls_connect(ip, port, servername=None, timeout=TIMEOUT):
    """Возвращает (cert_dict_or_None, alpn_or_empty). Кэшируется."""
    key = ("tls", ip, port, servername or "")
    cached = cache_get(_cert_cache, key)
    if cached is not None: return cached
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        try: ctx.set_alpn_protocols(["h2", "http/1.1"])
        except Exception: pass
        with socket.create_connection((ip, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=servername) as ssock:
                cert = ssock.getpeercert() or None
                alpn = ""
                try: alpn = ssock.selected_alpn_protocol() or ""
                except Exception: pass
                res = (cert, alpn)
                cache_put(_cert_cache, key, res)
                return res
    except Exception:
        res = (None, "")
        cache_put(_cert_cache, key, res)
        return res

def _parse_date(text):
    # Пример формата: 'Oct 26 12:34:56 2025 GMT'
    for fmt in ("%b %d %H:%M:%S %Y %Z", "%b %d %H:%M:%S %Y GMT"):
        try:
            return datetime.strptime(text, fmt).replace(tzinfo=timezone.utc)
        except Exception:
            pass
    return None

def cert_san_list(cert):
    out = []
    try:
        for t, v in cert.get("subjectAltName", []):
            if t.lower() == "dns": out.append(v.lower())
    except Exception:
        pass
    return out

def cert_cn(cert):
    try:
        for tup in cert.get("subject", []):
            for k, v in tup:
                if k.lower() == "commonname": return v.lower()
    except Exception:
        pass
    return ""

def cert_validity_score(cert):
    if not cert: return 0.0, ""
    nb = _parse_date(cert.get("notBefore", "") or "")
    na = _parse_date(cert.get("notAfter", "") or "")
    now = datetime.now(timezone.utc)
    if nb and na:
        if nb <= now <= na:
            return 0.4, "cert:valid"
        elif now > na:
            return -0.6, "cert:expired"
        else:
            return 0.1, "cert:notYetValid"
    return 0.0, ""

def host_matches_san(host, san):
    host = host.lower()
    for entry in san:
        if entry.startswith("*."):
            suf = entry[1:]
            if host.endswith(suf) and host.count(".") >= entry.count("."):
                return True
        elif entry == host:
            return True
    return False

def http_request(ip, port, host_header, use_tls, sni, method="HEAD", timeout=TIMEOUT):
    try:
        payload = (
            f"{method} / HTTP/1.1\r\n"
            f"Host: {host_header}\r\n"
            "User-Agent: map-ultra/1.0\r\n"
            "Accept: */*\r\n"
            "Connection: close\r\n\r\n"
        ).encode("ascii", errors="ignore")
        if use_tls:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            with socket.create_connection((ip, port), timeout=timeout) as sock:
                with ctx.wrap_socket(sock, server_hostname=sni or host_header) as ssock:
                    ssock.sendall(payload)
                    data = b""
                    ssock.settimeout(timeout)
                    while True:
                        chunk = ssock.recv(4096)
                        if not chunk: break
                        data += chunk
        else:
            with socket.create_connection((ip, port), timeout=timeout) as s:
                s.sendall(payload)
                data = b""
                s.settimeout(timeout)
                while True:
                    chunk = s.recv(4096)
                    if not chunk: break
                    data += chunk
        header = data.split(b"\r\n\r\n", 1)[0].decode("iso-8859-1", "replace")
        lines = header.split("\r\n")
        status = 0
        if lines and lines[0].startswith("HTTP/"):
            parts = lines[0].split()
            if len(parts) > 1 and parts[1].isdigit(): status = int(parts[1])
        hdrs = {}
        for line in lines[1:]:
            if ":" in line:
                k, v = line.split(":", 1)
                hdrs[k.strip().title()] = v.strip()
        return status, hdrs
    except Exception:
        return 0, {}

def extract_host_from_location(loc):
    try:
        u = urlparse(loc)
        if u.netloc: return u.netloc.split(":")[0].lower()
    except Exception:
        pass
    return ""

def score_match(host, ip, A_records, https_stat, https_hdrs, san_sni, san_nosni, cn_sni, ptr_name, alpn, cert_score, hsts):
    score = 0.0
    reasons = []

    if ip in A_records:
        score += 3.0
        reasons.append("A(host) содержит IP")

    if host_matches_san(host, san_sni):
        score += 2.0
        reasons.append("SAN(SNI) содержит host")

    if cn_sni and (cn_sni == host or (cn_sni.startswith("*.") and host.endswith(cn_sni[1:]))):
        score += 0.6
        reasons.append(f"CN(SNI) ~ {cn_sni}")

    if https_stat in OK_STAT:
        score += 1.2
        reasons.append(f"HTTPS({https_stat})")

    if alpn == "h2":
        score += 0.25
        reasons.append("ALPN=h2")

    if hsts:
        score += 0.25
        reasons.append("HSTS")

    loc = https_hdrs.get("Location", "")
    if loc:
        lh = extract_host_from_location(loc)
        base_dom = host.split(".", 1)[-1]
        if lh == host or lh.endswith("." + base_dom):
            score += 0.6
            reasons.append(f"Location→{lh}")

    if ptr_name and A_records:
        if fcrdns(ptr_name, A_records):
            score += 0.5
            reasons.append(f"PTR={ptr_name} & FCrDNS")


    if host_matches_san(host, san_nosni):
        score += 0.35
        reasons.append("SAN(no SNI) содержит host")

    if cert_score:
        score += cert_score
        if cert_score > 0: reasons.append("cert:valid")
        elif cert_score < 0: reasons.append("cert:expired")

    label = "NO MATCH"
    if score >= 4.2: label = "STRONG"
    elif score >= 1.3 and PRINT_MEDIUM: label = "MEDIUM"
    return label, round(score, 2), reasons

def load_hosts(path):
    out = []
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            s = line.strip()
            if not s or s.startswith("#"): continue
            out.append(s)
    return out

def list_ips(argv):
    if len(argv) < 3:
        eprint("Usage:\n  python3 map_match_ultra.py hosts.txt <CIDR|IP ...>")
        sys.exit(2)
    if "/" in argv[2]:
        net = ipaddress.ip_network(argv[2], strict=False)
        return [str(ip) for ip in net.hosts()]
    return argv[2:]

def print_match(ip, host, label, score, reasons, port, extra=None):
    ts = datetime.now(timezone.utc).isoformat()
    base = f"[{label}:{score}] IP={ip} HOST={host}"
    if SHOW_REASONS and reasons: base += " | " + "; ".join(reasons)
    if extra: base += " | " + extra
    base += f" | Port={port}"
    print(base + f" | {ts}", flush=True)

def one_probe(host, ip, port):

    A, _ = dns_forward(host)


    cert_sni, alpn = tls_connect(ip, port, servername=host, timeout=TIMEOUT)
    san_sni = cert_san_list(cert_sni) if cert_sni else []
    cn = cert_cn(cert_sni) if cert_sni else ""
    cert_bonus, cert_flag = cert_validity_score(cert_sni)


    cert_no, _ = tls_connect(ip, port, servername=None, timeout=TIMEOUT)
    san_no = cert_san_list(cert_no) if cert_no else []


    status, hdrs = http_request(ip, port, host, True, host, "HEAD", TIMEOUT)

    if status == 405 or status == 0:
        status2, hdrs2 = http_request(ip, port, host, True, host, "GET", min(TIMEOUT, 2.0))
        if status2: status, hdrs = status2, hdrs2

    # follow 1 hop
    if status in (301, 302, 303, 307, 308):
        loc = hdrs.get("Location")
        if loc:
            next_host = extract_host_from_location(loc)
            if next_host:
                status2, hdrs2 = http_request(ip, port, next_host, True, next_host, "HEAD", TIMEOUT)
                if status2 == 405 or status2 == 0:
                    status3, hdrs3 = http_request(ip, port, next_host, True, next_host, "GET", min(TIMEOUT, 2.0))
                    if status3: status2, hdrs2 = status3, hdrs3
                if status2:
                    status, hdrs = status2, hdrs2
                    cert_sni2, alpn2 = tls_connect(ip, port, servername=next_host, timeout=TIMEOUT)
                    if cert_sni2:
                        cert_sni, alpn = cert_sni2, (alpn2 or alpn)
                        san_sni = cert_san_list(cert_sni)
                        cn = cert_cn(cert_sni)
                        cert_bonus, cert_flag = cert_validity_score(cert_sni)

    hsts = bool(hdrs.get("Strict-Transport-Security"))
    ptr = dns_ptr(ip)

    return A, status, hdrs, san_sni, san_no, cn, ptr, alpn, cert_bonus, hsts

def check_pair(host, ip):
    best = ("NO MATCH", 0.0, [], "", None)
    for port in PORTS:
        attempt = 0
        while attempt <= RETRIES:
            A, status, hdrs, san_sni, san_no, cn, ptr, alpn, cert_bonus, hsts = one_probe(host, ip, port)
            label, score, reasons = score_match(host, ip, A, status, hdrs, san_sni, san_no, cn, ptr, alpn, cert_bonus, hsts)
            extra = ""
            if hdrs.get("Location"): extra = f"Location={hdrs['Location']}"
            if label != "NO MATCH":
                if score > best[1]:
                    best = (label, score, reasons, extra, port)
                if label == "STRONG":
                    break
            # backoff + jitter
            attempt += 1
            if attempt <= RETRIES:
                time.sleep(BACKOFF * attempt + random.uniform(0, 0.2))
        if best[0] == "STRONG":
            break
    return best

def main():
    hosts_path = sys.argv[1]
    hosts = load_hosts(hosts_path)
    ips = list_ips(sys.argv)

    pairs = [(h, ip) for ip in ips for h in hosts]
    total = len(pairs)
    eprint(f"[i] Hosts={len(hosts)} IPs={len(ips)} Pairs={total} Concurrency~{CONCURRENCY_BASE} Timeout={TIMEOUT}s Ports={PORTS}")
    if total == 0:
        eprint("[!] Нет задач. Проверь входные параметры.")
        sys.exit(2)

    start = time.time()
    done = 0
    lock = threading.Lock()
    conc = CONCURRENCY_BASE
    error_counter = 0
    last_progress = 0

    ip_hits = {}  

    def add_hit(ip, host, label, score, reasons):
        cur = ip_hits.get(ip)
        item = (score, host, label, reasons)
        if cur is None:
            ip_hits[ip] = [item]
        else:
            replaced = False
            for i, (s, h, l, r) in enumerate(cur):
                if h == host and score > s:
                    cur[i] = item
                    replaced = True
                    break
            if not replaced:
                cur.append(item)

    def progress_tick():
        elapsed = time.time() - start
        rps = done / elapsed if elapsed > 0 else 0.0
        pct = (done * 100.0) / total
        left = total - done
        eta = left / rps if rps > 0 else 0.0
        eprint(f"[i] {done}/{total} ({pct:5.1f}%) | {elapsed:7.1f}s | {rps:5.2f} rps | ETA {eta/60:5.1f} min | conc={conc}")

    def adapt_concurrency():
        nonlocal conc, error_counter
        window = max(1, PROGRESS_EVERY)
        if error_counter / window > 0.25 and conc > 16:
            conc = max(16, conc - 8)
        elif error_counter == 0 and conc < CONCURRENCY_BASE * 2:
            conc = min(CONCURRENCY_BASE * 2, conc + 4)
        error_counter = 0

    try:
        import signal
        def on_sigint(signum, frame):
            eprint("\n[!] Interrupted — printing partial summary...\n")
            print_summary(ips, ip_hits)
            sys.exit(130)
        signal.signal(signal.SIGINT, on_sigint)
    except Exception:
        pass

    def print_summary(ip_list, hits):
        print("\n# Summary (best per IP, top {})".format(SUMMARY_TOP), flush=True)
        for ip in ip_list:
            arr = hits.get(ip, [])
            if not arr: continue
            arr = sorted(arr, key=lambda x: (-x[0], x[1]))[:SUMMARY_TOP]
            for score, host, label, reasons in arr:
                rs = "; ".join(reasons) if reasons else ""
                print(f"[BEST:{label}:{score}] IP={ip} HOST={host} | {rs}", flush=True)

    idx = 0
    while idx < total:
        end = min(total, idx + conc * 5)
        batch_pairs = pairs[idx:end]
        idx = end

        with ThreadPoolExecutor(max_workers=conc) as ex:
            futs = {ex.submit(check_pair, h, ip): (h, ip) for (h, ip) in batch_pairs}
            for fut in as_completed(futs):
                h, ip = futs[fut]
                try:
                    label, score, reasons, extra, port = fut.result()
                    with lock:
                        done += 1
                        if label != "NO MATCH":
                            print_match(ip, h, label, score, reasons, port, extra=extra)
                            add_hit(ip, h, label, score, reasons)
                        if (done % PROGRESS_EVERY == 0) or (done == total):
                            progress_tick()
                            adapt_concurrency()
                except Exception:
                    with lock:
                        done += 1
                        error_counter += 1
                        if (done % PROGRESS_EVERY == 0) or (done == total):
                            progress_tick()
                            adapt_concurrency()

    print_summary(ips, ip_hits)
    elapsed = time.time() - start
    eprint(f"[+] Готово: {done} пар за {elapsed:.1f}s")

if __name__ == "__main__":
    main()
