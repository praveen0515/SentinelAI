"""
SentinelAI Log Processor Module
Parses multiple HTTP log formats (Apache, Nginx, JSON) and extracts a 28+ dimension
cybersecurity feature vector for machine learning threat detection.
"""

import re
import math
import json
import hashlib
from collections import deque
from datetime import datetime, timezone
from typing import Dict, Any, Tuple, Optional, List
from urllib.parse import urlparse, parse_qs

# Pre-compiled Regex patterns for Common/Combined Apache/Nginx logs
# Example: 127.0.0.1 - frank [10/Oct/2000:13:55:36 -0700] "GET /apache_pb.gif HTTP/1.0" 200 2326 "http://..." "Mozilla/..."
APACHE_COMBINED_PATTERN = re.compile(
    r'^(?P<client_ip>\S+)\s+\S+\s+(?P<user>\S+)\s+\[(?P<timestamp>[^\]]+)\]\s+'
    r'"(?P<method>[A-Z]+)\s+(?P<path>[^\s"]+)(?:\s+(?P<protocol>[^"]+))?"\s+'
    r'(?P<status_code>\d{3})\s+(?P<response_bytes>\S+)'
    r'(?:\s+"(?P<referer>[^"]*)"\s+"(?P<user_agent>[^"]*)")?'
)

APACHE_COMMON_PATTERN = re.compile(
    r'^(?P<client_ip>\S+)\s+\S+\s+(?P<user>\S+)\s+\[(?P<timestamp>[^\]]+)\]\s+'
    r'"(?P<method>[A-Z]+)\s+(?P<path>[^\s"]+)(?:\s+(?P<protocol>[^"]+))?"\s+'
    r'(?P<status_code>\d{3})\s+(?P<response_bytes>\S+)'
)

# Attack signature heuristics
SQLI_PATTERNS = re.compile(
    r"(\b(SELECT|UNION|INSERT|DELETE|UPDATE|DROP|ALTER|CREATE|TRUNCATE)\b|"
    r"(\%27|\')|(\%22|\")|(--|\#|\/\*)|(\bOR\b|\bAND\b)\s+[\d\w\'\"]+\s*=\s*[\d\w\'\"]|"
    r"information_schema|waitfor\s+delay|benchmark\s*\(|sleep\s*\()",
    re.IGNORECASE
)

XSS_PATTERNS = re.compile(
    r"(<script\b|javascript:|onerror\s*=|onload\s*=|alert\s*\(|eval\s*\(|"
    r"document\.cookie|<img\b[^>]*src=|<svg\b|<iframe\b|%3cscript%3e)",
    re.IGNORECASE
)

TRAVERSAL_PATTERNS = re.compile(
    r"(\.\./|\.\.\\|%2e%2e%2f|%2e%2e/|\.\.%2f|/etc/passwd|windows/win\.ini|/boot\.ini|cmd\.exe)",
    re.IGNORECASE
)

CMD_INJECTION_PATTERNS = re.compile(
    r"(;|\||`|\$\(|\b(wget|curl|nc|bash|sh|whoami|cat|powershell|base64_decode)\b)",
    re.IGNORECASE
)

SCANNER_UA_PATTERNS = re.compile(
    r"(sqlmap|nikto|nmap|gobuster|dirbuster|wpscan|masscan|zgrab|acunetix|nessus|"
    r"python-requests|aiohttp|curl/|libwww-perl)",
    re.IGNORECASE
)

# Simulated Geo Location coordinates for realistic map visual analytics
GEO_SIMULATION_DB = {
    "US": {"country": "United States", "city": "Ashburn", "lat": 39.0438, "lon": -77.4874},
    "CN": {"country": "China", "city": "Beijing", "lat": 39.9042, "lon": 116.4074},
    "RU": {"country": "Russia", "city": "Moscow", "lat": 55.7558, "lon": 37.6173},
    "DE": {"country": "Germany", "city": "Frankfurt", "lat": 50.1109, "lon": 8.6821},
    "NL": {"country": "Netherlands", "city": "Amsterdam", "lat": 52.3676, "lon": 4.9041},
    "BR": {"country": "Brazil", "city": "Sao Paulo", "lat": -23.5505, "lon": -46.6333},
    "IN": {"country": "India", "city": "Bengaluru", "lat": 12.9716, "lon": 77.5946},
    "SG": {"country": "Singapore", "city": "Singapore", "lat": 1.3521, "lon": 103.8198},
    "GB": {"country": "United Kingdom", "city": "London", "lat": 51.5074, "lon": -0.1278},
    "UA": {"country": "Ukraine", "city": "Kyiv", "lat": 50.4501, "lon": 30.5234},
    "KP": {"country": "North Korea", "city": "Pyongyang", "lat": 39.0392, "lon": 125.7625},
    "IR": {"country": "Iran", "city": "Tehran", "lat": 35.6892, "lon": 51.3890},
}


def calculate_entropy(text: str) -> float:
    """Calculate Shannon Entropy of a given string."""
    if not text:
        return 0.0
    prob_dist = [float(text.count(c)) / len(text) for c in set(text)]
    return -sum(p * math.log2(p) for p in prob_dist if p > 0)


def resolve_geo_ip(ip: str) -> Dict[str, Any]:
    """
    Deterministic Geo-IP resolver for realistic demonstration.
    Hashes the IP to map consistently to global coordinates.
    """
    if ip.startswith("127.") or ip == "localhost" or ip.startswith("10.") or ip.startswith("192.168."):
        return {"country": "Local Network", "city": "Internal", "latitude": 37.7749, "longitude": -122.4194}

    # Hash IP to choose country
    hash_val = int(hashlib.md5(ip.encode()).hexdigest(), 16)
    country_codes = list(GEO_SIMULATION_DB.keys())
    code = country_codes[hash_val % len(country_codes)]
    geo = GEO_SIMULATION_DB[code]

    # Add small deterministic jitter
    jitter_lat = ((hash_val % 100) - 50) / 100.0
    jitter_lon = (((hash_val // 100) % 100) - 50) / 100.0

    return {
        "country": geo["country"],
        "city": geo["city"],
        "latitude": round(geo["lat"] + jitter_lat, 4),
        "longitude": round(geo["lon"] + jitter_lon, 4)
    }


class LogStreamState:
    """Tracks stateful rolling IP statistics across streaming events."""

    def __init__(self, window_seconds: int = 300):
        self.window_seconds = window_seconds
        # Mapping IP -> deque of (timestamp, is_error, endpoint)
        self.ip_history: Dict[str, deque] = {}

    def record_and_get_stats(self, ip: str, ts: datetime, status_code: int, endpoint: str) -> Tuple[int, int, int, int]:
        """
        Record current request and compute:
        (freq_1m, freq_5m, errors_5m, unique_endpoints_5m)
        """
        now_ts = ts.timestamp()
        if ip not in self.ip_history:
            self.ip_history[ip] = deque()

        history = self.ip_history[ip]
        history.append((now_ts, status_code >= 400, endpoint))

        # Evict entries older than window_seconds
        cutoff = now_ts - self.window_seconds
        while history and history[0][0] < cutoff:
            history.popleft()

        cutoff_1m = now_ts - 60
        freq_1m = sum(1 for entry in history if entry[0] >= cutoff_1m)
        freq_5m = len(history)
        errors_5m = sum(1 for entry in history if entry[1])
        unique_endpoints_5m = len(set(entry[2] for entry in history))

        return freq_1m, freq_5m, errors_5m, unique_endpoints_5m


class LogProcessor:
    """Enterprise Log Parsing and 28+ Feature Extraction Engine."""

    # Ordered list of feature names used by ML model
    FEATURE_NAMES: List[str] = [
        "req_length",
        "query_param_count",
        "query_length",
        "payload_entropy",
        "special_char_count",
        "special_char_ratio",
        "digit_count",
        "digit_ratio",
        "uppercase_ratio",
        "status_code",
        "is_error_status",
        "is_server_error",
        "response_bytes",
        "hour_of_day",
        "is_weekend",
        "is_off_hours",
        "ip_req_freq_1m",
        "ip_req_freq_5m",
        "ip_error_freq_5m",
        "unique_endpoints_count",
        "user_agent_length",
        "user_agent_entropy",
        "is_known_scanner_ua",
        "is_empty_user_agent",
        "method_encoded",
        "is_post_or_put",
        "sqli_signature_match",
        "xss_signature_match",
        "traversal_signature_match",
        "cmd_signature_match",
    ]

    METHOD_MAP = {
        "GET": 1,
        "POST": 2,
        "PUT": 3,
        "DELETE": 4,
        "HEAD": 5,
        "OPTIONS": 6,
        "PATCH": 7
    }

    def __init__(self):
        self.stream_state = LogStreamState()

    def parse_raw_log(self, raw_input: Any) -> Dict[str, Any]:
        """
        Parses Apache Combined, Apache Common, Nginx, or JSON logs into normalized dict.
        """
        if isinstance(raw_input, dict):
            parsed = dict(raw_input)
            if "timestamp" not in parsed:
                parsed["timestamp"] = datetime.now(timezone.utc)
            elif isinstance(parsed["timestamp"], str):
                try:
                    parsed["timestamp"] = datetime.fromisoformat(parsed["timestamp"].replace("Z", "+00:00"))
                except Exception:
                    parsed["timestamp"] = datetime.now(timezone.utc)
            return self._normalize_dict(parsed)

        if not isinstance(raw_input, str):
            raise ValueError(f"Unsupported log type: {type(raw_input)}")

        raw_str = raw_input.strip()

        # Check if JSON
        if raw_str.startswith("{") and raw_str.endswith("}"):
            try:
                data = json.loads(raw_str)
                return self.parse_raw_log(data)
            except json.JSONDecodeError:
                pass

        # Check Apache Combined
        match = APACHE_COMBINED_PATTERN.match(raw_str)
        if not match:
            # Check Apache Common
            match = APACHE_COMMON_PATTERN.match(raw_str)

        if match:
            gd = match.groupdict()
            ts_str = gd.get("timestamp")
            dt = datetime.now(timezone.utc)
            if ts_str:
                try:
                    # e.g. 10/Oct/2026:13:55:36 +0000
                    dt = datetime.strptime(ts_str.split()[0], "%d/%b/%Y:%H:%M:%S").replace(tzinfo=timezone.utc)
                except Exception:
                    pass

            resp_bytes = gd.get("response_bytes")
            bytes_val = int(resp_bytes) if resp_bytes and resp_bytes != "-" else 0

            return self._normalize_dict({
                "client_ip": gd.get("client_ip", "127.0.0.1"),
                "timestamp": dt,
                "method": gd.get("method", "GET"),
                "path": gd.get("path", "/"),
                "status_code": int(gd.get("status_code", 200)),
                "response_bytes": bytes_val,
                "referer": gd.get("referer", "-"),
                "user_agent": gd.get("user_agent", "-"),
            })

        # Fallback simplistic split
        parts = raw_str.split()
        return self._normalize_dict({
            "client_ip": parts[0] if parts else "127.0.0.1",
            "timestamp": datetime.now(timezone.utc),
            "method": parts[1] if len(parts) > 1 else "GET",
            "path": parts[2] if len(parts) > 2 else "/",
            "status_code": int(parts[3]) if len(parts) > 3 and parts[3].isdigit() else 200,
            "response_bytes": 500,
            "user_agent": "Mozilla/5.0 (Standard Browser)"
        })

    def _normalize_dict(self, d: Dict[str, Any]) -> Dict[str, Any]:
        """Ensure standard keys and types."""
        d.setdefault("client_ip", "127.0.0.1")
        d.setdefault("method", "GET")
        d.setdefault("path", "/")
        d.setdefault("status_code", 200)
        d.setdefault("response_bytes", 512)
        d.setdefault("user_agent", "-")
        d.setdefault("referer", "-")
        d.setdefault("payload", "")

        # Attach Geo details
        geo = resolve_geo_ip(d["client_ip"])
        d.setdefault("country", geo["country"])
        d.setdefault("city", geo["city"])
        d.setdefault("latitude", geo["latitude"])
        d.setdefault("longitude", geo["longitude"])

        return d

    def extract_features(self, log_dict: Dict[str, Any]) -> Dict[str, float]:
        """
        Extracts 30 cyber features from a normalized log dict.
        Returns a dictionary mapping feature name to numeric value.
        """
        path = str(log_dict.get("path", "/"))
        method = str(log_dict.get("method", "GET")).upper()
        status_code = int(log_dict.get("status_code", 200))
        resp_bytes = float(log_dict.get("response_bytes", 0))
        ua = str(log_dict.get("user_agent", ""))
        payload = str(log_dict.get("payload", ""))
        full_target = f"{path} {payload}"

        parsed_url = urlparse(path)
        query_params = parse_qs(parsed_url.query)
        query_length = len(parsed_url.query)
        query_param_count = len(query_params)

        # 1. Structural features
        req_length = float(len(path))
        payload_entropy = calculate_entropy(full_target)

        special_chars = set("<>'\"-;/*%$|\\^{}[]()=")
        spec_count = sum(1 for c in full_target if c in special_chars)
        spec_ratio = spec_count / (req_length + 1.0)

        digit_count = sum(1 for c in full_target if c.isdigit())
        digit_ratio = digit_count / (req_length + 1.0)

        alpha_count = sum(1 for c in full_target if c.isalpha())
        upper_count = sum(1 for c in full_target if c.isupper())
        upper_ratio = (upper_count / alpha_count) if alpha_count > 0 else 0.0

        # 2. HTTP Status & Timing
        is_error = 1.0 if status_code >= 400 else 0.0
        is_server_error = 1.0 if status_code >= 500 else 0.0

        ts = log_dict.get("timestamp")
        if not isinstance(ts, datetime):
            ts = datetime.now(timezone.utc)
        hour_of_day = float(ts.hour)
        is_weekend = 1.0 if ts.weekday() >= 5 else 0.0
        is_off_hours = 1.0 if (ts.hour < 8 or ts.hour >= 19) else 0.0

        # 3. Rolling IP metrics
        ip = log_dict.get("client_ip", "127.0.0.1")
        freq_1m, freq_5m, err_5m, uniq_endpts = self.stream_state.record_and_get_stats(
            ip=ip, ts=ts, status_code=status_code, endpoint=parsed_url.path
        )

        # 4. User-Agent characteristics
        ua_len = float(len(ua))
        ua_entropy = calculate_entropy(ua)
        is_scanner_ua = 1.0 if bool(SCANNER_UA_PATTERNS.search(ua)) else 0.0
        is_empty_ua = 1.0 if (not ua or ua == "-" or ua == '""') else 0.0

        # 5. Method encoding
        method_code = float(self.METHOD_MAP.get(method, 8))
        is_post_or_put = 1.0 if method in ["POST", "PUT", "PATCH"] else 0.0

        # 6. Attack signature pattern matching
        sqli_match = 1.0 if bool(SQLI_PATTERNS.search(full_target)) else 0.0
        xss_match = 1.0 if bool(XSS_PATTERNS.search(full_target)) else 0.0
        traversal_match = 1.0 if bool(TRAVERSAL_PATTERNS.search(full_target)) else 0.0
        cmd_match = 1.0 if bool(CMD_INJECTION_PATTERNS.search(full_target)) else 0.0

        return {
            "req_length": req_length,
            "query_param_count": float(query_param_count),
            "query_length": float(query_length),
            "payload_entropy": float(payload_entropy),
            "special_char_count": float(spec_count),
            "special_char_ratio": float(spec_ratio),
            "digit_count": float(digit_count),
            "digit_ratio": float(digit_ratio),
            "uppercase_ratio": float(upper_ratio),
            "status_code": float(status_code),
            "is_error_status": is_error,
            "is_server_error": is_server_error,
            "response_bytes": resp_bytes,
            "hour_of_day": hour_of_day,
            "is_weekend": is_weekend,
            "is_off_hours": is_off_hours,
            "ip_req_freq_1m": float(freq_1m),
            "ip_req_freq_5m": float(freq_5m),
            "ip_error_freq_5m": float(err_5m),
            "unique_endpoints_count": float(uniq_endpts),
            "user_agent_length": ua_len,
            "user_agent_entropy": float(ua_entropy),
            "is_known_scanner_ua": is_scanner_ua,
            "is_empty_user_agent": is_empty_ua,
            "method_encoded": method_code,
            "is_post_or_put": is_post_or_put,
            "sqli_signature_match": sqli_match,
            "xss_signature_match": xss_match,
            "traversal_signature_match": traversal_match,
            "cmd_signature_match": cmd_match,
        }

    def classify_threat_category(self, features: Dict[str, float], path: str, ua: str) -> Optional[str]:
        """
        Rule-assisted classifier to categorize anomalies detected by Isolation Forest.
        """
        if features.get("sqli_signature_match", 0) > 0:
            return "SQL Injection"
        if features.get("xss_signature_match", 0) > 0:
            return "Cross-Site Scripting (XSS)"
        if features.get("traversal_signature_match", 0) > 0:
            return "Path Traversal"
        if features.get("cmd_signature_match", 0) > 0:
            return "Command Injection / Webshell"
        if features.get("is_known_scanner_ua", 0) > 0:
            return "Automated Security Scanner"
        if features.get("ip_req_freq_1m", 0) > 40:
            return "DDoS / High-Velocity Spike"
        if features.get("ip_error_freq_5m", 0) > 15:
            return "Credential Stuffing / Brute Force"
        if features.get("payload_entropy", 0) > 4.8:
            return "High Entropy Obfuscated Payload"
        if features.get("is_server_error", 0) > 0:
            return "Exploitation Attempt (5xx Trigger)"
        return "Behavioral Anomaly"


log_processor = LogProcessor()
