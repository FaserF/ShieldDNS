import os
import json
import ipaddress
import re
import tempfile
from datetime import datetime, timezone, timedelta
from collections import defaultdict
from typing import List, Dict, Optional, Tuple, Any

from whitelist_manager import (
    is_rfc1918,
    load_whitelist,
    DEFAULT_CONFIG_PATH
)

DEFAULT_RATE_LIMIT_LOG_PATH = os.path.join(os.path.dirname(__file__), "logs", "rate_limit.log")
DEFAULT_BLOCKLIST_PATH = os.path.join(os.path.dirname(__file__), "config", "blocklist.json")

IPV4_PATTERN = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")

def log_rate_limit_event(
    ip_address: str,
    action: str,
    reason: str,
    log_path: str = DEFAULT_RATE_LIMIT_LOG_PATH
) -> None:
    os.makedirs(os.path.dirname(os.path.abspath(log_path)), exist_ok=True)
    event = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "ip_address": ip_address,
        "action": action,
        "reason": reason
    }
    with open(log_path, "a", encoding="utf-8") as f:
        f.write(json.dumps(event) + "\n")

def is_whitelisted(ip_str: str, whitelist_entries: List[str]) -> bool:
    try:
        ip_obj = ipaddress.ip_address(ip_str)
    except ValueError:
        return False

    for entry in whitelist_entries:
        try:
            if "/" in entry:
                net = ipaddress.ip_network(entry, strict=False)
                if ip_obj in net:
                    return True
            else:
                if ip_obj == ipaddress.ip_address(entry):
                    return True
        except ValueError:
            continue
    return False

def load_blocklist(blocklist_path: str = DEFAULT_BLOCKLIST_PATH) -> List[str]:
    if not os.path.exists(blocklist_path):
        return []
    try:
        with open(blocklist_path, "r", encoding="utf-8") as f:
            data = json.load(f)
            if isinstance(data, list):
                return [str(x) for x in data if isinstance(x, str)]
            if isinstance(data, dict):
                raw = data.get("blocked_ips", [])
                if isinstance(raw, list):
                    return [str(x) for x in raw if isinstance(x, str)]
            return []
    except (json.JSONDecodeError, OSError):
        return []

def save_blocklist(blocked_ips: List[str], blocklist_path: str = DEFAULT_BLOCKLIST_PATH) -> None:
    target_dir = os.path.dirname(os.path.abspath(blocklist_path))
    os.makedirs(target_dir, exist_ok=True)
    temp_fd, temp_path = tempfile.mkstemp(dir=target_dir, prefix="blocklist_", suffix=".tmp")
    try:
        with os.fdopen(temp_fd, "w", encoding="utf-8") as f:
            json.dump({"blocked_ips": blocked_ips}, f, indent=2)
            f.flush()
            os.fsync(f.fileno())
        os.replace(temp_path, blocklist_path)
    except Exception:
        if os.path.exists(temp_path):
            os.remove(temp_path)
        raise

def block_ip(
    ip_str: str,
    reason: str,
    blocklist_path: str = DEFAULT_BLOCKLIST_PATH,
    rate_log_path: str = DEFAULT_RATE_LIMIT_LOG_PATH
) -> bool:
    blocked = load_blocklist(blocklist_path)
    if ip_str not in blocked:
        blocked.append(ip_str)
        save_blocklist(blocked, blocklist_path)
    log_rate_limit_event(ip_str, "blocked", reason, rate_log_path)
    return True

def parse_log_line(line: str) -> Optional[Tuple[datetime, str]]:
    line = line.strip()
    if not line:
        return None

    if line.startswith("{") and line.endswith("}"):
        try:
            record = json.loads(line)
            if isinstance(record, dict):
                ts_val = record.get("timestamp") or record.get("time")
                ip_val = record.get("client_ip") or record.get("ip") or record.get("ip_address")
                if isinstance(ts_val, str) and isinstance(ip_val, str):
                    try:
                        ipaddress.ip_address(ip_val)
                    except ValueError:
                        return None
                    try:
                        dt = datetime.fromisoformat(ts_val.replace("Z", "+00:00"))
                        return dt, ip_val
                    except ValueError:
                        return None
                return None
        except json.JSONDecodeError:
            pass

    match = IPV4_PATTERN.search(line)
    if not match:
        return None

    candidate_ip = match.group(0)
    try:
        ipaddress.ip_address(candidate_ip)
    except ValueError:
        return None

    return datetime.now(timezone.utc), candidate_ip

class RateLimiterService:
    def __init__(
        self,
        hourly_threshold: int = 100,
        whitelist_config_path: str = DEFAULT_CONFIG_PATH,
        blocklist_path: str = DEFAULT_BLOCKLIST_PATH,
        rate_log_path: str = DEFAULT_RATE_LIMIT_LOG_PATH
    ):
        self.hourly_threshold = hourly_threshold
        self.whitelist_config_path = whitelist_config_path
        self.blocklist_path = blocklist_path
        self.rate_log_path = rate_log_path

    def process_logs(
        self,
        log_lines: List[str],
        window_hours: float = 1.0,
        now: Optional[datetime] = None
    ) -> Dict[str, Any]:
        if now is None:
            now = datetime.now(timezone.utc)
        elif now.tzinfo is None:
            now = now.replace(tzinfo=timezone.utc)
        
        window_start = now - timedelta(hours=window_hours)
        ip_counts: Dict[str, int] = defaultdict(int)

        for line in log_lines:
            parsed = parse_log_line(line)
            if not parsed:
                continue
            ts, ip = parsed
            if ts.tzinfo is None:
                ts = ts.replace(tzinfo=timezone.utc)
            if ts >= window_start:
                ip_counts[ip] += 1

        whitelist = load_whitelist(self.whitelist_config_path)
        blocked_list = load_blocklist(self.blocklist_path)

        newly_blocked = []
        ignored_rfc1918 = []
        ignored_whitelisted = []

        for ip, count in ip_counts.items():
            if count > self.hourly_threshold:
                if is_rfc1918(ip):
                    ignored_rfc1918.append(ip)
                    continue
                if is_whitelisted(ip, whitelist):
                    ignored_whitelisted.append(ip)
                    continue

                if ip not in blocked_list:
                    reason = f"Exceeded hourly threshold ({count} requests > {self.hourly_threshold})"
                    block_ip(ip, reason, self.blocklist_path, self.rate_log_path)
                    newly_blocked.append(ip)

        return {
            "processed_counts": dict(ip_counts),
            "newly_blocked": newly_blocked,
            "ignored_rfc1918": ignored_rfc1918,
            "ignored_whitelisted": ignored_whitelisted
        }

    def process_log_file(
        self,
        file_path: str,
        window_hours: float = 1.0,
        now: Optional[datetime] = None
    ) -> Dict[str, Any]:
        if not os.path.exists(file_path):
            return {
                "processed_counts": {},
                "newly_blocked": [],
                "ignored_rfc1918": [],
                "ignored_whitelisted": []
            }
        with open(file_path, "r", encoding="utf-8") as f:
            lines = f.readlines()
        return self.process_logs(lines, window_hours, now)
