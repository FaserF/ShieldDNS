import json
import os
import ipaddress
from typing import List, Union

DEFAULT_CONFIG_PATH = os.path.join(os.path.dirname(__file__), "config", "whitelist.json")

RFC1918_NETWORKS = (
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
)

def is_rfc1918(ip_or_network: Union[str, ipaddress.IPv4Address, ipaddress.IPv4Network, ipaddress.IPv6Address, ipaddress.IPv6Network]) -> bool:
    try:
        net = ipaddress.ip_network(ip_or_network, strict=False)
        return any(net.subnet_of(rfc) for rfc in RFC1918_NETWORKS)
    except (ValueError, TypeError):
        return False

def load_whitelist(config_path: str = DEFAULT_CONFIG_PATH) -> List[str]:
    if not os.path.exists(config_path):
        return []
    with open(config_path, "r", encoding="utf-8") as f:
        try:
            data = json.load(f)
            if isinstance(data, list):
                return data
            if isinstance(data, dict):
                return data.get("whitelist", [])
            return []
        except json.JSONDecodeError:
            return []

def save_whitelist(entries: List[str], config_path: str = DEFAULT_CONFIG_PATH) -> None:
    os.makedirs(os.path.dirname(os.path.abspath(config_path)), exist_ok=True)
    with open(config_path, "w", encoding="utf-8") as f:
        json.dump({"whitelist": entries}, f, indent=2)

def shielddns_manage_autoblock_whitelist(operation: str, target: str, config_path: str = DEFAULT_CONFIG_PATH) -> bool:
    op = operation.strip().lower()
    if op not in ("add", "remove"):
        raise ValueError(f"Invalid operation: {operation}. Expected 'add' or 'remove'.")
    
    try:
        net = ipaddress.ip_network(target, strict=False)
        normalized_target = str(net.network_address) if net.num_addresses == 1 else str(net)
    except ValueError:
        raise ValueError(f"Invalid IP address or CIDR range: {target}")

    entries = load_whitelist(config_path)

    if op == "add":
        if normalized_target not in entries:
            entries.append(normalized_target)
            save_whitelist(entries, config_path)
        return True
    elif op == "remove":
        if normalized_target in entries:
            entries.remove(normalized_target)
            save_whitelist(entries, config_path)
            return True
        return False
    return False
