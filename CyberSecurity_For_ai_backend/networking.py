import time
import ipaddress
import struct
import re
import json
import base64

# ─── Rate Limiting Configuration ───
RATE_LIMIT_MAX_REQUESTS = 5
RATE_LIMIT_WINDOW_SECONDS = 10
_request_history = {}  # IP -> list of timestamps

# ─── TOR / Known Proxy IPs ───
BLOCKED_IPS = {
    "185.220.101.1",
    "185.220.101.2",
    "104.244.72.115",  # Known TOR exit
    "192.168.1.100",   # Known proxy (simulated)
    "tor",
}

# ─── Geo-IP CIDR Blocks (High-risk / sanctioned regions) ─────────────
# These are representative ranges for simulation/demo.
# In production: use MaxMind GeoIP2 or ip-api.com for accurate data.
GEO_BLOCKED_RANGES = [
    # China (CN)
    ("116.31.116.0/24",   "China (CN)"),
    ("1.180.0.0/13",      "China (CN)"),
    ("14.0.0.0/11",       "China (CN)"),
    ("27.0.0.0/8",        "China (CN)"),
    # Russia (RU)
    ("95.173.136.0/24",   "Russia (RU)"),
    ("5.45.192.0/18",     "Russia (RU)"),
    ("37.9.64.0/18",      "Russia (RU)"),
    ("77.108.64.0/18",    "Russia (RU)"),
    # Iran (IR)
    ("5.160.0.0/16",      "Iran (IR)"),
    ("5.200.0.0/19",      "Iran (IR)"),
    ("31.2.128.0/17",     "Iran (IR)"),
    # North Korea (KP)
    ("175.45.176.0/22",   "North Korea (KP)"),
    # Syria (SY)
    ("84.234.0.0/16",     "Syria (SY)"),
]

# Pre-compile CIDR networks for fast lookup
_GEO_NETWORKS = []
for cidr, country in GEO_BLOCKED_RANGES:
    try:
        _GEO_NETWORKS.append((ipaddress.ip_network(cidr, strict=False), country))
    except ValueError:
        pass

# ─── Known Commercial VPN Exit Ranges ────────────────────────────────
# In production: fetch from vpnapi.io or similar service
VPN_RANGES = [
    "10.0.0.0/8",       # Private / corporate VPN (RFC1918)
    "172.16.0.0/12",    # Private range
    "100.64.0.0/10",    # Carrier-grade NAT (often VPN)
]
_VPN_NETWORKS = []
for cidr in VPN_RANGES:
    try:
        _VPN_NETWORKS.append(ipaddress.ip_network(cidr, strict=False))
    except ValueError:
        pass

# Explicit known VPN IPs (for simulation)
KNOWN_VPN_IPS = {"10.0.0.5"}

# ─── JWT Forgery Detection ────────────────────────────────────────────
# Dangerous claims that attackers embed in forged tokens
DANGEROUS_JWT_CLAIMS = {"admin", "superuser", "root", "god_mode", "bypass_security"}
DANGEROUS_ROLES = {"admin", "superuser", "root", "system", "internal", "developer"}

def _decode_jwt_part(part: str) -> dict:
    """Safely base64-decode a JWT header or payload segment."""
    # JWT uses base64url encoding (no padding)
    padding = 4 - len(part) % 4
    if padding != 4:
        part += "=" * padding
    try:
        decoded = base64.urlsafe_b64decode(part)
        return json.loads(decoded)
    except Exception:
        return {}

def validate_session_token(auth_header: str) -> dict:
    """
    Validates an Authorization Bearer JWT token for forgery.
    
    Checks:
    1. Token structure (3-part JWT)
    2. Algorithm — rejects 'none' (alg:none attack)
    3. Dangerous claims (admin, superuser, role escalation)
    4. Expiry check
    
    Returns:
        {"safe": bool, "reason": str, "risk": float}
    """
    if not auth_header or not auth_header.lower().startswith("bearer "):
        return {"safe": True, "reason": "", "risk": 0.0}
    
    token = auth_header[7:].strip()
    parts = token.split(".")
    
    if len(parts) != 3:
        return {"safe": False, "reason": "Malformed JWT: not a valid 3-part token", "risk": 0.9}
    
    header = _decode_jwt_part(parts[0])
    payload = _decode_jwt_part(parts[1])
    
    # 1. Algorithm confusion attack (alg:none)
    alg = str(header.get("alg", "")).lower()
    if alg == "none" or alg == "":
        return {
            "safe": False,
            "reason": "JWT Algorithm Confusion Attack: 'alg:none' bypass detected",
            "risk": 1.0
        }
    
    # 2. Weak algorithm warning (HS256 is acceptable, RS256 better)
    if alg not in ("hs256", "hs384", "hs512", "rs256", "rs384", "rs512", "es256"):
        return {
            "safe": False,
            "reason": f"JWT uses non-standard/dangerous algorithm: {alg.upper()}",
            "risk": 0.85
        }
    
    # 3. Dangerous claim escalation
    for key, value in payload.items():
        key_lower = key.lower()
        val_lower = str(value).lower()
        if key_lower in DANGEROUS_JWT_CLAIMS or val_lower in DANGEROUS_JWT_CLAIMS:
            return {
                "safe": False,
                "reason": f"Session Token Hijacking: forged claim '{key}={value}' — privilege escalation attempt",
                "risk": 0.98
            }
        if key_lower == "role" and val_lower in DANGEROUS_ROLES:
            return {
                "safe": False,
                "reason": f"Session Token Hijacking: forged role claim '{value}' — unauthorized privilege",
                "risk": 0.97
            }
    
    # 4. Implausibly long expiry (> 30 days = suspicious)
    exp = payload.get("exp", 0)
    iat = payload.get("iat", time.time())
    if exp and iat and (exp - iat) > 30 * 86400:
        return {
            "safe": False,
            "reason": "JWT Session Anomaly: token lifetime exceeds 30 days — likely crafted token",
            "risk": 0.75
        }
    
    return {"safe": True, "reason": "", "risk": 0.0}


def check_geo_ip(ip: str) -> dict:
    """
    Check if the given IP belongs to a geo-blocked region.
    Returns {"blocked": bool, "country": str or None}
    """
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return {"blocked": False, "country": None}
    
    for network, country in _GEO_NETWORKS:
        if addr in network:
            return {"blocked": True, "country": country}
    
    return {"blocked": False, "country": None}


def check_vpn_ip(ip: str) -> bool:
    """Check if the given IP appears to be a VPN exit node."""
    if ip in KNOWN_VPN_IPS:
        return True
    try:
        addr = ipaddress.ip_address(ip)
        for network in _VPN_NETWORKS:
            if addr in network:
                return True
    except ValueError:
        pass
    return False


def check_network_security(ip: str, auth_header: str = "") -> tuple:
    """
    Comprehensive network security check.
    
    Checks (in order):
    1. Known TOR / Proxy IPs  → block
    2. Geo-IP country block   → block
    3. VPN detection          → restrict (allow with flag)
    4. JWT token forgery      → block
    5. Rate limiting          → block (bot flood)
    
    Returns:
        (is_allowed: bool, decision: str, attack_type: str or None)
    """
    # 1. Known TOR / Proxy IPs
    if ip in BLOCKED_IPS or "tor" in ip.lower():
        return False, "block", "TOR Anonymity Abuse"
    
    # 2. Geo-IP block
    geo = check_geo_ip(ip)
    if geo["blocked"]:
        return False, "block", f"Geo-IP Country Block ({geo['country']})"
    
    # 3. VPN detection (restrict, not block outright — log and flag)
    if check_vpn_ip(ip):
        return False, "restrict", "VPN Policy Evasion"
    
    # 4. JWT token validation
    if auth_header:
        token_result = validate_session_token(auth_header)
        if not token_result["safe"]:
            return False, "block", token_result["reason"]
    
    # 5. Rate limiting (bot flood detection)
    now = time.time()
    history = _request_history.get(ip, [])
    history = [t for t in history if now - t < RATE_LIMIT_WINDOW_SECONDS]
    history.append(now)
    _request_history[ip] = history
    
    if len(history) > RATE_LIMIT_MAX_REQUESTS:
        return False, "block", "Prompt Injection (Bot Attack)"
    
    return True, "allow", None
