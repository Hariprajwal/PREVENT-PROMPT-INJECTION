import time

# ─── Rate Limiting Configuration ───
RATE_LIMIT_MAX_REQUESTS = 5
RATE_LIMIT_WINDOW_SECONDS = 10
_request_history = {}  # IP -> list of timestamps

# ─── Simulated TOR IPs ───
# In a real app, this would be fetched from a dynamic list (like Dan.me.uk)
SIMULATED_TOR_IPS = {
    "185.220.101.1", 
    "185.220.101.2", 
    "192.168.1.100",
    "104.244.72.115", # Known proxy
    "tor"
}

def check_network_security(ip: str):
    """
    Checks the IP against TOR lists and Rate Limits.
    Returns:
        (is_allowed: bool, decision: str, attack_type: str)
    """
    # 1. Check TOR / Anonymity Abuse
    if ip in SIMULATED_TOR_IPS or "tor" in ip.lower():
        return False, "block", "TOR Anonymity Abuse"
    
    # 2. Check Rate Limiting (Bot Attack)
    now = time.time()
    history = _request_history.get(ip, [])
    # Remove timestamps older than the window
    history = [t for t in history if now - t < RATE_LIMIT_WINDOW_SECONDS]
    history.append(now)
    _request_history[ip] = history
    
    if len(history) > RATE_LIMIT_MAX_REQUESTS:
        return False, "block", "Prompt Injection (Bot Attack)"
        
    return True, "allow", None
