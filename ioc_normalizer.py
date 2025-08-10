import ipaddress
import re
import hashlib

def normalize_ip(ip):
    """Normalize IP address to a standard format."""
    try:
        ip_obj = ipaddress.ip_address(ip.strip())
        return str(ip_obj)
    except ValueError:
        return None

def normalize_domain(domain):
    """Normalize domain to lowercase, remove protocols and paths."""
    domain = domain.strip().lower()
    domain = re.sub(r"^(https?://|www\.)", "", domain)
    domain = re.sub(r"/.*$", "", domain)
    if ":" in domain:
        domain = domain.split(":")[0]
    return domain if re.match(r"^[\w\-\.]+$", domain) else None

def normalize_hash(hash_str):
    """Normalize hash (MD5, SHA1, SHA256) to lowercase."""
    hash_str = hash_str.strip().lower()
    if re.match(r"^[a-f0-9]{32}$", hash_str):  # MD5
        return hash_str
    elif re.match(r"^[a-f0-9]{40}$", hash_str):  # SHA1
        return hash_str
    elif re.match(r"^[a-f0-9]{64}$", hash_str):  # SHA256
        return hash_str
    return None

def normalize_ioc(indicator, indicator_type_raw):
    """Normalize IOC based on type and return normalized indicator and original type."""
    normalized_indicator = None
    indicator_type_lower = indicator_type_raw.lower() # Convert to lowercase for internal logic

    if indicator_type_lower == "ip":
        normalized_indicator = normalize_ip(indicator)
    elif indicator_type_lower == "domain":
        normalized_indicator = normalize_domain(indicator)
    elif indicator_type_lower == "hash":
        normalized_indicator = normalize_hash(indicator)
    
    # Always return a tuple, even if normalization failed for the indicator
    return (normalized_indicator, indicator_type_raw) # Return original type for consistency with app.py