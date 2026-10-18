import re
import math
from src.allowlist import KNOWN_DOMAINS

SUSPICIOUS_WORDS = ["login", "verify", "secure", "account", "update",
                    "bank", "paypal", "signin", "confirm", "password"]

def clean_url(url):
    # strip protocol and www so the model can't use them as shortcuts
    url = url.strip().lower()
    url = re.sub(r"^https?://", "", url)
    url = re.sub(r"^www\.", "", url)
    return url

def entropy(s):
    if not s:
        return 0.0
    probs = [s.count(c) / len(s) for c in set(s)]
    return -sum(p * math.log2(p) for p in probs)

def extract_features(url):
    u = clean_url(url)
    host = re.split(r"[/?#]", u)[0].split(":")[0]
    path = u[len(host):]
    registered = ".".join(host.split(".")[-2:])
    return {
        "url_length": len(u),
        "host_length": len(host),
        "path_length": len(path),
        "num_dots": u.count("."),
        "num_hyphens": u.count("-"),
        "num_digits": sum(c.isdigit() for c in u),
        "num_special": sum(not c.isalnum() for c in u),
        "has_at": int("@" in u),
        "has_ip": int(bool(re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", host))),
        "num_subdomains": max(len(host.split(".")) - 2, 0),
        "has_query": int("?" in u),
        "num_params": u.count("&") + (1 if "?" in u else 0),
        "suspicious_words": sum(w in u for w in SUSPICIOUS_WORDS),
        "entropy": round(entropy(u), 3),
	"known_domain": int(registered in KNOWN_DOMAINS),
    }