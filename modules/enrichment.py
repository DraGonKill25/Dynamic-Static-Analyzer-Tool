#! Enrichissement externe (WHOIS, etc.)

import re
from typing import Dict, List, Optional


def extract_ips_and_domains(strings: List) -> List[str]:
    """Extracts IPs and domains from strings (suspicious or classified)."""
    ip_re = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
    domain_re = re.compile(r"[a-zA-Z0-9][a-zA-Z0-9.-]*\.(?:com|net|org|io|ru|cn|tk|xyz|info|biz)[^\s\x00]*")
    results = []
    for s in strings:
        if isinstance(s, dict):
            val = s.get("value", str(s))
        else:
            val = str(s)
        for m in ip_re.findall(val):
            if m not in results:
                results.append(m)
        for m in domain_re.findall(val):
            d = m.split("/")[0].split(":")[0]
            if d not in results:
                results.append(d)
    return results[:20]


def whois_lookup(target: str) -> Optional[Dict]:
    """Lookup WHOIS pour une IP ou un domaine."""
    try:
        import whois
        w = whois.whois(target)
        return {
            "domain": getattr(w, "domain_name", None) or target,
            "registrar": getattr(w, "registrar", None),
            "country": getattr(w, "country", None),
            "creation_date": str(getattr(w, "creation_date", None))[:50],
        }
    except ImportError:
        return None
    except Exception:
        return None


def enrich_iocs(suspicious_strings: List, classified_strings: Dict, enable: bool = True) -> Dict:
    """Enriches IOCs with WHOIS if enabled."""
    if not enable:
        return {}
    targets = extract_ips_and_domains(suspicious_strings)
    for cat_items in (classified_strings or {}).values():
        targets.extend(extract_ips_and_domains(cat_items))
    targets = list(dict.fromkeys(targets))[:10]
    enriched = {}
    for t in targets:
        info = whois_lookup(t)
        if info:
            enriched[t] = info
    return enriched
