#! Advanced string extraction: UTF-16, Base64, XOR, classification

import re
import base64
import zlib
import gzip
import io
from typing import List, Dict, Optional


def extract_ascii(data: bytes, min_len: int = 4) -> List[str]:
    """Extracts ASCII strings."""
    result = []
    current = []
    for b in data:
        if 32 <= b <= 126:
            current.append(chr(b))
        else:
            if len(current) >= min_len:
                result.append("".join(current))
            current = []
    if len(current) >= min_len:
        result.append("".join(current))
    return result


def extract_utf16le(data: bytes, min_len: int = 4) -> List[str]:
    """Extrait les chaînes UTF-16LE."""
    result = []
    current = []
    i = 0
    while i < len(data) - 1:
        lo, hi = data[i], data[i + 1]
        if hi == 0 and 32 <= lo <= 126:
            current.append(chr(lo))
        else:
            if len(current) >= min_len:
                result.append("".join(current))
            current = []
        i += 2
    if len(current) >= min_len:
        result.append("".join(current))
    return result


def try_decode_base64(s: str) -> Optional[tuple]:
    """Tries to decode a Base64 string. Returns (original, decoded) or None."""
    s = s.strip()
    for candidate in [s, s + "=", s + "=="]:
        try:
            decoded = base64.b64decode(candidate)
            if decoded and all(32 <= b <= 126 or b in (9, 10, 13) for b in decoded[:100]):
                return (s, decoded.decode("ascii", errors="replace"))
        except Exception:
            continue
    return None


def extract_base64_strings(strings: List[str], min_len: int = 20) -> List[Dict]:
    """Detects and decodes Base64 strings."""
    result = []
    for s in strings:
        matches = re.findall(r"[A-Za-z0-9+/]{20,}={0,2}", s)
        for m in matches:
            decoded = try_decode_base64(m)
            if decoded:
                result.append({"original": decoded[0][:80], "decoded": decoded[1][:200], "type": "base64"})
    return result


def xor_decrypt(data: bytes, key: bytes) -> bytes:
    """XOR with repeated key."""
    result = bytearray()
    for i, b in enumerate(data):
        result.append(b ^ key[i % len(key)])
    return bytes(result)


def try_xor_strings(data: bytes, min_len: int = 4) -> List[Dict]:
    """Tries common XOR keys."""
    common_keys = [bytes([k]) for k in [0x41, 0x90, 0x55, 0xAA, 0xFF, 0x00]]
    common_keys += [bytes([0x41, 0x42]), bytes([0x90, 0x90])]
    result = []
    for key in common_keys:
        dec = xor_decrypt(data[:2000], key)
        strs = extract_ascii(dec, min_len)
        if strs and len(strs) > 2:
            result.append({"key_hex": key.hex(), "sample": strs[0][:100], "type": "xor"})
    return result[:5]


def try_decompress(data: bytes) -> List[Dict]:
    """Tries zlib/gzip on candidate blocks."""
    result = []
    for start in range(0, min(5000, len(data) - 10), 100):
        for decompressor, name in [(zlib.decompress, "zlib"), (gzip.decompress, "gzip")]:
            try:
                block = data[start : start + 500]
                dec = decompressor(block)
                if dec and len(dec) < 10000:
                    strs = extract_ascii(dec, 6)
                    if strs:
                        result.append({"format": name, "sample": strs[0][:100]})
                        break
            except Exception:
                pass
    return result[:3]


# String classification
CLASSIFICATION_PATTERNS = {
    "network": [
        r"https?://[^\s\x00]+",
        r"\b(?:\d{1,3}\.){3}\d{1,3}\b",
        r"[a-zA-Z0-9.-]+\.(com|net|org|io|ru|cn|tk)[^\s\x00]*",
        r"User-Agent\s*:",
        r"Mozilla/",
    ],
    "persistence": [
        r"(?i)(HKCU|HKLM|HKEY)[\\\s][^\s\x00]+",
        r"(?i)Run\s*[=\(]",
        r"(?i)Startup",
        r"(?i)CurrentVersion\\Run",
        r"@reboot",
        r"cron",
        r"systemd",
        r"\.service",
    ],
    "c2": [
        r"(?i)beacon",
        r"(?i)callback",
        r"(?i)c2\s*[:=]",
        r"(?i)command\s*and\s*control",
        r"(?i)check.?in",
    ],
    "anti_analysis": [
        r"(?i)sandbox",
        r"(?i)debugger",
        r"(?i)virtualbox",
        r"(?i)vmware",
        r"(?i)vbox",
        r"(?i)wine",
        r"(?i)qemu",
        r"(?i)proc/self",
    ],
}


def classify_strings(strings: List[str]) -> Dict[str, List[str]]:
    """Classifies strings by category."""
    classified = {"network": [], "persistence": [], "c2": [], "anti_analysis": []}
    seen = set()
    for s in strings:
        if len(s) < 6 or s in seen:
            continue
        for category, patterns in CLASSIFICATION_PATTERNS.items():
            for pat in patterns:
                if re.search(pat, s):
                    if s not in seen:
                        seen.add(s)
                        classified[category].append(s[:150])
                    break
    return classified


def extract_all_encodings(file_path: str, encodings: List[str]) -> Dict:
    """Extracts strings according to requested encodings."""
    try:
        with open(file_path, "rb") as f:
            data = f.read()
    except Exception as e:
        return {"error": str(e), "all": []}
    all_strings = []
    result = {"ascii": [], "utf16": [], "base64_decoded": [], "xor_samples": [], "compressed": []}
    if "ascii" in encodings:
        result["ascii"] = extract_ascii(data, 6)
        all_strings.extend(result["ascii"])
    if "utf16" in encodings or "utf16le" in encodings:
        result["utf16"] = extract_utf16le(data, 6)
        all_strings.extend(result["utf16"])
    if "base64" in encodings:
        result["base64_decoded"] = extract_base64_strings(all_strings)
    if "xor" in encodings:
        result["xor_samples"] = try_xor_strings(data)
    if "zlib" in encodings or "gzip" in encodings:
        result["compressed"] = try_decompress(data)
    result["all"] = list(dict.fromkeys(all_strings))
    return result
