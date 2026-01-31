#! Analysis profiles by file type

import os
import configparser
from pathlib import Path


def detect_file_type(file_path: str) -> str:
    """Detects file type (PE, ELF, Script, Document, Unknown)."""
    if not os.path.isfile(file_path):
        return "unknown"
    try:
        with open(file_path, "rb") as f:
            header = f.read(32)
    except Exception:
        return "unknown"
    ext = Path(file_path).suffix.lower()
    if header[:2] == b"MZ":
        return "PE"
    if header[:4] == b"\x7fELF":
        return "ELF"
    script_exts = {".py", ".pyc", ".js", ".vbs", ".ps1", ".bat", ".sh", ".bash"}
    if ext in script_exts:
        return "script"
    doc_exts = {".pdf", ".doc", ".docx", ".xls", ".xlsx", ".rtf", ".odt"}
    if ext in doc_exts:
        return "document"
    return "unknown"


def load_profiles(config_path: str) -> dict:
    """Loads profiles from config.ini."""
    config = configparser.ConfigParser()
    config.read(config_path)
    profiles = {}
    for section in config.sections():
        if section.startswith("PROFILE_"):
            name = section.replace("PROFILE_", "").lower()
            profiles[name] = dict(config[section])
    return profiles


def get_profile_for_file(file_path: str, config_path: str, force_profile: str = None) -> dict:
    """Returns the profile to use for a file."""
    profiles = load_profiles(config_path)
    if force_profile and force_profile.lower() in profiles:
        return profiles[force_profile.lower()]
    ftype = detect_file_type(file_path)
    if ftype in profiles:
        return profiles[ftype]
    return profiles.get("default", profiles.get("pe", {}))
