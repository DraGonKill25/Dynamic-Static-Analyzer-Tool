#! Moteur d'orchestration principal

import os
from pathlib import Path
from typing import Optional
import sys

# Add parent to path for imports
SCRIPT_DIR = Path(__file__).resolve().parent.parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

from core.profiles import get_profile_for_file, detect_file_type
from core.pipeline import load_pipeline_config, should_run_full_analysis

# Lazy imports for optional modules
_analyzer = None
_modules = {}


def _get_analyzer():
    global _analyzer
    if _analyzer is None:
        try:
            import malware_analyzer as ma
            _analyzer = ma
        except ImportError:
            pass
    return _analyzer


def _get_module(name: str):
    if name not in _modules:
        try:
            mod = __import__(f"modules.{name}", fromlist=[name])
            _modules[name] = mod
        except ImportError:
            _modules[name] = None
    return _modules[name]


def run_analysis(
    file_path: str,
    config_path: str,
    profile_override: Optional[str] = None,
    vt_report: Optional[dict] = None,
    api_key: Optional[str] = None,
) -> dict:
    """
    Runs analysis according to detected or forced profile.
    Returns a dictionary with all results.
    """
    result = {
        "file_path": file_path,
        "file_type": detect_file_type(file_path),
        "profile": {},
        "file_info": {},
        "strings": [],
        "suspicious_strings": [],
        "classified_strings": {},
        "yara_matches": [],
        "pe_info": {},
        "risk_score": 0,
        "risk_level": "LOW",
        "badges": [],
        "vt_report": vt_report,
    }
    analyzer = _get_analyzer()
    if not analyzer:
        result["error"] = "Module malware_analyzer introuvable"
        return result

    profile = get_profile_for_file(file_path, config_path, profile_override)
    result["profile"] = profile
    tools = profile.get("tools", "file,strings,hashes").split(",")
    tools = [t.strip().lower() for t in tools]

    # File info & hashes (toujours utile)
    result["file_info"] = analyzer.get_file_info(file_path)
    if "error" in result["file_info"]:
        return result

    # Strings
    if "strings" in tools or "hashes" in tools:
        result["strings"] = analyzer.extract_strings(file_path, 6)
        result["suspicious_strings"] = analyzer.extract_suspicious_strings(file_path, 6)

    # Advanced strings (UTF-16, Base64, classification)
    mod_strings = _get_module("strings_advanced")
    if mod_strings:
        try:
            encodings = profile.get("string_encodings", "ascii").split(",")
            encodings = [e.strip().lower() for e in encodings]
            result["strings_advanced"] = mod_strings.extract_all_encodings(file_path, encodings)
            result["classified_strings"] = mod_strings.classify_strings(result.get("strings", []) + result.get("strings_advanced", []).get("all", []))
        except Exception as e:
            result["strings_advanced_error"] = str(e)
    else:
        result["classified_strings"] = {}

    # YARA
    mod_yara = _get_module("yara_scanner")
    if mod_yara and "yara" in tools:
        rules_dir = os.path.join(SCRIPT_DIR, "rules")
        result["yara_matches"] = mod_yara.scan_file(file_path, rules_dir)

    # PE Analysis
    mod_pe = _get_module("pe_analyzer")
    if mod_pe and "pe" in tools and result["file_type"] == "PE":
        try:
            result["pe_info"] = mod_pe.analyze(file_path)
        except Exception as e:
            result["pe_info"] = {"error": str(e)}

    # Risk Scorer
    mod_score = _get_module("risk_scorer")
    if mod_score:
        result["risk_score"], result["risk_level"], result["badges"] = mod_score.compute(
            result.get("vt_report"),
            result.get("suspicious_strings", []),
            result.get("classified_strings", {}),
            result.get("yara_matches", []),
            result.get("pe_info", {}),
        )

    return result
