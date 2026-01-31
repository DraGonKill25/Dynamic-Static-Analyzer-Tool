#! Score de risque et badges

from typing import Dict, List, Tuple


def compute(
    vt_report: Dict = None,
    suspicious_strings: List = None,
    classified_strings: Dict = None,
    yara_matches: List = None,
    pe_info: Dict = None,
) -> Tuple[int, str, List[str]]:
    """
    Calcule le score 0-100, le niveau (LOW/MEDIUM/HIGH) et les badges.
    """
    score = 0
    badges = []
    vt_report = vt_report or {}
    suspicious_strings = suspicious_strings or []
    classified_strings = classified_strings or {}
    yara_matches = yara_matches or []
    pe_info = pe_info or {}

    # VT detections (max 40)
    vt_pos = vt_report.get("positives", 0)
    vt_total = vt_report.get("total", 70)
    if vt_total > 0:
        vt_ratio = min(vt_pos / vt_total, 1.0)
        score += int(vt_ratio * 40)
        if vt_pos >= 10:
            badges.append("VT High")
        elif vt_pos >= 1:
            badges.append("VT Detected")

    # Strings suspectes (max 20)
    sus_count = len(suspicious_strings)
    if sus_count > 20:
        score += 20
        badges.append("Many IoCs")
    elif sus_count > 10:
        score += 15
    elif sus_count > 5:
        score += 10
    elif sus_count > 0:
        score += 5

    # Classification (network, persistence, c2, anti_analysis)
    for cat in ["network", "persistence", "c2", "anti_analysis"]:
        items = classified_strings.get(cat, [])
        if items:
            if cat == "network":
                badges.append("Network")
                score += 3
            elif cat == "persistence":
                badges.append("Persistence")
                score += 5
            elif cat == "c2":
                badges.append("C2")
                score += 8
            elif cat == "anti_analysis":
                badges.append("Anti-Analysis")
                score += 5

    # YARA (max 25)
    yara_count = len([m for m in yara_matches if m[0] != "_error"])
    if yara_count > 5:
        score += 25
        badges.append("YARA High")
    elif yara_count > 0:
        score += min(yara_count * 5, 25)
        badges.append("YARA Match")

    # PE (max 15: packing + API)
    if pe_info.get("entropy_high"):
        score += 10
        badges.append("Packed")
    if pe_info.get("suspicious_imports"):
        score += min(len(pe_info["suspicious_imports"]) * 2, 5)

    score = min(score, 100)

    # Niveau
    if score >= 67:
        level = "HIGH"
    elif score >= 34:
        level = "MEDIUM"
    else:
        level = "LOW"

    return score, level, list(dict.fromkeys(badges))
