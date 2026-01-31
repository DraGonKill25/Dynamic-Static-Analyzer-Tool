#! Static PE analysis (Windows)

import os
import math
from typing import Dict, List, Optional

DANGEROUS_APIS = [
    "CreateRemoteThread", "WriteProcessMemory", "VirtualAlloc",
    "CreateProcess", "ShellExecute", "WinExec",
    "LoadLibrary", "GetProcAddress", "NtUnmapViewOfSection",
    "IsDebuggerPresent", "CheckRemoteDebuggerPresent",
    "CreateToolhelp32Snapshot", "Process32First", "OpenProcess",
]
SUSPICIOUS_SECTIONS = [".packed", ".upx", ".upx0", ".upx1", ".themida", ".vmp", ".nsp"]


def _entropy(data: bytes) -> float:
    """Calcule l'entropie de Shannon."""
    if not data:
        return 0.0
    freq = {}
    for b in data:
        freq[b] = freq.get(b, 0) + 1
    n = len(data)
    return -sum((c / n) * math.log2(c / n) for c in freq.values())


def analyze_with_pefile(file_path: str) -> Dict:
    """Analyse PE avec pefile."""
    import pefile
    pe = pefile.PE(file_path)
    result = {"sections": [], "imports": [], "suspicious_imports": [], "suspicious_sections": [], "entropy_high": [], "signed": False}
    for section in pe.sections:
        name = section.Name.decode("utf-8", errors="replace").strip("\x00")
        try:
            data = section.get_data()
            ent = _entropy(data)
        except Exception:
            ent = 0
        result["sections"].append({"name": name, "entropy": round(ent, 2), "size": section.SizeOfRawData})
        if ent > 7.0:
            result["entropy_high"].append(name)
        if any(s in name.lower() for s in SUSPICIOUS_SECTIONS):
            result["suspicious_sections"].append(name)
    if hasattr(pe, "DIRECTORY_ENTRY_IMPORT") and pe.DIRECTORY_ENTRY_IMPORT:
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            for imp in entry.imports:
                if imp.name:
                    name = imp.name.decode() if isinstance(imp.name, bytes) else str(imp.name)
                    result["imports"].append(name)
                    if any(api.lower() in name.lower() for api in DANGEROUS_APIS):
                        result["suspicious_imports"].append(name)
    if hasattr(pe, "DIRECTORY_ENTRY_SECURITY") and pe.DIRECTORY_ENTRY_SECURITY:
        result["signed"] = True
    pe.close()
    return result


def analyze_minimal(file_path: str) -> Dict:
    """Minimal analysis without pefile."""
    with open(file_path, "rb") as f:
        data = f.read(2048)
    result = {"sections": [], "imports": [], "suspicious_imports": [], "suspicious_sections": [], "entropy_high": [], "signed": False}
    ent = _entropy(data[:500])
    result["sections"].append({"name": ".data", "entropy": round(ent, 2), "size": len(data)})
    if ent > 7.0:
        result["entropy_high"].append(".data")
    return result


def analyze(file_path: str) -> Dict:
    """Analyzes PE (with pefile if available)."""
    if not os.path.isfile(file_path):
        return {"error": "File not found"}
    with open(file_path, "rb") as f:
        if f.read(2) != b"MZ":
            return {"error": "Pas un fichier PE"}
    try:
        return analyze_with_pefile(file_path)
    except ImportError:
        return analyze_minimal(file_path)
    except Exception as e:
        return {"error": str(e)}
