#! Scanner YARA

import os
from typing import List, Tuple

_yara_available = None


def _check_yara():
    global _yara_available
    if _yara_available is None:
        try:
            import yara
            _yara_available = True
        except ImportError:
            _yara_available = False
    return _yara_available


def scan_file(file_path: str, rules_dir: str) -> List[Tuple[str, str]]:
    """
    Scans a file with YARA rules.
    Retourne [(rule_name, match_string), ...]
    """
    if not _check_yara():
        return []
    import yara
    if not os.path.isfile(file_path):
        return []
    rules_paths = []
    if os.path.isdir(rules_dir):
        for root, _, files in os.walk(rules_dir):
            for f in files:
                if f.endswith((".yar", ".yara", ".yarc")):
                    rules_paths.append(os.path.join(root, f))
    if not rules_paths:
        return []
    try:
        compiled = yara.compile(filepaths={f"r{i}": p for i, p in enumerate(rules_paths)})
        matches = compiled.match(file_path)
        result = []
        for m in matches:
            for s in m.strings:
                result.append((m.rule, str(s.instances[0]) if s.instances else ""))
        return result
    except yara.Error as e:
        return [("_error", str(e))]
    except Exception as e:
        return [("_error", str(e))]
