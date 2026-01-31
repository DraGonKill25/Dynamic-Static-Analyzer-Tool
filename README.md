# Malware Analyzer

Unified file analysis application: online scan via VirusTotal and advanced local analysis pipeline (file, strings, strace, Ghidra, YARA, PE, scoring, structured reports).

## Features

### Online scan (VirusTotal)
- Directory scan via VirusTotal API (key to configure)
- Detection report (X/Y engines)
- HTML export of scan results
- Double-click on a row to open the VirusTotal report

### Local analysis tools
- **file**: file type identification
- **strings**: extraction of printable ASCII strings
- **strace**: system call tracing (Linux only)
- **Ghidra**: launch Ghidra with the selected file

### Analysis pipeline (pro mode)
- **Profiles**: Auto, PE, Script, ELF, Document — adapts tools based on file type
- **Risk score**: 0–100 with LOW / MEDIUM / HIGH level and badges (Network, Persistence, C2, Packed, YARA Match…)
- **Advanced strings**: UTF-16LE, Base64, classification (network, persistence, C2, anti-analysis)
- **YARA**: scan with custom rules (in `rules/` folder)
- **PE analysis**: suspicious imports, sections, entropy (with pefile)
- **Structured reports**: Markdown and HTML (executive summary, IOCs, recommendations)

### History and comparison
- **History**: list of recent analyses, double-click to reopen a report
- **Compare**: compare 2 files (hashes, string intersection/difference)

## Installation

```bash
pip install -r requirements.txt
```

**Optional prerequisites:**
- **yara-python**: requires libyara (`apt install libyara-dev` on Linux, or vcpkg on Windows)
- **pefile**: advanced PE analysis
- **watchdog**: folder monitoring
- **python-whois**: WHOIS enrichment (option `enable_whois` in config)

## Launch

**Graphical interface:**
```bash
python main.py
```

**Command line:**
```bash
# Full analysis (pro pipeline)
python malware_analyzer.py file.exe

# Markdown and HTML reports
python malware_analyzer.py file.exe -o ./reports --format md html

# Folder monitoring (auto analysis on new files)
python malware_analyzer.py --watch /path/samples --auto-report html

# Specific options
python malware_analyzer.py file.exe --profile pe
python malware_analyzer.py file.exe --strings
python malware_analyzer.py file.exe --suspicious
python malware_analyzer.py file.exe --file
```

## Configuration

### config.ini

| Section | Key | Description |
|---------|-----|-------------|
| `[API]` | `key` | VirusTotal API key |
| `[PIPELINE]` | `vt_threshold` | VT detection threshold for full analysis |
| `[PIPELINE]` | `enable_whois` | WHOIS enrichment for IOCs (true/false) |
| `[PROFILE_*]` | `tools` | Tools to run (file, strings, hashes, pe, yara, vt) |
| `[PROFILE_*]` | `string_encodings` | Encodings for strings (ascii, utf16, base64) |

### Predefined profiles

- **PROFILE_PE**: Windows PE (file, strings, hashes, pe, yara, vt)
- **PROFILE_SCRIPT**: Python/JS/PowerShell scripts, etc.
- **PROFILE_ELF**: Linux executables
- **PROFILE_DOCUMENT**: PDF, Office
- **PROFILE_DEFAULT**: Fallback

## Project structure

```
├── main.py                  # Graphical interface (dark mode)
├── malware_analyzer.py      # CLI entry point
├── config.ini               # Configuration (API, profiles, pipeline)
├── analysis_history.json    # Analysis history (generated)
├── core/
│   ├── engine.py            # Orchestration engine
│   ├── profiles.py          # File type detection + profiles
│   └── pipeline.py          # Conditional pipeline
├── modules/
│   ├── strings_advanced.py  # UTF-16, Base64, XOR, classification
│   ├── string_decoder.py    # Automatic decoding
│   ├── pe_analyzer.py       # PE analysis (imports, sections, entropy)
│   ├── yara_scanner.py      # YARA scan
│   ├── risk_scorer.py       # Score 0–100, badges
│   ├── report_generator.py  # Markdown, HTML reports
│   └── enrichment.py        # WHOIS
├── rules/
│   └── example.yar          # Sample YARA rule
└── requirements.txt
```

## User guide

### Graphical interface

1. **VirusTotal API key**: enter the key, click Save. Recommended delay: 20–25 s.
2. **Folder (scan)**: Browse folder → Start scan. Results appear in the table.
3. **File (tools)**: select a table row or Browse file to analyze a file.
4. **Profile**: choose Auto (automatic detection), PE, Script, ELF or Document.
5. **Buttons**: file, strings, strace, Ghidra, Full analysis, History, Compare.
6. **Score**: displayed after full analysis (color by level).
7. **Double-click** on a table row → opens the VirusTotal report.

### Full analysis (pipeline)

Produces:
- Risk score and badges
- MD5, SHA1, SHA256 hashes
- Suspicious and classified strings
- YARA matches
- PE information (if Windows file)
- `<name>_report.md` and `<name>_report.html` reports

### YARA rules

Place your `.yar` or `.yara` files in the `rules/` folder. The scan will apply them automatically.

## Command line

| Command | Description |
|---------|-------------|
| `python malware_analyzer.py <file>` | Full analysis (pro pipeline) |
| `python malware_analyzer.py <file> -o DIR --format md html` | Reports in DIR folder |
| `python malware_analyzer.py <file> -p pe` | Force PE profile |
| `python malware_analyzer.py --watch DIR --auto-report html` | Folder monitoring |
| `python malware_analyzer.py <file> --strings` | Strings extraction only |
| `python malware_analyzer.py <file> --suspicious` | Suspicious strings only |
| `python malware_analyzer.py <file> --file` | File type only |
| `python malware_analyzer.py <file> -r report.txt` | Legacy text report |

## License

GPL License.

## Disclaimer

This tool is intended for analysis of potentially malicious files. It does not replace a complete security solution. Handle suspicious files with caution.
