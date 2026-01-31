# Sample Files for Testing

These files are used to test the Malware Analyzer's risk scoring.

| File | Level | Description |
|------|-------|-------------|
| `sample_low.txt` | **LOW** (0) | Benign content (license, config) |
| `sample_medium.ps1` | **MEDIUM** (~36) | Network, persistence, C2, anti-analysis, PowerShell |
| `sample_high.txt` | **MEDIUM** (~41) | Many IoCs, all classifications, maximum string-based score |

**HIGH level (67+):** Requires VirusTotal detections, YARA matches, or a packed PE file. The `rules/samples_test.yar` file contains additional rules—install `yara-python` to trigger them.
