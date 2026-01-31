#! Structured report generation (Markdown, HTML, PDF)

import os
from datetime import datetime
from typing import Dict, List
from jinja2 import Template


def generate_tldr(analysis: Dict) -> str:
    """Generates an automatic executive summary."""
    score = analysis.get("risk_score", 0)
    level = analysis.get("risk_level", "LOW")
    badges = analysis.get("badges", [])
    vt = analysis.get("vt_report") or {}
    vt_pos = vt.get("positives", 0)
    yara_count = len([m for m in analysis.get("yara_matches", []) if m[0] != "_error"])
    classified = analysis.get("classified_strings", {})

    parts = []
    if level == "HIGH":
        parts.append("The file presents a high risk.")
    elif level == "MEDIUM":
        parts.append("The file presents indicators of suspicious behavior.")
    else:
        parts.append("The file presents a low risk or limited indicators.")

    if vt_pos > 0:
        parts.append(f"{vt_pos} antivirus engines on VirusTotal detected this file.")
    if yara_count > 0:
        parts.append(f"{yara_count} YARA rule(s) matched.")
    if "Network" in badges:
        parts.append("Network strings (URLs, IPs) were detected.")
    if "Persistence" in badges:
        parts.append("Potential persistence mechanisms were identified.")
    if "Packed" in badges:
        parts.append("The file may be packed or obfuscated.")

    return " ".join(parts)


def generate_recommendations(analysis: Dict) -> str:
    """Generates recommendations based on the analysis."""
    level = analysis.get("risk_level", "LOW")
    lines = []
    if level == "HIGH":
        lines.append("- Do not execute this file.")
        lines.append("- Isolate the system if already executed.")
        lines.append("- Review IOCs for compromise hunting.")
    elif level == "MEDIUM":
        lines.append("- Conduct in-depth analysis before execution.")
        lines.append("- Verify detected network indicators.")
    lines.append("- Keep a copy for forensic analysis.")
    return "\n".join(lines)


def _escape_md(s: str) -> str:
    return s.replace("|", "\\|").replace("\n", " ")


def _prepare_analysis_context(analysis: Dict) -> Dict:
    """Prepares analysis data for templates."""
    fi = analysis.get("file_info", {})
    hashes = fi.get("hashes", {})
    vt = analysis.get("vt_report") or {}
    pe = analysis.get("pe_info") or {}
    classified = analysis.get("classified_strings", {})
    yara = [m for m in analysis.get("yara_matches", []) if m[0] != "_error"]
    sus = analysis.get("suspicious_strings", [])[:40]

    # Risk bar (0-100)
    score = analysis.get("risk_score", 0)
    score_pct = min(max(score, 0), 100)

    return {
        **analysis,
        "_tldr": generate_tldr(analysis),
        "_recommendations": generate_recommendations(analysis),
        "_recommendations_list": [l.strip().lstrip("-").strip() for l in generate_recommendations(analysis).split("\n") if l.strip().startswith("-")],
        "_now": datetime.now().strftime("%Y-%m-%d %H:%M"),
        "_now_iso": datetime.now().isoformat(),
        "_score_pct": score_pct,
        "_vt_positives": vt.get("positives", 0),
        "_vt_total": vt.get("total", 70),
        "_vt_permalink": vt.get("permalink", ""),
        "_yara_count": len(yara),
        "_has_pe": bool(pe and "error" not in pe),
        "_classified_with_items": {k: v for k, v in classified.items() if v},
        "_suspicious": sus,
    }


def generate_markdown(analysis: Dict, output_path: str) -> str:
    """Generates a Markdown report."""
    ctx = _prepare_analysis_context(analysis)

    tpl = """# 🔬 Malware Analysis Report

## {{ file_info.name }}

| Field | Value |
|-------|-------|
| **Date** | {{ _now }} |
| **File type** | {{ file_type }} |
| **Profile** | {{ profile.get('tools', 'default') }} |
| **Size** | {{ file_info.get('size_formatted', file_info.get('size', 'N/A')) }} |
| **Modified** | {{ file_info.get('modified', 'N/A') }} |

---

## 🎯 Risk Assessment

| **Score** | **Level** | **Badges** |
|-----------|-----------|------------|
| **{{ risk_score }}/100** | `{{ risk_level }}` | {% for b in badges %}`{{ b }}` {% endfor %}{% if not badges %}—{% endif %} |

{{ _tldr }}

---

## 📋 Indicators of Compromise (IOC)

### Hashes

| Type | Hash |
|------|------|
| **MD5** | `{{ file_info.hashes.md5 }}` |
| **SHA1** | `{{ file_info.hashes.sha1 }}` |
| **SHA256** | `{{ file_info.hashes.sha256 }}` |

### VirusTotal
{% if _vt_total and (_vt_positives > 0 or _vt_permalink) %}
| Detections | {{ _vt_positives }}/{{ _vt_total }} |
| Report | {% if _vt_permalink %}[Open on VirusTotal]({{ _vt_permalink }}){% else %}—{% endif %} |
{% else %}
| Status | Not scanned |
{% endif %}

### Suspicious strings
| Type | Value |
|------|-------|
{% for s in _suspicious %}
| `{{ s.type }}` | `{{ s.value[:70] }}{% if s.value|length > 70 %}...{% endif %}` |
{% endfor %}
{% if not _suspicious %}
| — | No suspicious strings detected |
{% endif %}

---

## 🔍 Technical Analysis

### Classified strings
{% for cat, items in _classified_with_items.items() %}
- **{{ cat }}** ({{ items | length }}): {% for item in items[:5] %}`{{ item[:50] }}{% if item|length > 50 %}...{% endif %}`{% if not loop.last %}, {% endif %}{% endfor %}{% if items|length > 5 %} ...{% endif %}
{% endfor %}
{% if not _classified_with_items %}
- No classified strings
{% endif %}

### YARA matches
{% for rule, _ in yara_matches %}
- ✓ {{ rule }}
{% endfor %}
{% if _yara_count == 0 %}
- No YARA matches
{% endif %}

### PE Analysis
{% if _has_pe and pe_info %}
| Section | Entropy | Size | Notes |
|---------|---------|------|-------|
{% for sec in pe_info.get('sections', []) %}
| {{ sec.name }} | {{ sec.entropy }} | {{ sec.size }} | {% if sec.name in (pe_info.get('entropy_high') or []) %}⚠️ High entropy{% elif sec.name in (pe_info.get('suspicious_sections') or []) %}⚠️ Suspicious{% else %}—{% endif %} |
{% endfor %}

**Suspicious imports:** {{ pe_info.get('suspicious_imports', []) | join(", ") or "None" }}
**Signed:** {{ "Yes" if pe_info.get('signed') else "No" }}
{% else %}
*N/A (not a PE file)*
{% endif %}

---

## ✅ Recommendations

{{ _recommendations }}

---

*Report generated by Malware Analyzer*
"""
    t = Template(tpl)
    content = t.render(**ctx)
    if output_path:
        os.makedirs(os.path.dirname(output_path) or ".", exist_ok=True)
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(content)
    return content


def generate_html(analysis: Dict, output_path: str) -> str:
    """Generates an HTML report."""
    ctx = _prepare_analysis_context(analysis)
    level_colors = {"HIGH": "#dc2626", "MEDIUM": "#ea580c", "LOW": "#16a34a"}
    ctx["_risk_color"] = level_colors.get(analysis.get("risk_level", "LOW"), "#6b7280")

    tpl = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Report — {{ file_info.name }}</title>
<style>
:root { --risk-color: {{ _risk_color }}; --bg: #0f0f14; --card: #1a1a24; --border: #2a2a3a; --fg: #e4e4e7; }
* { box-sizing: border-box; }
body { font-family: 'Segoe UI', system-ui, sans-serif; background: var(--bg); color: var(--fg); margin: 0; line-height: 1.6; }
.container { max-width: 900px; margin: 0 auto; padding: 2rem; }
h1 { font-size: 1.75rem; margin-bottom: 0.5rem; }
h2 { font-size: 1.2rem; margin: 2rem 0 1rem; color: #fafafa; border-bottom: 1px solid var(--border); padding-bottom: 0.5rem; }
.card { background: var(--card); border: 1px solid var(--border); border-radius: 8px; padding: 1.25rem; margin: 1rem 0; }
.score-box { display: inline-flex; align-items: center; gap: 1rem; padding: 1rem 1.5rem; background: var(--card); border-radius: 8px; border: 2px solid var(--risk-color); margin: 1rem 0; }
.score-num { font-size: 2.5rem; font-weight: 700; color: var(--risk-color); }
.score-bar { width: 120px; height: 12px; background: #2a2a3a; border-radius: 6px; overflow: hidden; }
.score-fill { height: 100%; background: var(--risk-color); width: {{ _score_pct }}%; min-width: 2px; transition: width 0.3s; }
.badges { display: flex; flex-wrap: wrap; gap: 6px; margin-top: 0.5rem; }
.badge { display: inline-block; padding: 4px 10px; border-radius: 6px; font-size: 12px; font-weight: 500; background: var(--risk-color); color: #fff; }
.meta-table { width: 100%; border-collapse: collapse; }
.meta-table th, .meta-table td { text-align: left; padding: 8px 12px; border-bottom: 1px solid var(--border); }
.meta-table th { width: 140px; color: #a1a1aa; font-weight: 500; }
.meta-table code { background: #2a2a3a; padding: 2px 6px; border-radius: 4px; font-size: 0.9em; word-break: break-all; }
.ioc-table { width: 100%; border-collapse: collapse; font-size: 0.9em; }
.ioc-table th, .ioc-table td { padding: 8px 12px; border-bottom: 1px solid var(--border); }
.ioc-table th { background: var(--card); color: #a1a1aa; }
.ioc-table code { background: #2a2a3a; padding: 2px 6px; border-radius: 4px; word-break: break-all; max-width: 400px; display: inline-block; overflow: hidden; text-overflow: ellipsis; }
a { color: #3b82f6; text-decoration: none; }
a:hover { text-decoration: underline; }
.tldr { background: rgba(59, 130, 246, 0.1); border-left: 4px solid #3b82f6; padding: 1rem 1.25rem; margin: 1rem 0; border-radius: 0 8px 8px 0; }
.recommendations { background: rgba(34, 197, 94, 0.08); border-left: 4px solid #22c55e; padding: 1rem 1.25rem; margin: 1rem 0; border-radius: 0 8px 8px 0; }
.recommendations li { margin: 0.4rem 0; }
.footer { margin-top: 3rem; padding-top: 1rem; border-top: 1px solid var(--border); font-size: 0.85em; color: #71717a; }
.section-icon { margin-right: 0.5rem; }
.pe-section { font-size: 0.9em; }
.pe-section table { width: 100%; border-collapse: collapse; }
.pe-section th, .pe-section td { padding: 6px 10px; border-bottom: 1px solid var(--border); text-align: left; }
.warn { color: #f59e0b; }
</style>
</head>
<body>
<div class="container">
<h1>🔬 Malware Analysis Report</h1>
<p style="color:#a1a1aa; margin-top:0;">{{ file_info.name }}</p>

<div class="score-box">
  <span class="score-num" style="color:var(--risk-color)">{{ risk_score }}/100</span>
  <div class="score-bar"><div class="score-fill"></div></div>
  <span style="font-weight:600;">{{ risk_level }}</span>
</div>
<div class="badges">
  {% for b in badges %}<span class="badge">{{ b }}</span>{% endfor %}
  {% if not badges %}<span style="color:#71717a;">No badges</span>{% endif %}
</div>

<div class="card">
<table class="meta-table">
<tr><th>Date</th><td>{{ _now }}</td></tr>
<tr><th>File type</th><td>{{ file_type }}</td></tr>
<tr><th>Profile</th><td>{{ profile.get('tools', 'default') }}</td></tr>
<tr><th>Size</th><td>{{ file_info.get('size_formatted', file_info.get('size', 'N/A')) }}</td></tr>
<tr><th>Modified</th><td>{{ file_info.get('modified', 'N/A') }}</td></tr>
</table>
</div>

<h2><span class="section-icon">📋</span>Executive Summary</h2>
<div class="tldr">{{ _tldr }}</div>

<h2><span class="section-icon">🎯</span>Indicators of Compromise</h2>
<div class="card">
<table class="ioc-table">
<tr><th>MD5</th><td><code>{{ file_info.hashes.md5 }}</code></td></tr>
<tr><th>SHA1</th><td><code>{{ file_info.hashes.sha1 }}</code></td></tr>
<tr><th>SHA256</th><td><code>{{ file_info.hashes.sha256 }}</code></td></tr>
{% if _vt_total and (_vt_positives > 0 or _vt_permalink) %}
<tr><th>VirusTotal</th><td>{{ _vt_positives }}/{{ _vt_total }}{% if _vt_permalink %} <a href="{{ _vt_permalink }}" target="_blank">→ Report</a>{% endif %}</td></tr>
{% endif %}
</table>
</div>

<h3 style="margin-top:1.5rem;">Suspicious strings</h3>
<div class="card">
<table class="ioc-table">
<tr><th>Type</th><th>Value</th></tr>
{% for s in _suspicious %}
<tr><td><code>{{ s.type }}</code></td><td><code>{{ s.value[:80] }}{% if s.value|length > 80 %}...{% endif %}</code></td></tr>
{% endfor %}
{% if not _suspicious %}
<tr><td colspan="2" style="color:#71717a;">No suspicious strings detected</td></tr>
{% endif %}
</table>
</div>

<h2><span class="section-icon">🔍</span>Technical Analysis</h2>

<h3>Classified strings</h3>
<div class="card">
{% for cat, items in _classified_with_items.items() %}
<p><strong>{{ cat }}</strong> ({{ items | length }}): {% for item in items[:3] %}<code>{{ item[:60] }}{% if item|length > 60 %}...{% endif %}</code>{% if not loop.last %}, {% endif %}{% endfor %}{% if items|length > 3 %} ...{% endif %}</p>
{% endfor %}
{% if not _classified_with_items %}
<p style="color:#71717a;">No classified strings</p>
{% endif %}
</div>

<h3>YARA matches</h3>
<div class="card">
{% if _yara_count > 0 %}
<ul style="margin:0; padding-left:1.25rem;">{% for rule, _ in yara_matches %}{% if rule != "_error" %}<li>{{ rule }}</li>{% endif %}{% endfor %}</ul>
{% else %}
<p style="color:#71717a;">No YARA matches</p>
{% endif %}
</div>

{% if _has_pe and pe_info %}
<h3>PE Analysis</h3>
<div class="card pe-section">
<table>
<tr><th>Section</th><th>Entropy</th><th>Size</th><th>Notes</th></tr>
{% for sec in pe_info.get('sections', []) %}
<tr>
  <td>{{ sec.name }}</td>
  <td>{{ sec.entropy }}</td>
  <td>{{ sec.size }}</td>
  <td>{% if sec.name in (pe_info.get('entropy_high') or []) %}<span class="warn">⚠ High entropy</span>{% elif sec.name in (pe_info.get('suspicious_sections') or []) %}<span class="warn">⚠ Suspicious</span>{% else %}—{% endif %}</td>
</tr>
{% endfor %}
</table>
<p style="margin-top:1rem;"><strong>Suspicious imports:</strong> {{ pe_info.get('suspicious_imports', []) | join(", ") or "None" }}</p>
<p><strong>Digitally signed:</strong> {{ "Yes" if pe_info.get('signed') else "No" }}</p>
</div>
{% endif %}

<h2><span class="section-icon">✅</span>Recommendations</h2>
<div class="recommendations">
<ul style="margin:0; padding-left:1.25rem;">{% for line in _recommendations_list %}<li>{{ line }}</li>{% endfor %}</ul>
</div>

<div class="footer">Report generated by Malware Analyzer · {{ _now }}</div>
</div>
</body>
</html>
"""
    t = Template(tpl)
    content = t.render(**ctx)
    if output_path:
        os.makedirs(os.path.dirname(output_path) or ".", exist_ok=True)
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(content)
    return content


def generate_report(analysis: Dict, output_dir: str, formats: List[str] = None) -> Dict[str, str]:
    """Generates reports in the requested formats. Returns {format: path}."""
    formats = formats or ["md", "html"]
    base = os.path.basename(analysis.get("file_path", "report"))
    name = os.path.splitext(base)[0]
    results = {}
    for fmt in formats:
        if fmt == "md":
            path = os.path.join(output_dir, f"{name}_report.md")
            generate_markdown(analysis, path)
            results["md"] = path
        elif fmt == "html":
            path = os.path.join(output_dir, f"{name}_report.html")
            generate_html(analysis, path)
            results["html"] = path
    return results
