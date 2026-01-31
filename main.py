#! Malware Analyzer - Online scan & Local analysis
# Unified application: API scan + analysis tools (file, strings, strace, Ghidra, etc.)

import os
import sys
import json
import requests
import time
import hashlib
import webbrowser
import threading
import configparser
import tkinter as tk
from tkinter import messagebox
from tkinter import filedialog
from tkinter import ttk
from tkinter import scrolledtext
from queue import Queue
from jinja2 import Template

# Direct integration of analysis module
try:
    import malware_analyzer as analyzer
except ImportError:
    analyzer = None

# Script paths (relative to project)
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
CONFIG_PATH = os.path.join(SCRIPT_DIR, "config.ini")
HISTORY_FILE = os.path.join(SCRIPT_DIR, "analysis_history.json")
REPORTS_DIR = os.path.join(SCRIPT_DIR, "reports")

# Dark mode theme
DARK = {
    "bg": "#1e1e2e",
    "bg_secondary": "#252536",
    "bg_input": "#2d2d3d",
    "fg": "#e4e4e7",
    "fg_dim": "#a1a1aa",
    "header": "#18181b",
    "entry_bg": "#3f3f46",
    "entry_fg": "#fafafa",
    "entry_insert": "#fafafa",
    "select_bg": "#3b82f6",
    "tree_bg": "#27272a",
    "tree_fg": "#e4e4e7",
    "tree_selected": "#3f3f46",
    "border": "#3f3f46",
}


class MalwareAnalyzerGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Malware Analyzer")
        self.root.geometry("980x850")
        self.root.resizable(True, True)
        self.root.configure(bg=DARK["bg"])

        self.should_stop = False
        self.api_key = ""
        self.directory_path = ""
        self.scan_queue = Queue()
        self.scan_thread = None
        self.config = configparser.ConfigParser()
        self.config.read(CONFIG_PATH)

        self._build_ui()
        self._load_config()

    def _build_ui(self):
        """Builds the unified interface (dark mode)."""
        self._setup_ttk_dark_style()
        d = DARK

        main_frame = tk.Frame(self.root, padx=15, pady=15, bg=d["bg"])
        main_frame.pack(fill=tk.BOTH, expand=True)

        # === Header ===
        header = tk.Frame(main_frame, bg=d["header"], height=50, relief=tk.FLAT)
        header.pack(fill=tk.X, pady=(0, 15))
        header.pack_propagate(False)
        title = tk.Label(header, text="Malware Analyzer — Online Scan & Local Tools",
                         font=("TkDefaultFont", 14, "bold"), fg=d["fg"], bg=d["header"])
        title.pack(expand=True)

        # === Section 1 : Configuration API VirusTotal ===
        config_frame = tk.LabelFrame(main_frame, text="Configuration — VirusTotal Scan", font=("TkDefaultFont", 10, "bold"),
                                     bg=d["bg"], fg=d["fg"], highlightbackground=d["border"], highlightthickness=1)
        config_frame.pack(fill=tk.X, pady=(0, 10))

        api_row = tk.Frame(config_frame, bg=d["bg"])
        api_row.pack(fill=tk.X, pady=5)
        tk.Label(api_row, text="VirusTotal API Key:", font=("TkDefaultFont", 9), bg=d["bg"], fg=d["fg"]).pack(side=tk.LEFT, padx=(0, 5))
        self.api_entry = tk.Entry(api_row, font=("TkDefaultFont", 9), width=45, bg=d["entry_bg"], fg=d["entry_fg"],
                                  insertbackground=d["entry_insert"], relief=tk.FLAT, highlightthickness=0)
        self.api_entry.pack(side=tk.LEFT, padx=5)
        self.api_button = tk.Button(api_row, text="Save", command=self.toggle_api_key, font=("TkDefaultFont", 9),
                                    bg=d["bg_secondary"], fg=d["fg"], activebackground=d["select_bg"], relief=tk.FLAT, bd=0)
        self.api_button.pack(side=tk.LEFT, padx=5)
        tk.Label(api_row, text="Delay (sec):", font=("TkDefaultFont", 9), bg=d["bg"], fg=d["fg"]).pack(side=tk.LEFT, padx=(15, 5))
        self.wait_time_entry = tk.Entry(api_row, font=("TkDefaultFont", 9), width=5, bg=d["entry_bg"], fg=d["entry_fg"],
                                        insertbackground=d["entry_insert"], relief=tk.FLAT, highlightthickness=0)
        self.wait_time_entry.insert(0, "20")
        self.wait_time_entry.pack(side=tk.LEFT, padx=5)

        # === Section 2: File / Folder ===
        file_frame = tk.LabelFrame(main_frame, text="File or folder to analyze", font=("TkDefaultFont", 10, "bold"),
                                   bg=d["bg"], fg=d["fg"], highlightbackground=d["border"], highlightthickness=1)
        file_frame.pack(fill=tk.X, pady=(0, 10))

        row1 = tk.Frame(file_frame, bg=d["bg"])
        row1.pack(fill=tk.X, pady=5)
        tk.Label(row1, text="Folder (scan):", font=("TkDefaultFont", 9), bg=d["bg"], fg=d["fg"]).pack(side=tk.LEFT, padx=(0, 5))
        self.dir_var = tk.StringVar()
        e1 = tk.Entry(row1, textvariable=self.dir_var, font=("TkDefaultFont", 9), width=55, state="disabled",
                      bg=d["entry_bg"], fg=d["fg"], relief=tk.FLAT, highlightthickness=0)
        e1.pack(side=tk.LEFT, padx=5, fill=tk.X, expand=True)
        tk.Button(row1, text="Browse folder", command=self.browse_directory, font=("TkDefaultFont", 9),
                  bg=d["bg_secondary"], fg=d["fg"], activebackground=d["select_bg"], relief=tk.FLAT, bd=0).pack(side=tk.LEFT, padx=3)

        row2 = tk.Frame(file_frame, bg=d["bg"])
        row2.pack(fill=tk.X, pady=5)
        tk.Label(row2, text="File (tools):", font=("TkDefaultFont", 9), bg=d["bg"], fg=d["fg"]).pack(side=tk.LEFT, padx=(0, 5))
        self.analysis_file_var = tk.StringVar()
        tk.Entry(row2, textvariable=self.analysis_file_var, font=("TkDefaultFont", 9), width=55, bg=d["entry_bg"], fg=d["entry_fg"],
                 insertbackground=d["entry_insert"], relief=tk.FLAT, highlightthickness=0).pack(side=tk.LEFT, padx=5, fill=tk.X, expand=True)
        tk.Button(row2, text="Browse file", command=self.browse_analysis_file, font=("TkDefaultFont", 9),
                  bg=d["bg_secondary"], fg=d["fg"], activebackground=d["select_bg"], relief=tk.FLAT, bd=0).pack(side=tk.LEFT, padx=3)

        row3 = tk.Frame(file_frame, bg=d["bg"])
        row3.pack(fill=tk.X, pady=5)
        tk.Label(row3, text="Profile:", font=("TkDefaultFont", 9), bg=d["bg"], fg=d["fg"]).pack(side=tk.LEFT, padx=(0, 5))
        self.profile_var = tk.StringVar(value="auto")
        profile_combo = ttk.Combobox(row3, textvariable=self.profile_var, values=["auto", "pe", "script", "elf", "document"], width=12, state="readonly")
        profile_combo.pack(side=tk.LEFT, padx=5)

        self.score_label = tk.Label(main_frame, text="", font=("TkDefaultFont", 10, "bold"), bg=d["bg"], fg=d["fg"])
        self.score_label.pack(pady=5)

        # === Section 3 : Boutons d'action ===
        actions_frame = tk.Frame(main_frame, bg=d["bg"])
        actions_frame.pack(fill=tk.X, pady=10)

        tk.Label(actions_frame, text="Scan :", font=("TkDefaultFont", 9, "bold"), bg=d["bg"], fg=d["fg"]).pack(side=tk.LEFT, padx=(0, 8))
        self.start_scan_button = tk.Button(actions_frame, text="Start scan", command=self.start_scan, font=("TkDefaultFont", 9), bg="#16a34a", fg="white", relief=tk.FLAT)
        self.start_scan_button.pack(side=tk.LEFT, padx=3)
        self.stop_scan_button = tk.Button(actions_frame, text="Stop", command=self.stop_scan, state=tk.DISABLED, font=("TkDefaultFont", 9), bg="#dc2626", fg="white", relief=tk.FLAT)
        self.stop_scan_button.pack(side=tk.LEFT, padx=3)
        self.print_report_button = tk.Button(actions_frame, text="Generate HTML report", command=self.generate_report, state=tk.DISABLED, font=("TkDefaultFont", 9),
                                             bg=d["bg_secondary"], fg=d["fg"], activebackground=d["select_bg"], relief=tk.FLAT, bd=0)
        self.print_report_button.pack(side=tk.LEFT, padx=3)

        tk.Frame(actions_frame, width=25, bg=d["bg"]).pack(side=tk.LEFT)

        tk.Label(actions_frame, text="Tools:", font=("TkDefaultFont", 9, "bold"), bg=d["bg"], fg=d["fg"]).pack(side=tk.LEFT, padx=(0, 8))
        tk.Button(actions_frame, text="file", command=lambda: self.run_tool("file"), font=("TkDefaultFont", 9), bg="#2563eb", fg="white", relief=tk.FLAT).pack(side=tk.LEFT, padx=2)
        tk.Button(actions_frame, text="strings", command=lambda: self.run_tool("strings"), font=("TkDefaultFont", 9), bg="#0d9488", fg="white", relief=tk.FLAT).pack(side=tk.LEFT, padx=2)
        tk.Button(actions_frame, text="strace", command=lambda: self.run_tool("strace"), font=("TkDefaultFont", 9), bg="#ea580c", fg="white", relief=tk.FLAT).pack(side=tk.LEFT, padx=2)
        tk.Button(actions_frame, text="Ghidra", command=lambda: self.run_tool("ghidra"), font=("TkDefaultFont", 9), bg="#7c3aed", fg="white", relief=tk.FLAT).pack(side=tk.LEFT, padx=2)
        tk.Button(actions_frame, text="Full analysis", command=lambda: self.run_tool("full"), font=("TkDefaultFont", 9), bg="#dc2626", fg="white", relief=tk.FLAT).pack(side=tk.LEFT, padx=2)
        tk.Button(actions_frame, text="History", command=self.show_history, font=("TkDefaultFont", 9),
                  bg=d["bg_secondary"], fg=d["fg"], relief=tk.FLAT).pack(side=tk.LEFT, padx=2)
        tk.Button(actions_frame, text="Compare", command=self.compare_files, font=("TkDefaultFont", 9),
                  bg=d["bg_secondary"], fg=d["fg"], relief=tk.FLAT).pack(side=tk.LEFT, padx=2)

        # === Section 4 : Tableau des résultats ===
        table_frame = tk.LabelFrame(main_frame, text="Scan results", font=("TkDefaultFont", 10, "bold"),
                                    bg=d["bg"], fg=d["fg"], highlightbackground=d["border"], highlightthickness=1)
        table_frame.pack(fill=tk.BOTH, expand=True, pady=(0, 10))

        self.result_tree = ttk.Treeview(table_frame, columns=("Number", "Name", "Size", "Detection", "Location"), show="headings", height=8)
        self.result_tree.heading("Number", text="#")
        self.result_tree.heading("Name", text="Name")
        self.result_tree.heading("Size", text="Size")
        self.result_tree.heading("Detection", text="Detection")
        self.result_tree.heading("Location", text="Location")
        self.result_tree.column("Number", width=50)
        self.result_tree.column("Name", width=180)
        self.result_tree.column("Size", width=100)
        self.result_tree.column("Detection", width=150)
        self.result_tree.column("Location", width=350)
        self.result_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scroll = ttk.Scrollbar(table_frame, orient=tk.VERTICAL, command=self.result_tree.yview)
        scroll.pack(side=tk.RIGHT, fill=tk.Y)
        self.result_tree.configure(yscrollcommand=scroll.set)
        self.result_tree.bind("<Double-1>", self.open_report_url)
        self.result_tree.bind("<<TreeviewSelect>>", self.on_tree_select)

        self.current_file_label = tk.Label(main_frame, text="", font=("TkDefaultFont", 9), fg=d["fg_dim"], bg=d["bg"])
        self.current_file_label.pack(pady=2)

        # === Section 5 : Sortie des outils ===
        output_frame = tk.LabelFrame(main_frame, text="Analysis tools output", font=("TkDefaultFont", 10, "bold"),
                                     bg=d["bg"], fg=d["fg"], highlightbackground=d["border"], highlightthickness=1)
        output_frame.pack(fill=tk.BOTH, expand=True, pady=(0, 5))

        self.tools_output = scrolledtext.ScrolledText(output_frame, height=10, font=("Consolas", 9), wrap=tk.WORD,
                                                      bg="#0d1117", fg="#c9d1d9", insertbackground="#c9d1d9")
        self.tools_output.pack(fill=tk.BOTH, expand=True)

        footer = tk.Label(main_frame, text="Double-click on a row → open online report", font=("TkDefaultFont", 8), fg=d["fg_dim"], bg=d["bg"])
        footer.pack(pady=5)

    def _setup_ttk_dark_style(self):
        """Configures ttk style for dark mode (Treeview, LabelFrame, etc.)."""
        d = DARK
        style = ttk.Style()
        try:
            style.theme_use("clam")
        except tk.TclError:
            pass
        style.configure("Treeview", background=d["tree_bg"], foreground=d["tree_fg"], fieldbackground=d["tree_bg"], borderwidth=0)
        style.configure("Treeview.Heading", background=d["header"], foreground=d["fg"], borderwidth=0)
        style.map("Treeview", background=[("selected", d["select_bg"])], foreground=[("selected", "white")])
        style.configure("Vertical.TScrollbar", background=d["bg_secondary"], troughcolor=d["bg"], borderwidth=0)

    def _load_config(self):
        if "API" in self.config:
            self.api_key = self.config["API"].get("key", "")
            if self.api_key:
                self.api_entry.delete(0, tk.END)
                self.api_entry.insert(0, self.api_key)
                self.api_button.config(text="Remove key")
                self.start_scan_button.config(state=tk.NORMAL)
        self.browse_button = None  # No separate browse button, we use dir_var
        self.start_scan_button.config(state=tk.NORMAL if self.api_key else tk.DISABLED)

    def browse_directory(self):
        path = filedialog.askdirectory(title="Select folder to scan")
        if path:
            self.directory_path = path
            self.dir_var.set(path)
            self.start_scan_button.config(state=tk.NORMAL if self.api_key else tk.DISABLED)

    def on_tree_select(self, event):
        sel = self.result_tree.selection()
        if sel:
            vals = self.result_tree.item(sel[0], "values")
            if vals and len(vals) >= 5 and vals[4] and os.path.isfile(vals[4]):
                self.analysis_file_var.set(vals[4])

    def browse_analysis_file(self):
        path = filedialog.askopenfilename(title="Select file to analyze")
        if path:
            self.analysis_file_var.set(path)

    def _get_analysis_file(self):
        p = self.analysis_file_var.get().strip()
        return p if p and os.path.isfile(p) else None

    def _append_output(self, text: str, clear: bool = True):
        self.tools_output.config(state=tk.NORMAL)
        if clear:
            self.tools_output.delete(1.0, tk.END)
        self.tools_output.insert(tk.END, text)
        self.tools_output.see(tk.END)
        self.root.update()

    def run_tool(self, tool_name: str):
        path = self._get_analysis_file()
        if not path:
            messagebox.showwarning("Warning", "Select a file (click on a table row or Browse file).")
            return
        if not analyzer:
            messagebox.showerror("Error", "Module malware_analyzer not found.")
            return
        self._append_output(f">>> {tool_name} — {path}\n", clear=True)
        try:
            if tool_name == "file":
                out = analyzer.run_file_command(path)
            elif tool_name == "strings":
                out = analyzer.run_strings_command(path)
            elif tool_name == "strace":
                out = analyzer.run_strace(path)
            elif tool_name == "ghidra":
                ok, msg = analyzer.open_ghidra(path)
                out = msg
                if ok:
                    self._append_output(msg, clear=False)
                    return
            elif tool_name == "full":
                try:
                    from core.engine import run_analysis
                    from modules.report_generator import generate_report, generate_tldr
                    profile = getattr(self, "profile_var", None)
                    prof = profile.get() if profile else "auto"
                    vt_report = None
                    if self.api_key:
                        h = analyzer.calculate_hash(path)
                        r = requests.get("https://www.virustotal.com/vtapi/v2/file/report",
                                         params={"apikey": self.api_key, "resource": h})
                        vt_report = r.json() if r.status_code == 200 else None
                    analysis = run_analysis(path, CONFIG_PATH, prof, vt_report, self.api_key)
                    if "error" in analysis:
                        self._append_output(f"Error: {analysis['error']}", clear=False)
                        return
                    os.makedirs(REPORTS_DIR, exist_ok=True)
                    report_paths = generate_report(analysis, REPORTS_DIR, ["md", "html"])
                    score = analysis.get("risk_score", 0)
                    level = analysis.get("risk_level", "LOW")
                    badges = analysis.get("badges", [])
                    level_colors = {"HIGH": "#dc2626", "MEDIUM": "#ea580c", "LOW": "#16a34a"}
                    self.score_label.config(text=f"Score: {score}/100 ({level}) | Badges: {', '.join(badges) or 'None'}",
                                            fg=level_colors.get(level, DARK["fg"]))
                    lines = [f"Score: {score}/100 ({level})", f"Badges: {', '.join(badges) or 'None'}", "",
                             f"Type: {analysis.get('file_type', '?')} | Profile: {prof}", ""]
                    for fmt, p in report_paths.items():
                        lines.append(f"Report {fmt}: {p}")
                    tldr = generate_tldr(analysis)
                    self._append_output("\n".join(lines) + "\n\nSummary: " + tldr, clear=True)
                    self._save_to_history(path, analysis, report_paths)
                except ImportError:
                    rpath = os.path.join(os.path.dirname(path), "analyse_" + os.path.basename(path) + ".txt")
                    out = analyzer.run_full_analysis(path, rpath)
                    self._append_output(out + f"\n\nReport: {rpath}", clear=True)
                return
            else:
                out = "Unknown tool"
            self._append_output(out, clear=False)
        except Exception as e:
            self._append_output(f"Error: {e}", clear=False)

    def _save_to_history(self, path: str, analysis: dict, report_paths: dict):
        """Saves the analysis to history. Stores report paths as relative to project."""
        try:
            history = []
            if os.path.isfile(HISTORY_FILE):
                with open(HISTORY_FILE, "r", encoding="utf-8") as f:
                    history = json.load(f)
            from datetime import datetime
            # Store report paths as relative to project (portable)
            reports_rel = {}
            for fmt, p in report_paths.items():
                if p:
                    try:
                        reports_rel[fmt] = os.path.relpath(p, SCRIPT_DIR)
                    except ValueError:
                        reports_rel[fmt] = p  # Fallback to absolute if different drives (Windows)
            entry = {
                "path": path,
                "name": os.path.basename(path),
                "date": datetime.now().isoformat(),
                "score": analysis.get("risk_score", 0),
                "level": analysis.get("risk_level", "LOW"),
                "badges": analysis.get("badges", []),
                "reports": reports_rel,
            }
            history.insert(0, entry)
            history = history[:100]
            with open(HISTORY_FILE, "w", encoding="utf-8") as f:
                json.dump(history, f, indent=2, ensure_ascii=False)
        except Exception:
            pass

    def show_history(self):
        """Affiche l'historique des analyses."""
        if not os.path.isfile(HISTORY_FILE):
            messagebox.showinfo("History", "No analyses recorded.")
            return
        try:
            with open(HISTORY_FILE, "r", encoding="utf-8") as f:
                history = json.load(f)
        except Exception as e:
            messagebox.showerror("Error", str(e))
            return
        win = tk.Toplevel(self.root)
        win.title("Analysis history")
        win.geometry("600x400")
        win.configure(bg=DARK["bg"])
        tree = ttk.Treeview(win, columns=("Nom", "Date", "Score", "Level"), show="headings", height=15)
        tree.heading("Nom", text="Name")
        tree.heading("Date", text="Date")
        tree.heading("Score", text="Score")
        tree.heading("Level", text="Level")
        tree.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        def on_double_click(ev):
            sel = tree.selection()
            if sel:
                idx = tree.index(sel[0])
                if idx < len(history):
                    h = history[idx]
                    reports = h.get("reports", {})
                    path = reports.get("html") or reports.get("md")
                    if path:
                        # Resolve relative paths (stored from project root)
                        full_path = os.path.join(SCRIPT_DIR, path) if not os.path.isabs(path) else path
                        if os.path.isfile(full_path):
                            url = "file:///" + full_path.replace("\\", "/")
                            webbrowser.open(url)
                        else:
                            messagebox.showwarning("File not found", f"Report not found:\n{full_path}")

        tree.bind("<Double-1>", on_double_click)
        for h in history:
            tree.insert("", "end", values=(h.get("name", "?"), h.get("date", "?")[:19], h.get("score", "?"), h.get("level", "?")))

    def compare_files(self):
        """Compares two files (hashes, strings)."""
        path1 = filedialog.askopenfilename(title="File 1")
        if not path1:
            return
        path2 = filedialog.askopenfilename(title="File 2")
        if not path2 or path2 == path1:
            return
        if not analyzer:
            messagebox.showerror("Error", "Module malware_analyzer not found.")
            return
        h1 = analyzer.calculate_hash(path1)
        h2 = analyzer.calculate_hash(path2)
        s1 = set(analyzer.extract_strings(path1, 6))
        s2 = set(analyzer.extract_strings(path2, 6))
        inter = s1 & s2
        diff1 = s1 - s2
        diff2 = s2 - s1
        lines = [
            "=== COMPARISON ===",
            f"File 1: {path1}",
            f"SHA256: {h1}",
            f"File 2: {path2}",
            f"SHA256: {h2}",
            "",
            f"Identical hashes: {'Yes' if h1 == h2 else 'No'}",
            f"Common strings: {len(inter)}",
            f"Strings only in file 1: {len(diff1)}",
            f"Strings only in file 2: {len(diff2)}",
            "",
            "Sample of common strings (10):",
        ]
        for s in list(inter)[:10]:
            lines.append(f"  {s[:80]}")
        self._append_output("\n".join(lines), clear=True)

    def toggle_api_key(self):
        if self.api_key:
            self.api_entry.delete(0, tk.END)
            self.api_key = ""
            self.api_button.config(text="Save")
            self.start_scan_button.config(state=tk.DISABLED)
            if "API" in self.config and "key" in self.config["API"]:
                del self.config["API"]["key"]
                with open(CONFIG_PATH, "w") as f:
                    self.config.write(f)
        else:
            key = self.api_entry.get().strip()
            if key:
                self.api_key = key
                self.api_button.config(text="Remove key")
                self.start_scan_button.config(state=tk.NORMAL)
                if "API" not in self.config:
                    self.config.add_section("API")
                self.config.set("API", "key", self.api_key)
                with open(CONFIG_PATH, "w") as f:
                    self.config.write(f)
            else:
                messagebox.showerror("Error", "VirusTotal API key cannot be empty.")

    def insert_result(self, number, name, size, detection, location, permalink):
        self.result_tree.insert("", "end", values=(number, name, size, detection, location), tags=(permalink,))

    def open_report_url(self, event):
        item = self.result_tree.selection()
        if item:
            tags = self.result_tree.item(item[0], "tags")
            if tags and tags[0] != "-":
                try:
                    webbrowser.open_new(tags[0])
                except Exception:
                    pass

    def generate_report(self):
        items = self.result_tree.get_children()
        if not items:
            messagebox.showinfo("Info", "No results to generate the report.")
            return
        scan_results = []
        for item in items:
            vals = self.result_tree.item(item, "values")
            tags = self.result_tree.item(item, "tags")
            scan_results.append({
                "number": vals[0], "name": vals[1], "size": vals[2],
                "detection": vals[3], "location": vals[4],
                "permalink": tags[0] if tags else "-"
            })
        tpl = """
<!DOCTYPE html>
<html>
<head><meta charset="utf-8"><title>Scan Report</title>
<style>body{font-family:Arial,sans-serif}table{border-collapse:collapse;width:100%}
th,td{border:1px solid #ddd;padding:8px}th{background:#f2f2f2}</style>
</head>
<body><h1>Scan Report</h1>
<table><tr><th>#</th><th>Name</th><th>Size</th><th>Detection</th><th>Location</th><th>Link</th></tr>
{% for r in scan_results %}
<tr><td>{{ r.number }}</td><td>{{ r.name }}</td><td>{{ r.size }}</td><td>{{ r.detection }}</td><td>{{ r.location }}</td><td><a href="{{ r.permalink }}" target="_blank">Open</a></td></tr>
{% endfor %}
</table></body></html>
"""
        out_path = os.path.join(SCRIPT_DIR, "scan_report.html")
        with open(out_path, "w", encoding="utf-8") as f:
            f.write(Template(tpl).render(scan_results=scan_results))
        messagebox.showinfo("Info", f"Report generated: {out_path}")

    def format_size(self, size_bytes):
        for u in ["B", "KB", "MB", "GB"]:
            if size_bytes < 1024.0:
                return f"{size_bytes:.2f} {u}"
            size_bytes /= 1024.0
        return f"{size_bytes:.2f} TB"

    def start_scan(self):
        if not self.directory_path or not os.path.isdir(self.directory_path):
            messagebox.showwarning("Warning", "Select a folder to scan.")
            return
        self.result_tree.delete(*self.result_tree.get_children())
        self.scan_queue.queue.clear()
        for r, _, files in os.walk(self.directory_path):
            for f in files:
                self.scan_queue.put(os.path.join(r, f))
        if not self.scan_thread or not self.scan_thread.is_alive():
            self.scan_thread = threading.Thread(target=self.scan_files)
            self.scan_thread.start()
            self.start_scan_button.config(state=tk.DISABLED)
            self.stop_scan_button.config(state=tk.NORMAL)

    def stop_scan(self):
        self.should_stop = True
        self.stop_scan_button.config(state=tk.DISABLED)
        self.print_report_button.config(state=tk.NORMAL)

    def update_label(self, file_path):
        self.current_file_label.config(text=f"In progress: {os.path.basename(file_path)}")
        self.root.update()

    def scan_files(self):
        wait_time = int(self.wait_time_entry.get() or "20")
        files_to_rescan = list(self.scan_queue.queue)
        scan_number = 1
        while files_to_rescan and not self.should_stop:
            file_path = files_to_rescan.pop(0)
            self.update_label(file_path)
            h = self.calculate_hash(file_path)
            try:
                report = self.get_scan_report(h)
                time.sleep(wait_time)
                if report and "positives" in report:
                    self.insert_result(scan_number, os.path.basename(file_path), self.format_size(os.path.getsize(file_path)),
                                       f"{report['positives']}/{report['total']}", file_path, report.get("permalink", "-"))
                    scan_number += 1
                else:
                    resp = self.upload_to_virustotal(file_path)
                    if resp and "resource" in resp:
                        files_to_rescan.append(file_path)
                    self.insert_result(scan_number, os.path.basename(file_path), self.format_size(os.path.getsize(file_path)),
                                       f"{resp.get('positives', 0)}/{resp.get('total', 0)}" if resp else "-", file_path, resp.get("permalink", "-") if resp else "-")
                    scan_number += 1
                time.sleep(wait_time)
            except requests.exceptions.RequestException:
                messagebox.showerror("Error", "Invalid VirusTotal API key or too many requests. Increase the delay.")
                break
        self.should_stop = False
        self.current_file_label.config(text="Scan complete")
        self.stop_scan_button.config(state=tk.DISABLED)
        self.start_scan_button.config(state=tk.NORMAL)
        self.print_report_button.config(state=tk.NORMAL)

    def get_scan_report(self, resource):
        if not self.api_key:
            return None
        r = requests.get("https://www.virustotal.com/vtapi/v2/file/report", params={"apikey": self.api_key, "resource": resource})
        return r.json()

    def upload_to_virustotal(self, file_path):
        if not self.api_key:
            return None
        wait_time = int(self.wait_time_entry.get() or "20")
        url_scan = "https://www.virustotal.com/vtapi/v2/file/scan"
        url_report = "https://www.virustotal.com/vtapi/v2/file/report"
        try:
            with open(file_path, "rb") as f:
                r = requests.post(url_scan, params={"apikey": self.api_key},
                                  files={"file": (os.path.basename(file_path), f)})
            data = r.json()
            scan_id = data.get("scan_id") or data.get("resource")
            if not scan_id:
                return None
            while True:
                rep = requests.get(url_report, params={"apikey": self.api_key, "resource": scan_id}).json()
                if rep.get("response_code") == 1:
                    return rep
                if rep.get("response_code") != -2:
                    return None
                time.sleep(wait_time)
        except Exception:
            return None

    def calculate_hash(self, file_path):
        h = hashlib.sha256()
        with open(file_path, "rb") as f:
            for block in iter(lambda: f.read(4096), b""):
                h.update(block)
        return h.hexdigest()


if __name__ == "__main__":
    root = tk.Tk()
    app = MalwareAnalyzerGUI(root)
    root.mainloop()
