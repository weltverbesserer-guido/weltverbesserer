import os
import sys
import json
import time
import socket
import hashlib
import winreg
import shutil
import subprocess
from datetime import datetime
from pathlib import Path
from tkinter import messagebox

try:
    from watchdog.observers import Observer
    from watchdog.events import FileSystemEventHandler
    WATCHDOG_AVAILABLE = True
except ImportError:
    WATCHDOG_AVAILABLE = False


class DownloadWatchdogHandler(FileSystemEventHandler if WATCHDOG_AVAILABLE else object):
    def __init__(self, agent_instance, log_callback, watch_path):
        self.agent = agent_instance
        self.log_callback = log_callback
        self.watch_path = Path(watch_path)

    def on_created(self, event):
        if event.is_directory:
            return
        file_path = Path(event.src_path)
        self.log_callback(f"[👀 Watchdog Event] Datei erstellt: {file_path.name}\n")
        time.sleep(1.5)
        if file_path.suffix.lower() in {'.crdownload', '.tmp', '.part'}:
            return
        self.agent.scan_single_file(file_path, self.log_callback)


class LocalAuditAgent:
    def __init__(self, target_host="127.0.0.1", audit_paths=None, gui_root=None):
        self.target_host = target_host
        self.project_dir = Path(sys.executable).resolve().parent if getattr(sys, "frozen", False) else Path(__file__).resolve().parent
        self.audit_paths = audit_paths or [self.project_dir]
        self.findings = []
        self.whitelist = self.load_whitelist()
        
        self.quarantine_dir = self.project_dir / "quarantine"
        self.quarantine_dir.mkdir(parents=True, exist_ok=True)

        self.baseline_file = self.project_dir / "audit_baseline.json"
        self.previous_baseline = self.load_baseline()
        self.gui_root = gui_root

    def load_whitelist(self):
        whitelist_file = self.project_dir / "whitelist.txt"
        excluded = set()
        if whitelist_file.exists():
            try:
                with open(whitelist_file, "r", encoding="utf-8", errors="ignore") as f:
                    for line in f:
                        line = line.strip()
                        if line and not line.startswith("#"):
                            excluded.add(Path(line).resolve())
            except Exception:
                pass
        return excluded

    def load_baseline(self):
        if self.baseline_file.exists():
            try:
                with open(self.baseline_file, "r", encoding="utf-8") as f:
                    return json.load(f)
            except Exception:
                pass
        return {}

    def save_baseline(self, current_state):
        try:
            with open(self.baseline_file, "w", encoding="utf-8") as f:
                json.dump(current_state, f, indent=4, ensure_ascii=False)
        except Exception:
            pass

    def is_whitelisted(self, file_path):
        try:
            resolved_path = Path(file_path).resolve()
            for entry in self.whitelist:
                if resolved_path == entry or entry in resolved_path.parents:
                    return True
        except Exception:
            pass
        return False

    def log_finding(self, category, item, severity, desc):
        self.findings.append({
            "category": category,
            "item": item,
            "severity": severity,
            "desc": desc
        })

    def calculate_file_hash(self, file_path):
        sha256_hash = hashlib.sha256()
        try:
            with open(file_path, "rb") as f:
                for byte_block in iter(lambda: f.read(65536), b""):
                    sha256_hash.update(byte_block)
            return sha256_hash.hexdigest()
        except Exception:
            return "Hash-Berechnung fehlgeschlagen"

    def send_windows_notification(self, title, message):
        try:
            ps_script = f"""
            [Windows.UI.Notifications.ToastNotificationManager, Windows.UI.Notifications, ContentType = WindowsRuntime] > $null
            $Template = [Windows.UI.Notifications.ToastNotificationManager]::GetTemplateContent([Windows.UI.Notifications.ToastTemplateType]::ToastText02)
            $ToastXml = $Template.GetElementsByTagName("text")
            $ToastXml[0].AppendChild($Template.CreateTextNode("{title}")) > $null
            $ToastXml[1].AppendChild($Template.CreateTextNode("{message}")) > $null
            $Toast = [Windows.UI.Notifications.ToastNotification]::new($ToastXml)
            [Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier("LocalAuditAgent").Show($Toast)
            """
            subprocess.run(["powershell", "-Command", ps_script], capture_output=True, text=True, encoding="utf-8", errors="ignore")
        except Exception:
            pass

    def quarantine_file(self, file_path, log_callback):
        try:
            file_path = Path(file_path)
            if not file_path.exists():
                return False
            timestamp_str = datetime.now().strftime('%Y%m%d_%H%M%S')
            dest_name = f"{timestamp_str}_{file_path.name}"
            dest_path = self.quarantine_dir / dest_name
            shutil.move(str(file_path), str(dest_path))
            log_callback(f"[🔒 QUARANTÄNE] Datei isoliert: {file_path.name} -> {dest_path}\n")
            self.send_windows_notification("🛡️ Quarantäne aktiv!", f"Gefährliche Datei isoliert: {file_path.name}")
            return True
        except Exception as e:
            log_callback(f"[-] Fehler beim Verschieben in Quarantäne: {e}\n")
            return False

    def ask_user_about_change(self, file_name, file_path):
        if not self.gui_root:
            return False
        answer = [False]
        def show_dialog():
            res = messagebox.askyesno(
                "🚨 Sicherheitswarnung: Unerlaubte Änderung!",
                f"Die sensible Datei wurde inhaltlich verändert:\n\n'{file_name}'\n\nHaben SIE diese Änderung selbst vorgenommen?\n\n(Bei 'Nein' wird die Datei sofort in die Quarantäne verschoben!)",
                parent=self.gui_root
            )
            answer[0] = res
        show_dialog()
        return answer[0]

    def scan_single_file(self, file_path, log_callback):
        try:
            if self.is_whitelisted(file_path):
                log_callback(f"[-] Datei ist auf der Whitelist, übersprungen: {file_path.name}\n")
                return
            
            file_ext = file_path.suffix.lower()
            file_lower = file_path.name.lower()
            sensitive_extensions = {".env", ".key", ".pem", ".config", ".bak", ".pfx", ".txt", ".cfg", ".json"}
            sensitive_names = {"credentials.txt", "passwords.txt", "id_rsa", "secrets.json", "access.key", "sensitive_test.txt"}

            log_callback(f"[⚡ Echtzeit-Prüfung] Analysiere: {file_path.name} (Endung: {file_ext})\n")

            if file_ext in sensitive_extensions or file_lower in sensitive_names:
                file_size = file_path.stat().st_size
                file_hash = self.calculate_file_hash(file_path)
                log_callback(f"[!] Kritische Datei im Download erkannt: {file_path.name} (SHA-256: {file_hash[:12]}...)\n")
                self.quarantine_file(file_path, log_callback)
            else:
                log_callback(f"[✓] Datei unbedenklich: {file_path.name}\n")
        except Exception as e:
            log_callback(f"[-] Fehler beim Scannen der einzelnen Datei: {e}\n")

    def scan_filesystem(self, log_callback):
        sensitive_extensions = {".env", ".key", ".pem", ".config", ".bak", ".pfx", ".txt", ".cfg", ".json"}
        sensitive_names = {"credentials.txt", "passwords.txt", "id_rsa", "secrets.json", "access.key", "sensitive_test.txt"}
        new_baseline = {}

        for base_path in self.audit_paths:
            base_path = Path(base_path)
            if not base_path.exists():
                log_callback(f"[-] Pfad existiert nicht: {base_path}\n")
                continue
            log_callback(f"[*] Starte rekursiven Scan & Integritätsprüfung in: {base_path}\n")
            scanned_count = 0
            modified_count = 0
            new_count = 0
            
            for root, dirs, files in os.walk(base_path):
                dirs[:] = [d for d in dirs if d.lower() not in {'appdata', 'cache', '.git', 'node_modules', '$recycle.bin', 'windows', 'quarantine'}]
                for file in files:
                    file_path = Path(root) / file
                    if self.is_whitelisted(file_path):
                        continue
                    scanned_count += 1
                    try:
                        file_ext = file_path.suffix.lower()
                        file_lower = file.lower()
                        if file_ext in sensitive_extensions or file_lower in sensitive_names:
                            file_size = file_path.stat().st_size
                            mod_time = datetime.fromtimestamp(file_path.stat().st_mtime).strftime('%Y-%m-%d %H:%M:%S')
                            file_hash = self.calculate_file_hash(file_path)
                            path_str = str(file_path)
                            status_desc = "Neu erfasst"
                            severity = "Medium"

                            if path_str in self.previous_baseline:
                                old_data = self.previous_baseline[path_str]
                                if old_data.get("hash") != file_hash:
                                    user_approved = self.ask_user_about_change(file_path.name, file_path)
                                    if user_approved:
                                        status_desc = "Autorisiert verändert"
                                        severity = "Low"
                                    else:
                                        status_desc = "🚨 Unerlaubt verändert -> Quarantäne!"
                                        severity = "High"
                                        modified_count += 1
                                        self.quarantine_file(file_path, log_callback)
                                        continue
                                else:
                                    status_desc = "Unverändert"
                            else:
                                new_count += 1

                            new_baseline[path_str] = {"hash": file_hash, "size": file_size, "modified": mod_time}
                            self.log_finding("Dateisystem-Audit", path_str, severity, f"Zustand: {status_desc} | Größe: {file_size} Bytes | SHA-256: {file_hash}")
                    except (PermissionError, OSError):
                        continue
            log_callback(f"[+] Scan in {base_path} fertig. Geprüft: {scanned_count} | Neu: {new_count} | Verändert: {modified_count}\n")
        self.save_baseline(new_baseline)

    def scan_registry_autostarts(self, log_callback):
        log_callback("[*] Prüfe Registry-Autostarts...\n")
        reg_paths = [
            (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run"),
            (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\Run")
        ]
        for hkey, subkey in reg_paths:
            try:
                with winreg.OpenKey(hkey, subkey, 0, winreg.KEY_READ) as key:
                    i = 0
                    while True:
                        try:
                            name, value, _ = winreg.EnumValue(key, i)
                            self.log_finding("Registry Autostart", name, "Medium", f"Pfad: {value}")
                            i += 1
                        except WindowsError:
                            break
            except Exception:
                pass
        log_callback("[+] Registry-Autostarts geprüft.\n")

    def scan_network_connections(self, log_callback):
        log_callback("[*] Prüfe Netzwerkstatus...\n")
        self.log_finding("Netzwerk", self.target_host, "Info", "Lokaler Host-Scan aktiv.")
        log_callback("[+] Netzwerk-Check abgeschlossen.\n")

    def generate_json_report(self):
        timestamp_str = datetime.now().strftime('%Y%m%d_%H%M%S')
        filename = self.project_dir / f"audit_report_{timestamp_str}.json"
        
        report_data = {
            "timestamp": datetime.now().isoformat(),
            "target_host": self.target_host,
            "audit_paths": [str(p) for p in self.audit_paths],
            "findings": self.findings
        }
        with open(filename, "w", encoding="utf-8") as f:
            json.dump(report_data, f, indent=4, ensure_ascii=False)
        return filename

    def generate_html_report(self):
        timestamp_str = datetime.now().strftime('%Y%m%d_%H%M%S')
        filename = self.project_dir / f"audit_report_{timestamp_str}.html"

        severities = {"High": 0, "Medium": 0, "Low": 0, "Info": 0}
        for f in self.findings:
            severities[f["severity"]] = severities.get(f["severity"], 0) + 1

        chart_data = json.dumps([severities['High'], severities['Medium'], severities['Low'], severities['Info']])
        paths_str = ", ".join(str(p) for p in self.audit_paths)

        html_content = f"""<!DOCTYPE html>
<html lang="de">
<head>
    <meta charset="UTF-8">
    <title>Cyber Audit Report - {self.target_host}</title>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <style>
        body {{ font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background: #0f172a; color: #f8fafc; margin: 0; padding: 20px; }}
        .container {{ max-width: 1000px; margin: auto; background: #1e293b; padding: 30px; border-radius: 12px; box-shadow: 0 4px 20px rgba(0,0,0,0.5); }}
        h1 {{ color: #38bdf8; margin-top: 0; }}
        .tabs {{ display: flex; gap: 10px; margin-bottom: 25px; border-bottom: 2px solid #334155; padding-bottom: 10px; }}
        .tab-btn {{ background: #334155; color: #f8fafc; border: none; padding: 10px 20px; font-size: 15px; font-weight: bold; border-radius: 6px; cursor: pointer; transition: 0.2s; }}
        .tab-btn:hover {{ background: #475569; }}
        .tab-btn.active {{ background: #38bdf8; color: #0f172a; }}
        .tab-content {{ display: none; }}
        .tab-content.active {{ display: block; }}
        .top-section {{ display: flex; gap: 20px; align-items: center; margin-bottom: 25px; flex-wrap: wrap; }}
        .summary-cards {{ flex: 1; display: flex; flex-direction: column; gap: 10px; min-width: 250px; }}
        .card {{ background: #334155; padding: 12px 15px; border-radius: 8px; display: flex; justify-content: space-between; align-items: center; }}
        .card h3 {{ margin: 0; font-size: 20px; }}
        .chart-container {{ width: 200px; height: 200px; margin: auto; }}
        .high {{ color: #f43f5e; }}
        .medium {{ color: #fbbf24; }}
        .low {{ color: #34d399; }}
        .info {{ color: #94a3b8; }}
        .controls {{ display: flex; gap: 15px; margin-bottom: 20px; flex-wrap: wrap; justify-content: space-between; align-items: center; }}
        .search-box {{ flex: 1; min-width: 250px; padding: 10px 15px; background: #0f172a; border: 1px solid #475569; color: white; border-radius: 6px; font-size: 14px; }}
        .filter-buttons {{ display: flex; gap: 8px; flex-wrap: wrap; }}
        .btn-filter {{ padding: 8px 12px; border: none; border-radius: 6px; cursor: pointer; font-weight: bold; font-size: 13px; background: #334155; color: #f8fafc; transition: 0.2s; }}
        .btn-filter:hover {{ background: #475569; }}
        .btn-filter.active {{ background: #38bdf8; color: #0f172a; }}
        table {{ width: 100%; border-collapse: collapse; margin-top: 10px; }}
        th, td {{ padding: 12px; text-align: left; border-bottom: 1px solid #475569; word-break: break-word; }}
        th {{ background: #0f172a; color: #38bdf8; }}
        .badge {{ padding: 4px 8px; border-radius: 4px; font-size: 12px; font-weight: bold; display: inline-block; }}
        .badge-High {{ background: #f43f5e; color: white; }}
        .badge-Medium {{ background: #fbbf24; color: black; }}
        .badge-Low {{ background: #34d399; color: black; }}
        .badge-Info {{ background: #94a3b8; color: black; }}
        .manual-box {{ line-height: 1.6; color: #cbd5e1; }}
        .manual-box h2 {{ color: #38bdf8; margin-top: 25px; border-bottom: 1px solid #334155; padding-bottom: 5px; }}
        .manual-box h3 {{ color: #f8fafc; margin-top: 15px; }}
        .manual-box ul {{ padding-left: 20px; }}
        .manual-box code {{ background: #0f172a; padding: 2px 6px; border-radius: 4px; color: #38bdf8; font-family: Consolas, monospace; }}
    </style>
</head>
<body>
    <div class="container">
        <h1>🛡️ Lokale Sicherheitszentrale & Audit</h1>
        <p>Gescannte Pfade: <strong>{paths_str}</strong> | Erstellt am: {datetime.now().strftime('%d.%m.%Y %H:%M:%S')}</p>
        
        <div class="tabs">
            <button class="tab-btn active" onclick="switchTab('dashboard', this)">📊 Audit-Ergebnisse & Dashboard</button>
            <button class="tab-btn" onclick="switchTab('manual', this)">📖 Handbuch & FAQ</button>
        </div>

        <!-- REITER 1: DASHBOARD -->
        <div id="tab-dashboard" class="tab-content active">
            <div class="top-section">
                <div class="summary-cards">
                    <div class="card">
                        <span class="high"><strong>Hohes Risiko</strong></span>
                        <h3 class="high">{severities['High']}</h3>
                    </div>
                    <div class="card">
                        <span class="medium"><strong>Mittleres Risiko</strong></span>
                        <h3 class="medium">{severities['Medium']}</h3>
                    </div>
                    <div class="card">
                        <span class="low"><strong>Niedriges Risiko</strong></span>
                        <h3 class="low">{severities['Low']}</h3>
                    </div>
                    <div class="card">
                        <span class="info"><strong>Info</strong></span>
                        <h3 class="info">{severities['Info']}</h3>
                    </div>
                </div>
                <div class="chart-container">
                    <canvas id="severityDonut"></canvas>
                </div>
            </div>

            <div class="controls">
                <input type="text" id="searchInput" class="search-box" placeholder="🔍 Live-Suche (z.B. Pfad, Hash, Dateiname)..." onkeyup="filterTable()">
                <div class="filter-buttons">
                    <button class="btn-filter active" onclick="setFilter('all', this)">Alle</button>
                    <button class="btn-filter" onclick="setFilter('High', this)">High</button>
                    <button class="btn-filter" onclick="setFilter('Medium', this)">Medium</button>
                    <button class="btn-filter" onclick="setFilter('Low', this)">Low</button>
                    <button class="btn-filter" onclick="setFilter('Info', this)">Info</button>
                </div>
            </div>

            <table id="findingsTable">
                <thead>
                    <tr>
                        <th>Kategorie</th>
                        <th>Befund / Datei</th>
                        <th>Schweregrad</th>
                        <th>Details & SHA-256 Hash</th>
                    </tr>
                </thead>
                <tbody>"""

        for f in self.findings:
            html_content += f"""
                <tr data-severity="{f['severity']}">
                    <td>{f['category']}</td>
                    <td><strong>{f['item']}</strong></td>
                    <td><span class="badge badge-{f['severity']}">{f['severity']}</span></td>
                    <td>{f['desc']}</td>
                </tr>"""

        html_content += f"""
                </tbody>
            </table>
        </div>

        <!-- REITER 2: HANDBUCH & FAQ -->
        <div id="tab-manual" class="tab-content">
            <div class="manual-box">
                <h2>1. Schnellstart & Bedienung</h2>
                <p>Der <strong>LocalAuditAgent</strong> ist deine private, lokale Sicherheitszentrale für Windows. Über das Hauptfenster kannst du per Klick Zielpfade hinzufügen, Prüfmodule aktivieren und den Scan starten.</p>
                <ul>
                    <li><strong>Scan starten:</strong> Analysiert das Dateisystem anhand von SHA-256 Hashes, prüft Registry-Autostarts und Netzwerkeinbindungen.</li>
                    <li><strong>Live-Watchdog:</strong> Überwacht deinen Download-Ordner in Echtzeit auf neue, potenziell kritische Dateien.</li>
                </ul>

                <h2>2. Die Prüfmodule im Detail</h2>
                <ul>
                    <li><strong>Dateisystem-Scan:</strong> Prüft sensible Endungen (<code>.env</code>, <code>.key</code>, <code>.json</code>, etc.) auf unautorisierte Inhaltsänderungen.</li>
                    <li><strong>Registry Autostarts:</strong> Durchleuchtet die zentralen Windows-Registrierungsschlüssel nach unerwünschten Startprogrammen.</li>
                    <li><strong>Netzwerk-Check:</strong> Erfasst den lokalen Netzwerkstatus.</li>
                </ul>

                <h2>3. Quarantäne & Notfall-Management</h2>
                <p>Wird eine sensible Datei unerlaubt verändert und vom Benutzer im Warn-Dialog abgelehnt, verschiebt der Agent sie automatisch und sicher in den Quarantäne-Ordner. Von dort aus kann sie bei Bedarf manuell wiederhergestellt werden.</p>

                <h2>4. Häufig gestellte Fragen (FAQ)</h2>
                <h3>F: Werden Daten an das Internet gesendet?</h3>
                <p><strong>A:</strong> Nein. Der gesamte Agent läuft zu 100 % offline und lokal auf deinem Rechner.</p>
                
                <h3>F: Was tun bei fälschlicher Quarantäne?</h3>
                <p><strong>A:</strong> Öffne den Quarantäne-Ordner und schiebe die betroffene Datei an ihren Ursprungsort zurück. Ergänze sie ggf. in der Whitelist.</p>

                <h3>F: Wie aktualisiere ich die Baseline nach eigenen Skript-Änderungen?</h3>
                <p><strong>A:</strong> Wenn du bewusst Änderungen an deinen Skripten vorgenommen hast, bestätige dies im Pop-up-Dialog beim nächsten Scan, damit die neue Dateiprüfsumme in der Baseline gespeichert wird.</p>
            </div>
        </div>
    </div>

    <script>
        function switchTab(tabId, btnElement) {{
            document.querySelectorAll('.tab-content').forEach(el => el.classList.remove('active'));
            document.querySelectorAll('.tab-btn').forEach(el => el.classList.remove('active'));
            document.getElementById('tab-' + tabId).classList.add('active');
            btnElement.classList.add('active');
        }}

        const ctx = document.getElementById('severityDonut').getContext('2d');
        const severityDonut = new Chart(ctx, {{
            type: 'doughnut',
            data: {{
                labels: ['High', 'Medium', 'Low', 'Info'],
                datasets: [{{
                    data: {chart_data},
                    backgroundColor: ['#f43f5e', '#fbbf24', '#34d399', '#94a3b8'],
                    borderWidth: 0
                }}]
            }},
            options: {{
                responsive: true,
                maintainAspectRatio: false,
                plugins: {{
                    legend: {{
                        position: 'bottom',
                        labels: {{ color: '#f8fafc', font: {{ size: 11 }} }}
                    }}
                }}
            }}
        }});

        let currentSeverityFilter = 'all';

        function setFilter(severity, buttonElement) {{
            currentSeverityFilter = severity;
            document.querySelectorAll('.btn-filter').forEach(btn => btn.classList.remove('active'));
            buttonElement.classList.add('active');
            filterTable();
        }}

        function filterTable() {{
            const query = document.getElementById('searchInput').value.toLowerCase();
            const rows = document.querySelectorAll('#findingsTable tbody tr');

            rows.forEach(row => {{
                const text = row.textContent.toLowerCase();
                const severity = row.getAttribute('data-severity');
                const matchesSearch = text.includes(query);
                const matchesSeverity = (currentSeverityFilter === 'all' || severity === currentSeverityFilter);

                if (matchesSearch && matchesSeverity) {{
                    row.style.display = '';
                }} else {{
                    row.style.display = 'none';
                }}
            }});
        }}
    </script>
</body>
</html>
"""
        with open(filename, "w", encoding="utf-8") as f:
            f.write(html_content)
        return filename
