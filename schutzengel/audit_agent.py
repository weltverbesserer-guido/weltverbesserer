import os
import sys
import json
import time
import threading
import webbrowser
import subprocess
from datetime import datetime
from pathlib import Path
import tkinter as tk
from tkinter import messagebox, scrolledtext, filedialog

from core import LocalAuditAgent, WATCHDOG_AVAILABLE, DownloadWatchdogHandler, Observer

try:
    import pystray
    from PIL import Image, ImageDraw
    TRAY_AVAILABLE = True
except ImportError:
    TRAY_AVAILABLE = False


class AuditApp:
    def __init__(self, root):
        self.root = root
        self.root.title("LocalAuditAgent - Secure Control Center")
        self.root.geometry("880x800")
        self.root.configure(bg="#0b0f19")

        self.project_dir = Path(sys.executable).resolve().parent if getattr(sys, "frozen", False) else Path(__file__).resolve().parent
        self.latest_html_report = None
        self.observer = None
        self.agent = None
        self.current_paths = [str(self.project_dir)]
        self.tray_icon = None

        self.root.protocol("WM_DELETE_WINDOW", self.hide_to_tray)

        main_frame = tk.Frame(root, bg="#0b0f19")
        main_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=15)

        header_frame = tk.Frame(main_frame, bg="#0b0f19")
        header_frame.pack(fill=tk.X, pady=(0, 10))

        title_label = tk.Label(header_frame, text="🛡️ LocalAuditAgent", font=("Segoe UI", 18, "bold"), bg="#0b0f19", fg="#38bdf8")
        title_label.pack(side=tk.LEFT)

        subtitle_label = tk.Label(header_frame, text="Private Security & Integrity Center", font=("Segoe UI", 10), bg="#0b0f19", fg="#64748b")
        subtitle_label.pack(side=tk.LEFT, padx=10, pady=(6, 0))

        # Zielpfade Karte
        path_card = tk.LabelFrame(main_frame, text=" Überwachte Zielpfade ", font=("Segoe UI", 9, "bold"), bg="#111827", fg="#38bdf8", bd=1, relief=tk.SOLID)
        path_card.pack(fill=tk.X, pady=(0, 10), ipadx=10, ipady=8)

        path_inner = tk.Frame(path_card, bg="#111827")
        path_inner.pack(fill=tk.X, padx=10, pady=5)

        self.path_entry = tk.Entry(path_inner, font=("Segoe UI", 10), bg="#1f2937", fg="#f8fafc", insertbackground="white", bd=1, relief=tk.SOLID)
        self.path_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 10))
        self.update_path_entry()

        browse_btn = tk.Button(path_inner, text="📁 Ordner hinzufügen", font=("Segoe UI", 9, "bold"), bg="#374151", fg="#f8fafc", activebackground="#4b5563", activeforeground="white", bd=0, padx=12, pady=6, cursor="hand2", command=self.add_directory)
        browse_btn.pack(side=tk.LEFT)

        # Prüfmodule & Automatisierung Grid
        config_grid = tk.Frame(main_frame, bg="#0b0f19")
        config_grid.pack(fill=tk.X, pady=(0, 10))
        config_grid.columnconfigure(0, weight=1)
        config_grid.columnconfigure(1, weight=1)

        modules_card = tk.LabelFrame(config_grid, text=" Aktive Prüfmodule ", font=("Segoe UI", 9, "bold"), bg="#111827", fg="#38bdf8", bd=1, relief=tk.SOLID)
        modules_card.grid(row=0, column=0, sticky="nsew", padx=(0, 5), ipadx=10, ipady=8)

        mod_inner = tk.Frame(modules_card, bg="#111827")
        mod_inner.pack(fill=tk.BOTH, padx=10, pady=5)

        self.var_fs = tk.BooleanVar(value=True)
        self.var_reg = tk.BooleanVar(value=True)
        self.var_net = tk.BooleanVar(value=True)

        tk.Checkbutton(mod_inner, text="Dateisystem (Integrität)", variable=self.var_fs, font=("Segoe UI", 9), bg="#111827", fg="#f8fafc", selectcolor="#1f2937", activebackground="#111827", activeforeground="#38bdf8", anchor="w").pack(fill=tk.X, pady=2)
        tk.Checkbutton(mod_inner, text="Registry Autostarts", variable=self.var_reg, font=("Segoe UI", 9), bg="#111827", fg="#f8fafc", selectcolor="#1f2937", activebackground="#111827", activeforeground="#38bdf8", anchor="w").pack(fill=tk.X, pady=2)
        tk.Checkbutton(mod_inner, text="Netzwerk-Verbindungen", variable=self.var_net, font=("Segoe UI", 9), bg="#111827", fg="#f8fafc", selectcolor="#1f2937", activebackground="#111827", activeforeground="#38bdf8", anchor="w").pack(fill=tk.X, pady=2)

        auto_card = tk.LabelFrame(config_grid, text=" Automatisierung & Live-Schutz ", font=("Segoe UI", 9, "bold"), bg="#111827", fg="#38bdf8", bd=1, relief=tk.SOLID)
        auto_card.grid(row=0, column=1, sticky="nsew", padx=(5, 0), ipadx=10, ipady=8)

        auto_inner = tk.Frame(auto_card, bg="#111827")
        auto_inner.pack(fill=tk.BOTH, padx=10, pady=5)

        self.var_sched = tk.BooleanVar(value=self.check_existing_task())
        self.var_watchdog = tk.BooleanVar(value=False)

        tk.Checkbutton(auto_inner, text="Wöchentlicher Task (Montags)", variable=self.var_sched, font=("Segoe UI", 9), bg="#111827", fg="#f8fafc", selectcolor="#1f2937", activebackground="#111827", activeforeground="#38bdf8", anchor="w", command=self.toggle_scheduler).pack(fill=tk.X, pady=2)
        tk.Checkbutton(auto_inner, text="Live-Watchdog (Downloads)", variable=self.var_watchdog, font=("Segoe UI", 9), bg="#111827", fg="#f8fafc", selectcolor="#1f2937", activebackground="#111827", activeforeground="#38bdf8", anchor="w", command=self.toggle_watchdog).pack(fill=tk.X, pady=2)

        # Log Konsole
        log_card = tk.LabelFrame(main_frame, text=" Live-Protokoll & Ereignisse ", font=("Segoe UI", 9, "bold"), bg="#111827", fg="#38bdf8", bd=1, relief=tk.SOLID)
        log_card.pack(fill=tk.BOTH, expand=True, pady=(0, 15), ipadx=5, ipady=5)

        log_inner = tk.Frame(log_card, bg="#111827")
        log_inner.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)

        self.log_area = scrolledtext.ScrolledText(log_inner, wrap=tk.WORD, bg="#0f172a", fg="#38bdf8", font=("Consolas", 9), bd=0, highlightthickness=0)
        self.log_area.pack(fill=tk.BOTH, expand=True)

        # Aktions-Buttons
        btn_frame = tk.Frame(main_frame, bg="#0b0f19")
        btn_frame.pack(fill=tk.X, pady=(0, 5))

        self.start_btn = tk.Button(btn_frame, text="🚀 Scan starten", font=("Segoe UI", 10, "bold"), bg="#0284c7", fg="white", activebackground="#0369a1", activeforeground="white", bd=0, padx=16, pady=8, cursor="hand2", command=self.start_audit_thread)
        self.start_btn.pack(side=tk.LEFT, padx=(0, 8))

        self.report_btn = tk.Button(btn_frame, text="📊 Dashboard", font=("Segoe UI", 9, "bold"), bg="#374151", fg="#f8fafc", activebackground="#4b5563", activeforeground="white", bd=0, padx=12, pady=8, cursor="hand2", command=self.open_report)
        self.report_btn.pack(side=tk.LEFT, padx=4)

        self.quarantine_btn = tk.Button(btn_frame, text="📂 Quarantäne", font=("Segoe UI", 9, "bold"), bg="#991b1b", fg="#f8fafc", activebackground="#b91c1c", activeforeground="white", bd=0, padx=12, pady=8, cursor="hand2", command=self.open_quarantine_folder)
        self.quarantine_btn.pack(side=tk.LEFT, padx=4)

        self.whitelist_btn = tk.Button(btn_frame, text="➕ Whitelist", font=("Segoe UI", 9, "bold"), bg="#065f46", fg="#f8fafc", activebackground="#047857", activeforeground="white", bd=0, padx=12, pady=8, cursor="hand2", command=self.add_to_whitelist_gui)
        self.whitelist_btn.pack(side=tk.LEFT, padx=4)

        self.help_btn = tk.Button(btn_frame, text="📖 Handbuch", font=("Segoe UI", 9, "bold"), bg="#4b5563", fg="#f8fafc", activebackground="#6b7280", activeforeground="white", bd=0, padx=12, pady=8, cursor="hand2", command=self.open_manual)
        self.help_btn.pack(side=tk.RIGHT, padx=(4, 0))

        self.thanks_btn = tk.Button(btn_frame, text="\u2764 Dankesch\u00f6n (PayPal)", font=("Segoe UI", 9, "bold"), bg="#b45309", fg="#f8fafc", activebackground="#d97706", activeforeground="white", bd=0, padx=12, pady=8, cursor="hand2", command=self.open_paypal)
        self.thanks_btn.pack(side=tk.RIGHT, padx=(4, 0))

        self.agent = LocalAuditAgent(audit_paths=[Path(p) for p in self.current_paths], gui_root=self.root)

        if TRAY_AVAILABLE:
            threading.Thread(target=self.setup_tray, daemon=True).start()

    def update_path_entry(self):
        self.path_entry.delete(0, tk.END)
        self.path_entry.insert(0, "; ".join(self.current_paths))

    def add_directory(self):
        d = filedialog.askdirectory(title="Weiteren Ordner zum Scan hinzufügen")
        if d and d not in self.current_paths:
            self.current_paths.append(d)
            self.update_path_entry()
            if self.agent:
                self.agent.audit_paths = [Path(p) for p in self.current_paths]

    def log(self, message):
        self.log_area.insert(tk.END, message)
        self.log_area.see(tk.END)

    def check_existing_task(self):
        try:
            result = subprocess.run(["schtasks", "/Query", "/TN", "LocalAuditAgent_AutoScan"], capture_output=True, text=True, encoding="utf-8", errors="ignore")
            return result.returncode == 0
        except Exception:
            return False

    def toggle_scheduler(self):
        task_name = "LocalAuditAgent_AutoScan"
        script_path = str(self.project_dir / "audit_agent.py")
        python_exe = sys.executable

        if self.var_sched.get():
            cmd = f'schtasks /Create /TN "{task_name}" /TR "\"{python_exe}\" \"{script_path}\"" /SC WEEKLY /D MON /ST 08:00 /F'
            res = subprocess.run(cmd, capture_output=True, text=True, shell=True, encoding="utf-8", errors="ignore")
            if res.returncode == 0:
                messagebox.showinfo("Scheduler", "Automatischer Hintergrund-Scan wurde aktiviert.")
            else:
                messagebox.showwarning("Hinweis", "Konnte den Windows-Task nicht anlegen.")
                self.var_sched.set(False)
        else:
            cmd = f'schtasks /Delete /TN "{task_name}" /F'
            subprocess.run(cmd, capture_output=True, text=True, shell=True, encoding="utf-8", errors="ignore")
            messagebox.showinfo("Scheduler", "Automatischer Hintergrund-Scan wurde deaktiviert.")

    def toggle_watchdog(self):
        if not WATCHDOG_AVAILABLE:
            messagebox.showerror("Fehler", "Das Modul 'watchdog' ist nicht installiert.\nBitte führe 'pip install watchdog' in der PowerShell aus.")
            self.var_watchdog.set(False)
            return

        downloads_path = Path.home() / "Downloads"
        if not downloads_path.exists():
            try:
                downloads_path.mkdir(parents=True, exist_ok=True)
            except Exception:
                pass

        if self.var_watchdog.get():
            try:
                event_handler = DownloadWatchdogHandler(self.agent, self.log, downloads_path)
                self.observer = Observer()
                self.observer.schedule(event_handler, path=str(downloads_path), recursive=False)
                self.observer.start()
                self.log(f"[+] Live-Überwachung gestartet für: {downloads_path}\n")
                messagebox.showinfo("Live-Überwachung", f"Echtzeit-Überwachung aktiv!\nNeue Dateien in '{downloads_path}' werden sofort geprüft.")
            except Exception as e:
                messagebox.showerror("Fehler", f"Konnte Watchdog nicht starten: {e}")
                self.var_watchdog.set(False)
                self.observer = None
        else:
            if self.observer:
                try:
                    self.observer.stop()
                    self.observer.join()
                except Exception:
                    pass
                self.observer = None
            self.log("[-] Live-Überwachung beendet.\n")
            messagebox.showinfo("Live-Überwachung", "Echtzeit-Überwachung wurde deaktiviert.")

    def start_audit_thread(self):
        self.start_btn.config(state=tk.DISABLED)
        self.log_area.delete(1.0, tk.END)
        threading.Thread(target=self.run_audit, daemon=True).start()

    def run_audit(self):
        do_fs = self.var_fs.get()
        do_reg = self.var_reg.get()
        do_net = self.var_net.get()

        if do_fs and not self.current_paths:
            messagebox.showerror("Fehler", "Bitte wähle mindestens einen Zielpfad aus.")
            self.start_btn.config(state=tk.NORMAL)
            return

        if not self.agent:
            self.agent = LocalAuditAgent(audit_paths=[Path(p) for p in self.current_paths], gui_root=self.root)

        start_time = time.time()
        self.log(f"=== Audit gestartet: {datetime.now().strftime('%H:%M:%S')} ===\n")
        
        self.agent.audit_paths = [Path(p) for p in self.current_paths]

        if do_fs:
            self.log(f"[*] Aktive Zielpfade:\n" + "\n".join(f"    - {p}" for p in self.current_paths) + "\n")
            self.agent.scan_filesystem(self.log)
        else:
            self.log("[-] Dateisystem-Scan übersprungen (deaktiviert).\n")

        if do_reg:
            self.agent.scan_registry_autostarts(self.log)
        else:
            self.log("[-] Registry-Autostarts übersprungen (deaktiviert).\n")

        if do_net:
            self.agent.scan_network_connections(self.log)
        else:
            self.log("[-] Netzwerk-Check übersprungen (deaktiviert).\n")
        
        json_rep = self.agent.generate_json_report()
        self.latest_html_report = self.agent.generate_html_report()
        
        elapsed_time = round(time.time() - start_time, 2)
        
        self.log(f"\n=== Audit vollständig abgeschlossen in {elapsed_time} Sekunden! ===\n")
        self.log(f"[+] JSON-Report: {json_rep}\n")
        self.log(f"[+] HTML-Report: {self.latest_html_report}\n")
        self.start_btn.config(state=tk.NORMAL)
        messagebox.showinfo("Erfolg", f"Der Sicherheits-Audit wurde in {elapsed_time} Sekunden abgeschlossen!")

    def open_report(self):
        if self.latest_html_report and Path(self.latest_html_report).exists():
            webbrowser.open(str(Path(self.latest_html_report).resolve()))
        else:
            messagebox.showwarning("Warnung", "Es wurde noch kein Report generiert.")

    def open_manual(self):
        manual = self.project_dir / "manual.md"
        if manual.exists():
            os.startfile(str(manual))
        else:
            messagebox.showwarning("Warnung", "manual.md wurde nicht gefunden.")

    def open_paypal(self):
        # Freiwilliges Dankesch\u00f6n \u00fcber PayPal.Me (\u00f6ffnet nur den Browser, keine Daten\u00fcbertragung)
        webbrowser.open("https://www.paypal.me/BiboTheNerd")

    def open_quarantine_folder(self):
        q_path = self.project_dir / "quarantine"
        q_path.mkdir(parents=True, exist_ok=True)
        subprocess.Popen(f'explorer "{q_path.resolve()}"')

    def add_to_whitelist_gui(self):
        file_path = filedialog.askopenfilename(title="Datei zur Whitelist hinzufügen")
        if file_path:
            whitelist_file = self.project_dir / "whitelist.txt"
            try:
                with open(whitelist_file, "a", encoding="utf-8") as f:
                    f.write(f"\n{file_path}")
                if self.agent:
                    self.agent.whitelist = self.agent.load_whitelist()
                messagebox.showinfo("Whitelist", f"Erfolgreich hinzugefügt:\n{file_path}")
                self.log(f"[+] Zur Whitelist hinzugefügt: {file_path}\n")
            except Exception as e:
                messagebox.showerror("Fehler", f"Konnte Datei nicht zur Whitelist hinzufügen: {e}")

    def create_tray_icon_image(self):
        image = Image.new("RGB", (64, 64), color="#0b0f19")
        dc = ImageDraw.Draw(image)
        dc.rectangle([16, 16, 48, 48], fill="#38bdf8")
        return image

    def setup_tray(self):
        icon_image = self.create_tray_icon_image()
        menu = pystray.Menu(
            pystray.MenuItem("Öffnen", self.show_from_tray, default=True),
            pystray.MenuItem("Quarantäne öffnen", lambda: self.open_quarantine_folder()),
            pystray.MenuItem("Beenden", self.exit_application)
        )
        self.tray_icon = pystray.Icon("LocalAuditAgent", icon_image, "LocalAuditAgent (Aktiv)", menu)
        self.tray_icon.run()

    def hide_to_tray(self):
        self.root.withdraw()

    def show_from_tray(self):
        self.root.deiconify()
        self.root.lift()
        self.root.focus_force()

    def exit_application(self):
        if self.tray_icon:
            self.tray_icon.stop()
        if self.observer:
            try:
                self.observer.stop()
                self.observer.join()
            except Exception:
                pass
        self.root.quit()

if __name__ == "__main__":
    root = tk.Tk()
    app = AuditApp(root)
    root.mainloop()
