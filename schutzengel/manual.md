# 🛡️ LocalAuditAgent – Das offizielle Handbuch & FAQ

Willkommen beim **LocalAuditAgent**, deiner privaten, lokalen Sicherheitszentrale für Windows. Dieses Handbuch erklärt alle Funktionen, Module und Best Practices, um deinen PC optimal zu schützen – ganz ohne Cloud-Abhängigkeit oder komplexe Unternehmens-Software.

---

## 📑 Inhaltsverzeichnis
1. [Schnellstart](#1-schnellstart)
2. [Die Module im Detail](#2-die-module-im-detail)
3. [Automatischer Schutz & Live-Überwachung](#3-automatischer-schutz--live-überwachung)
4. [Quarantäne & Notfall-Management](#4-quarantäne--notfall-management)
5. [Häufig gestellte Fragen (FAQ)](#5-häufig-gestellte-fragen-faq)

---

## 1. Schnellstart
* **Starten:** Führe den Agenten über die Konsole mit `python audit_agent.py` im Programmordner aus (Windows, Python 3).
* **Zielpfade wählen:** Über den Button **"📁 Ordner hinzufügen"** kannst du beliebige Verzeichnisse auswählen, die auf sensible Dateien oder Änderungen überwacht werden sollen.
* **Scan ausführen:** Klicke auf **"🚀 Scan starten"**. Nach Abschluss öffnet sich automatisch das HTML-Dashboard im Browser.

---

## 2. Die Module im Detail
* **Dateisystem-Scan:** Prüft rekursiv nach sensiblen Dateiendungen (`.env`, `.key`, `.pem`, `.config`, `.txt`, `.json`) und gleicht sie mit einer Baseline ab. Unautorisierte Änderungen lösen automatisch eine Quarantäne aus.
* **Registry Autostarts:** Überprüft die wichtigsten Autostart-Schlüssel in der Windows-Registry (`Run`), um versteckte Schädlinge oder ungewollte Hintergrundprogramme aufzuspüren.
* **Netzwerk-Check:** Überprüft den lokalen Host-Status und dokumentiert aktive Netzwerkeinbindungen.

---

## 3. Automatischer Schutz & Live-Überwachung
* **Wöchentlicher Hintergrund-Scan:** Über die Checkbox im GUI kannst du den Windows-Taskplaner aktivieren. Der Agent läuft dann jeden Montag um 08:00 Uhr völlig autonom im Hintergrund.
* **Echtzeit-Watchdog (Downloads):** Überwacht deinen `Downloads`-Ordner in Echtzeit. Jede neu heruntergeladene Datei wird unmittelbar nach dem Download im Hintergrund analysiert.

---

## 4. Quarantäne & Notfall-Management
* Verdächtige oder unautorisiert veränderte Dateien werden automatisch aus ihrem Ursprungsordner entfernt und in den Ordner **`quarantine`** verschoben, sodass sie keinen Schaden mehr anrichten können.

---

## 5. Häufig gestellte Fragen (FAQ)

### F: Werden meine Daten an Dritte oder eine Cloud übertragen?
**A:** Das Programm selbst sendet keine Daten und läuft lokal auf deinem Computer. Einzige Ausnahme: Der HTML-Report lädt beim Öffnen im Browser die Diagramm-Bibliothek Chart.js von einem Server (jsDelivr). Dabei werden keine Scan-Daten übertragen, aber deine IP-Adresse an diesen Anbieter.

### F: Was passiert, wenn eine wichtige Datei fälschlicherweise in Quarantäne landet?
**A:** Du kannst den Quarantäne-Ordner (`quarantine`) jederzeit öffnen und die betreffende Datei manuell an ihren Ursprungsort zurückverschieben. Zudem kannst du Dateien per Whitelist (`whitelist.txt`) dauerhaft von der Prüfung ausschließen.

### F: Wie aktualisiere ich den Scan-Zustand (Baseline)?
**A:** Die Baseline (`audit_baseline.json`) speichert den bekannten, sicheren Zustand deiner Dateien. Wenn du bewusste Änderungen an deinen Skripten vorgenommen hast, wird beim nächsten Scan ein Dialog eingeblendet, in dem du bestätigen kannst, dass die Änderung von dir stammt.
