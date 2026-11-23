# Schutzengel (LocalAuditAgent)

Kleines, lokales Sicherheits-Werkzeug für Windows: prüft ausgewählte Ordner auf sensible Dateien und unerlaubte Änderungen, zeigt Autostart-Einträge der Registry und erstellt einen HTML-Report.

Teil der kostenlosen Werkzeuge von [Weltverbesserer](https://weltverbesserer-guido.github.io/weltverbesserer/).

## Wichtig
- Hobby-Projekt, ohne Gewähr. Es ersetzt keinen Virenscanner und keine Firewall.
- Das Programm kann Dateien in den Ordner `quarantine` verschieben. Erst mit einem Testordner ausprobieren, nicht mit wichtigen Daten.
- Nur Windows, Python 3.

## Starten
```
pip install watchdog pystray pillow
python audit_agent.py
```
`watchdog` (Live-Überwachung Downloads) und `pystray`/`pillow` (Tray-Symbol) sind optional.

Mehr dazu im [Handbuch](manual.md).

## Freiwilliges Dankeschön
https://www.paypal.me/BiboTheNerd

Lizenz: GPLv3, wie die übrigen Werkzeuge auf Weltverbesserer.
