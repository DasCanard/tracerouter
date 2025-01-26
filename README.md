# Traceroute Analysis Tool

Ein einfaches Python-Tool zur automatisierten Durchführung von Traceroute-Messungen zu verschiedenen Diensten und Erstellung eines übersichtlichen HTML-Reports.

## Beschreibung

Dieses Tool wurde entwickelt, um Netzwerkprobleme und erhöhte Latenzen zu verschiedenen Online-Diensten zu dokumentieren. Es führt automatisch Traceroute-Messungen zu einer vordefinierten Liste von Domains durch und erstellt einen übersichtlichen HTML-Bericht mit den Ergebnissen. Verbindungen mit einer Latenz über 80ms werden dabei automatisch markiert, um problematische Routen schnell erkennbar zu machen.

### Features

- Automatische Traceroute-Messungen zu verschiedenen Diensten
- Plattformunabhängig (Windows/Linux)
- Zensierung sensitiver Daten (IP-Adressen, Hostnamen)
- Übersichtlicher HTML-Report mit automatischer Markierung von Latenzen >80ms
- Detailliertes Logging für Fehleranalyse
- Erweiterbare Liste von Ziel-Domains
- Anzeigen der Route auf einer Weltkarte

## Voraussetzungen

- Python 3.6 oder höher
- Keine zusätzlichen Python-Pakete erforderlich
- Traceroute (Linux) oder tracert (Windows) muss auf dem System installiert sein

## Installation

1. Repository klonen oder ZIP herunterladen
```bash
git clone https://github.com/DasCanard/tracerouter
```

2. In das Projektverzeichnis wechseln
```bash
cd tracerouter
```

## Verwendung

Einfach das Script ausführen:
```bash
python traceroute_analyzer.py
```

Das Tool erstellt:
- Eine HTML-Datei (`traceroute_report.html`) mit den Messergebnissen
- Eine Log-Datei (`traceroute.log`) für die Fehleranalyse

## Output

Der generierte HTML-Report enthält:
- Zeitstempel der Messung
- Traceroute-Ergebnisse für jede Domain
- Visuelle Hervorhebung von hohen Latenzen (>80ms)
- Formatierte und zensierte Ausgabe für bessere Lesbarkeit
- Die IPs der Hops für das ausgeben von einer Route Map (optional)

## Domains

Das Tool enthält bereits eine Basis-Liste bekannter problematischer Domains. Diese Liste kann einfach erweitert werden:
- Durch Anpassung der Domain-Liste in der `main()`-Funktion
- Durch Pull Requests für weitere relevante Domains

Aktuell enthaltene Service-Kategorien:
- Gaming Plattformen (Steam, Epic, etc.)
- Streaming Dienste
- Cloud Services
- Gaming Server
- Content Delivery Networks

## Anpassungen

Die Liste der zu testenden Domains kann in der `main()`-Funktion angepasst werden. Neue Domains können einfach zur Liste hinzugefügt werden.

## Datenschutz

- Automatische Zensierung von privaten IP-Adressen und Hostnamen
- Keine externe API-Aufrufe
- Alle Daten werden nur lokal gespeichert

## Beitragen

Feedback, Issues und Pull Requests sind willkommen! Besonders für:
- Neue relevante Domains
- Verbesserungen der Latenz-Erkennung
- Zusätzliche Features
- Bug Fixes

## Hinweise

- Das Tool benötigt entsprechende Berechtigungen zur Ausführung von Traceroute
- Die Ausführungszeit kann je nach Anzahl der Domains mehrere Minuten betragen
- Der Schwellenwert von 80ms für die Latenzwarnung kann bei Bedarf angepasst werden