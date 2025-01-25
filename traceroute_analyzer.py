import subprocess
import re
import logging
import datetime
from pathlib import Path
import time
import sys

# Logging-Konfiguration
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler('traceroute.log', encoding='utf-8')
    ]
)

def run_traceroute(domain):
    """Führt traceroute für eine Domain aus"""
    logging.info(f"Starte traceroute für {domain}")
    
    try:
        # Wähle den richtigen Befehl je nach Betriebssystem
        if sys.platform.startswith('win'):
            command = ['tracert', domain]
            encoding = 'cp437'  # Windows DOS Codepage
        else:
            command = ['traceroute', '-n', domain]  # -n für numerische Ausgabe
            encoding = 'utf-8'
            
        # Führe traceroute aus
        process = subprocess.Popen(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            universal_newlines=False  # Wichtig: Raw Bytes lesen
        )
        
        output_lines = []
        
        # Verarbeite die Ausgabe zeilenweise
        while True:
            line = process.stdout.readline()
            if not line:
                break
            try:
                # Versuche die Zeile zu dekodieren
                decoded_line = line.decode(encoding, errors='replace')
                logging.debug(f"Traceroute Ausgabe: {decoded_line.strip()}")
                censored_line = censor_sensitive_data(decoded_line)
                output_lines.append(censored_line)
            except Exception as decode_error:
                logging.warning(f"Fehler beim Dekodieren einer Zeile: {decode_error}")
                continue
            
        process.wait()
        
        if process.returncode != 0:
            stderr = process.stderr.read().decode(encoding, errors='replace')
            logging.error(f"Traceroute Fehler: {stderr}")
            return f"Fehler bei der Ausführung: {stderr}"
            
        return "".join(output_lines)
        
    except Exception as e:
        logging.error(f"Fehler bei traceroute für {domain}: {str(e)}", exc_info=True)
        return f"Fehler: {str(e)}"

def censor_sensitive_data(line):
    """Zensiert sensitive Daten in der Traceroute-Ausgabe"""
    
    # IPv4 Pattern für t-ipconnect.de Hosts
    line = re.sub(
        r'([a-z0-9]+\.dip0\.t-ipconnect\.de)\s+\[(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\]',
        r'XXXXX.dip0.t-ipconnect.de [XXX.XXX.XXX.XXX]',
        line
    )
    
    # IPv6 Pattern für t-ipconnect.de Hosts
    line = re.sub(
        r'([a-z0-9]+\.dip0\.t-ipconnect\.de)\s+\[([0-9a-fA-F:]+)\]',
        r'XXXXX.dip0.t-ipconnect.de [XXXX:XXXX:XXXX:XXXX:XXXX:XXXX:XXXX:XXXX]',
        line
    )
    
    # Zensiere den Hostnamen selbst
    line = re.sub(
        r'[a-z0-9]+\.dip0\.t-ipconnect\.de',
        'XXXXX.dip0.t-ipconnect.de',
        line
    )
    
    return line

def get_last_hop_latency(traceroute_output):
    """Extrahiert die letzte Latenz aus der Traceroute-Ausgabe"""
    lines = traceroute_output.split('\n')
    
    # Suche die letzte nicht-leere Zeile mit Zahlen
    for line in reversed(lines):
        if not line.strip():
            continue
            
        # Windows Format: "    1    <1 ms    <1 ms    <1 ms  192.168.1.1"
        win_matches = re.findall(r'\d+\s+ms', line)
        if win_matches:
            latencies = [int(x.split()[0]) for x in win_matches]
            return sum(latencies) / len(latencies)
            
        # Linux Format: " 11  172.253.71.89  5.886 ms  5.879 ms  5.769 ms"
        linux_matches = re.findall(r'(\d+\.?\d*)\s+ms', line)
        if linux_matches:
            latencies = [float(x) for x in linux_matches]
            return sum(latencies) / len(latencies)
            
    return 0

def analyze_routing(traceroute_output):
    """Analysiert das Routing auf DTAG-Hosts und deren Standorte"""
    lines = traceroute_output.split('\n')
    international_routing = False
    
    # Regex für DTAG Hostnames
    dtag_pattern = r'[A-Za-z0-9-]+\.[A-Za-z0-9]+\.([A-Za-z]{2})\.NET\.DTAG\.DE'
    
    for line in lines:
        match = re.search(dtag_pattern, line, re.IGNORECASE)
        if match:
            country_code = match.group(1).upper()
            if country_code != 'DE':
                international_routing = True
                break
    
    return international_routing

def create_html_report(results):
    """Erstellt einen HTML-Bericht mit den traceroute-Ergebnissen"""
    logging.debug("Erstelle HTML-Bericht")
    current_time = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    html_content = f"""
    <!DOCTYPE html>
    <html lang="de">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Traceroute Report</title>
        <style>
            body {{
                font-family: Arial, sans-serif;
                margin: 20px;
                background-color: #f0f0f0;
            }}
            .container {{
                max-width: 1200px;
                margin: 0 auto;
                background-color: white;
                padding: 20px;
                border-radius: 10px;
                box-shadow: 0 0 10px rgba(0,0,0,0.1);
            }}
            h1 {{
                color: #333;
                text-align: center;
            }}
            .timestamp {{
                text-align: center;
                color: #666;
                margin-bottom: 30px;
            }}
            .domain-section {{
                margin-bottom: 30px;
                padding: 15px;
                background-color: #f8f8f8;
                border-radius: 5px;
            }}
            .high-latency-national {{
                border: 2px solid #ffd700;
                background-color: #ffffd0;
            }}
            .high-latency-international {{
                border: 2px solid #ff4444;
                background-color: #fff0f0;
            }}
            .latency-warning-national {{
                color: #b8860b;
                font-weight: bold;
                margin-top: 10px;
            }}
            .latency-warning-international {{
                color: #ff4444;
                font-weight: bold;
                margin-top: 10px;
            }}
            h2 {{
                color: #444;
                border-bottom: 2px solid #ddd;
                padding-bottom: 5px;
            }}
            pre {{
                background-color: #f5f5f5;
                padding: 15px;
                border-radius: 5px;
                overflow-x: auto;
                white-space: pre-wrap;
            }}
        </style>
    </head>
    <body>
        <div class="container">
            <h1>Traceroute Report</h1>
            <div class="timestamp">Erstellt am: {current_time}</div>
    """
    
    for domain, result in results.items():
        last_hop_latency = get_last_hop_latency(result)
        is_high_latency = last_hop_latency > 80
        international_routing = analyze_routing(result)
        
        section_class = "domain-section"
        warning_class = ""
        warning_text = ""
        
        if is_high_latency:
            if international_routing:
                section_class += " high-latency-international"
                warning_class = "latency-warning-international"
                warning_text = f"⚠️ Hohe Latenz über internationales Routing: {last_hop_latency:.1f}ms"
            else:
                section_class += " high-latency-national"
                warning_class = "latency-warning-national"
                warning_text = f"⚠️ Hohe Latenz über nationales Routing: {last_hop_latency:.1f}ms"
        
        html_content += f"""
            <div class="{section_class}">
                <h2>Traceroute zu {domain}</h2>
                <pre>{result}</pre>
                {f'<div class="{warning_class}">{warning_text}</div>' if is_high_latency else ''}
            </div>
        """
    
    html_content += """
        </div>
    </body>
    </html>
    """
    
    return html_content

def main():
    logging.info("Starte Traceroute-Programm")
    
    domains = [
        # Google
        "google.com",
        "youtube.com",
        
        # Cloudflare
        "valuehunt.net", # Ein Dienst hinter Cloudflare (Argo Tunnel connected)
        "cloudflare.com",
        
        # Microsoft Flight Simulator
        "microsoft.com",
        "flightsimulator.com",
        
        # GitHub
        "github.com",
        
        # Steam
        "steampowered.com",
        "steamcommunity.com",
        
        # YouTube (bereits enthalten)
        
        # ARD & ZDF Mediathek
        "ardmediathek.de",
        "zdf.de",
        
        # SRF
        "srf.ch",
        
        # Apex Legends
        "ea.com",
        "origin.com",
        
        # Hunt Showdown
        "huntshowdown.com",
        "crytek.com",
        
        # World of Tanks Console
        "wargaming.net",
        "worldoftanks.com",
        
        # Path of Exile
        "pathofexile.com",
        "grindinggear.com",
        
        # Escape From Tarkov
        "escapefromtarkov.com",
        "battlestate.com",
        
        # Discord
        "discord.com",
        "discord.gg",
        
        # Mega Upload
        "mega.nz",
        "mega.io",
        
        # Square Enix
        "square-enix.com",
        "square-enix-games.com",
        
        # DDownload
        "ddownload.com"
    ]
    
    results = {}
    
    for domain in domains:
        logging.info(f"Verarbeite Domain: {domain}")
        try:
            results[domain] = run_traceroute(domain)
            logging.info(f"Traceroute für {domain} abgeschlossen")
            # Kleine Pause zwischen den Traceroutes
            time.sleep(2)
        except Exception as e:
            logging.error(f"Hauptfehler bei {domain}: {str(e)}", exc_info=True)
            results[domain] = f"Fehler: {str(e)}"
    
    try:
        html_content = create_html_report(results)
        output_file = Path("traceroute_report.html")
        output_file.write_text(html_content, encoding='utf-8')
        logging.info(f"Bericht wurde erstellt: {output_file.absolute()}")
    except Exception as e:
        logging.error("Fehler beim Erstellen des HTML-Berichts", exc_info=True)
        print(f"Fehler beim Erstellen des Berichts: {str(e)}")

if __name__ == "__main__":
    main()