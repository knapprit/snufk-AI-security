import json
import os
import time
from collections import defaultdict
from kafka import KafkaConsumer
from kafka.errors import NoBrokersAvailable

try:
    from signatures_db import ATTACK_SIGNATURES, WHITE_LIST
    from rich.console import Console
    from rich.panel import Panel
    from rich.table import Table
    from rich.text import Text
except ImportError:
    print("Ошибка. Убедитесь, что файлы на месте и выполнили 'pip install rich kafka-python-ng'")
    exit(1)

console = Console()

class SentinelXDR:
    def __init__(self):
        self.risk_scores = defaultdict(int)
        self.incident_history = defaultdict(list)
        self.last_seen = defaultdict(float)
        self.reset_after = 600  # Сброс баллов через 10 минут тишины
        
        self.consumer = self.connect_to_kafka()

    def connect_to_kafka(self):
        console.print("[bold blue][SYSTEM][/bold blue] Инициализация интеллектуального ядра...")
        while True:
            try:
                consumer = KafkaConsumer(
                    'unified-logs',
                    bootstrap_servers=['localhost:9092'],
                    value_deserializer=lambda m: json.loads(m.decode('utf-8')),
                    auto_offset_reset='latest'
                )
                console.print("[bold green] [SYSTEM][/bold green] Соединение с шиной данных установлено.")
                return consumer
            except NoBrokersAvailable:
                console.print("[yellow] [SYSTEM] Ожидание Kafka...[/yellow]")
                time.sleep(5)

    def analyze_risk(self, event_msg, suricata_severity=3):
        """
        ГИБРИДНЫЙ АНАЛИЗ РИСКА
        1. проверка по базе signatures_db
        2. поиск по ключевым словам
        3. анализ штатного приоритета сурикаты
        """
        # поиск в приоритетном списке
        for key, data in ATTACK_SIGNATURES.items():
            if data['desc'].lower() in event_msg.lower():
                return data['score'], data['desc']

        #ключевые слова в тексте любого правила
        keywords = {
            "exploit": 100, "critical": 100, "rce": 100, "shell": 100,
            "sql": 60, "brute": 60, "injection": 60,
            "scan": 40, "nmap": 40, "probe": 40, "discovery": 30,
            "anomaly": 30, "unusual": 20, "denial": 80
        }
        
        for word, score in keywords.items():
            if word in event_msg.lower():
                return score, f"Dynamic: {word.upper()} Detected"

        #доверие к сурикаты если правило новое
        #в сурикате: 1 - Critical, 2 - Info/Warning, 3 - Low
        if suricata_severity == 1:
            return 80, "High Severity Rule (S1)"
        elif suricata_severity == 2:
            return 40, "Medium Severity Rule (S2)"
        
        return 10, "Minor Anomaly (S3)"

    def block_ip(self, ip):
        """Автоматическая изоляция"""
        if ip == "127.0.0.1" or ip in WHITE_LIST:
            return

        console.print(Panel(
            f"[bold white on red] КРИТИЧЕСКИЙ РИСК: {ip} [/bold white on red]\n"
            f"[bold yellow][IPS][/bold yellow] Блокировка в Windows Firewall...",
            border_style="red"
        ))
        
        rule_name = f"XDR_BLOCK_{ip.replace('.', '_')}"
        os.system(f"netsh advfirewall firewall add rule name='{rule_name}' dir=in action=block remoteip={ip}")
        self.generate_final_report(ip)

    def generate_final_report(self, ip):
        table = Table(title=f"Incident Evidence: {ip}", title_style="bold magenta", border_style="bright_yellow")
        table.add_column("Time", style="cyan")
        table.add_column("Detection Signal", style="white")

        for event in self.incident_history[ip]:
            table.add_row(event['time'], event['msg'])

        console.print(Panel(
            f"[bold white]ОБЪЕКТ:[/bold white] [bold cyan]{ip}[/bold cyan]\n"
            f"[bold white]СТАТУС:[/bold white] [bold green]ИЗОЛИРОВАН[/bold green]\n"
            f"[bold white]РИСК:  [/bold white] [bold red]{self.risk_scores[ip]} баллов[/bold red]",
            title="[bold red]ОТЧЕТ ОБ ИНЦИДЕНТЕ[/bold red]",
            border_style="bright_red"
        ))
        console.print(table)
        console.print("\n")

    def process(self):
        console.print(Panel.fit(" SENTINEL HYBRID XDR \n[dim]AI-Enhanced IPS Engine[/dim]", border_style="cyan"))

        for message in self.consumer:
            log = message.value
            now = time.time()
            
            src_ip = "127.0.0.1"
            event_msg = ""
            s_sev = 3 #дефолт
            source_label = ""

            #источник сетевой(Suricata/Zeek) ---
            if 'alert' in log:
                src_ip = log.get('src_ip', '0.0.0.0')
                event_msg = log['alert'].get('signature', 'Unknown network alert')
                s_sev = log['alert'].get('severity', 3)
                source_label = "[bold blue]NETWORK[/bold blue]"
            
            #источник системный(Sysmon)
            elif 'event_id' in log or 'EventID' in log:
                src_ip = log.get('event_data', {}).get('SourceIp') or "127.0.0.1"
                source_label = "[bold magenta]SYSTEM [/bold magenta]"
                
                # Логика Sysmon (RCE)
                parent = log.get('event_data', {}).get('ParentImage', '').lower()
                child = log.get('event_data', {}).get('Image', '').lower()
                if 'java' in parent and ('cmd.exe' in child or 'powershell.exe' in child):
                    event_msg = "RCE Attempt: Web-server spawned Shell"
                else:
                    event_msg = f"Sysmon Event {log.get('event_id') or log.get('EventID')}"

            if not event_msg or src_ip in WHITE_LIST: continue

            #долгое отстуствие активности
            if now - self.last_seen[src_ip] > self.reset_after:
                self.risk_scores[src_ip] = 0
                self.incident_history[src_ip] = []
            
            self.last_seen[src_ip] = now

            #анализ
            added_points, reason = self.analyze_risk(event_msg, s_sev)

            if added_points > 0:
                self.risk_scores[src_ip] += added_points
                self.incident_history[src_ip].append({
                    "time": time.strftime('%H:%M:%S'),
                    "msg": f"{reason} ({source_label})"
                })
                
                console.print(f"⚠️  {source_label} [bold cyan]{src_ip}[/bold cyan]: {reason} [bold red]+{added_points}[/bold red] (Risk: {self.risk_scores[src_ip]})")

                if self.risk_scores[src_ip] >= 100:
                    self.block_ip(src_ip)
                    self.risk_scores[src_ip] = 0
                    self.incident_history[src_ip] = []

if __name__ == "__main__":
    try:
        SentinelXDR().process()
    except KeyboardInterrupt:
        console.print("\n[bold red] Мониторинг остановлен.[/bold red]")