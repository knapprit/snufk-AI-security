import json
import os
import time
from collections import defaultdict
from kafka import KafkaConsumer
from kafka.errors import NoBrokersAvailable
from signatures_db import ATTACK_SIGNATURES, WHITE_LIST

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich.live import Live
from rich.layout import Layout

console = Console()

class CyberGuardianIPS:
    def __init__(self):
        self.risk_scores = defaultdict(int)
        self.incident_history = defaultdict(list)
        self.consumer = self.connect_to_kafka()

    def connect_to_kafka(self):
        console.print("[bold blue] [SYSTEM][/bold blue] Инициализация аналитического ядра...")
        while True:
            try:
                consumer = KafkaConsumer(
                    'unified-logs',
                    bootstrap_servers=['localhost:9092'],
                    value_deserializer=lambda m: json.loads(m.decode('utf-8')),
                    auto_offset_reset='latest'
                )
                console.print("[bold green] [SYSTEM][/bold green] Связь с Kafka установлена. Мониторинг запущен.")
                return consumer
            except NoBrokersAvailable:
                console.print("[yellow] [SYSTEM] Ожидание шины данных (Kafka)...[/yellow]")
                time.sleep(5)

    def block_ip(self, ip):
        if ip == "127.0.0.1": return
        
    
        console.print(Panel(
            f"[bold white on red] КРИТИЧЕСКИЙ ПОРОГ РИСКА ПРЕВЫШЕН ДЛЯ IP: {ip} [/bold white on red]\n"
            f"[bold yellow] [ACTION][/bold yellow] Автоматическая блокировка через Windows Firewall...",
            border_style="red"
        ))
        
        cmd = f"netsh advfirewall firewall add rule name='IPS_BLOCK_{ip}' dir=in action=block remoteip={ip}"
        os.system(cmd)
        self.generate_final_report(ip)

    def generate_final_report(self, ip):
        """визуальный отчет"""
        
        table = Table(title="Attack Timeline", title_style="bold magenta", border_style="bright_yellow")
        table.add_column("Time", style="cyan")
        table.add_column("Event Description", style="white")

        for event in self.incident_history[ip]:
            table.add_row(event['time'], event['msg'])

        report_content = Text()
        report_content.append(f"ОБЪЕКТ: {ip}\n", style="bold white")
        report_content.append(f"СТАТУС: ЗАБЛОКИРОВАН\n", style="bold green")
        report_content.append(f"УРОВЕНЬ: CRITICAL\n", style="bold red")
        report_content.append(f"ИТОГОВЫЙ РИСК: {self.risk_scores[ip]} баллов", style="bold yellow")

        console.print("\n")
        console.print(Panel(
            report_content,
            title="[bold red]ИНЦИДЕНТ ПРЕДОТВРАЩЕН[/bold red]",
            subtitle="Sentinel Hybrid XDR",
            border_style="bright_red",
            expand=False
        ))
        console.print(table)
        console.print("[bold cyan] РЕКОМЕНДАЦИЯ:[/bold cyan] Проверьте целостность системы и эскалируйте тикет в группу реагирования.\n")

    def process(self):
    
        console.print(Panel.fit(
            "   [bold cyan]SENTINEL HYBRID XDR[/bold cyan]   \n[dim]Autonomous IPS Engine v1.0[/dim]",
            border_style="cyan"
        ))

        for message in self.consumer:
            log = message.value
            src_ip = "127.0.0.1"
            event_msg = ""
            source_label = ""

            if 'alert' in log:
                src_ip = log.get('src_ip')
                event_msg = log['alert'].get('signature', '')
                source_label = "[bold blue]NETWORK[/bold blue]"
            elif 'event_id' in log:
                src_ip = log.get('event_data', {}).get('SourceIp', '127.0.0.1')
                event_msg = f"Sysmon Event {log['event_id']}"
                source_label = "[bold magenta]SYSTEM[/bold blue]"
            else:
                continue

            if src_ip in WHITE_LIST: continue

            added_points = 0
            found_desc = ""

            for key, data in ATTACK_SIGNATURES.items():
                if data['desc'].lower() in event_msg.lower():
                    added_points = data['score']
                    found_desc = data['desc']
                    break

            if added_points > 0:
                self.risk_scores[src_ip] += added_points
                self.incident_history[src_ip].append({
                    "time": time.strftime('%H:%M:%S'),
                    "msg": found_desc
                })
                
                # Вывод в реальном времени
                console.print(f"[bold yellow] [/bold yellow] {source_label} [bold cyan]{src_ip}[/bold cyan]: {found_desc} [bold red]+{added_points}[/bold red] (Всего: {self.risk_scores[src_ip]})")

                if self.risk_scores[src_ip] >= 100:
                    self.block_ip(src_ip)
                    self.risk_scores[src_ip] = 0
                    self.incident_history[src_ip] = []

if __name__ == "__main__":
    try:
        guardian = CyberGuardianIPS()
        guardian.process()
    except KeyboardInterrupt:
        console.print("\n[bold red] Мониторинг остановлен....[/bold red]")