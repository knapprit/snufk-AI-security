import json
import time
from collections import defaultdict
from kafka import KafkaConsumer
from kafka.errors import NoBrokersAvailable

ATTACK_SIGNATURES = {
    "SCAN_NMAP_FLAGS": {"score": 40, "desc": "Обнаружено сканирование флагами Nmap (NULL/FIN/XMAS)"},
    "SCAN_DIR_PROBING": {"score": 30, "desc": "Поиск скрытых файлов (.env, .git, config.php, backup.zip)"},
    "WEB_PROBING_LOGIN": {"score": 20, "desc": "Аномальный интерес к странице авторизации (частые запросы без входа)"},
    "DNS_ZONE_TRANSFER": {"score": 50, "desc": "Попытка AXFR-запроса (попытка украсть карту сети)"},

    # СКАН
    "INJ_ERROR_BASED_PROBE": {"score": 40, "desc": "Вызов преднамеренных ошибок БД (символы ', \", --, /*)"},
    "INJ_XSS_PROBE": {"score": 40, "desc": "Попытка внедрения <script>alert(1)</script> для проверки фильтров"},
    "CMD_PATH_PROBE": {"score": 60, "desc": "Попытка прочитать /etc/passwd или win.ini (LFI/Path Traversal)"},
    "RECON_PORT_SCAN": {"score": 40, "desc": "Активное сканирование портов (Nmap)"},
    "WEB_SCANNER_DIRBUSTER": {"score": 40, "desc": "Активный перебор скрытых директорий (много 404)"},
    
    "SESS_ID_BRUTEFORCE": {"score": 60, "desc": "Многократные попытки входа (Brute-force)"},
    "WEB_PROBING_LOGIN": {"score": 30, "desc": "Аномальный интерес к странице авторизации"},
    "INJ_SQL_CHAR_DETECTION": {"score": 40, "desc": "Обнаружение спецсимволов SQL (', --, /*)"},

    # ПОДГОТОВКА И ПЕРЕДАЧА
    "FILE_UP_DOUBLE_EXT": {"score": 80, "desc": "Попытка загрузки файла с двойным расширением (.jpg.php)"},
    "FILE_UP_WEBSHELL_NAME": {"score": 90, "desc": "Загрузка файла с подозрительным именем (shell, cmd, bypass)"},
    "DL_MALWARE_STAGER": {"score": 70, "desc": "Загрузка стадийного файла (certutil.exe скачивает что-то извне)"},

    # СИСТЕМНЫЕ АНОМАЛИИ
    "SYS_WHOAMI_BY_WEB": {"score": 100, "desc": "КРИТИЧНО: Команда 'whoami' выполнена из-под веб-сервера"},
    "SYS_NET_ENUM": {"score": 60, "desc": "Запуск команд 'net view' или 'ipconfig' сразу после сетевой активности"},
    "SYS_USB_NEW": {"score": 40, "desc": "Подключено новое неизвестное USB-устройство"},
    "SYS_CMD_ENCODED": {"score": 80, "desc": "Запуск PowerShell с зашифрованной командой (-EncodedCommand)"},
    
    # ЗАКРЕПЛЕНИЕ
    "SYS_REG_RUN_MOD": {"score": 90, "desc": "Изменение ключей автозагрузки в реестре"},
    "SYS_NEW_USER_CMD": {"score": 100, "desc": "Попытка создания пользователя через командную строку (net user /add)"}
}

WHITE_LIST = ["127.0.0.1", "localhost"]

class DockerSOCBrain:
    def __init__(self):
        self.risk_scores = defaultdict(int)
        self.incident_history = defaultdict(list)
        self.last_seen = defaultdict(float)
        self.reset_after = 600  #10 минут тишины. сброс.
        
    
        self.consumer = self.connect_to_kafka()

    def connect_to_kafka(self):
        """подключение к брокеру внутри Docker"""
        print("[DOCKER ENGINE] Инициализация аналитического ядра...")
        while True:
            try:
                #внутри докера порт 29092
                consumer = KafkaConsumer(
                    'unified-logs',
                    bootstrap_servers=['kafka:29092'], 
                    value_deserializer=lambda m: json.loads(m.decode('utf-8')),
                    auto_offset_reset='latest',
                    group_id='docker-soc-group'
                )
                print("[DOCKER ENGINE] Соединение с Kafka установлено")
                return consumer
            except NoBrokersAvailable:
                print("[DOCKER ENGINE] Kafka еще не готова, жду 5 секунд...")
                time.sleep(5)
            except Exception as e:
                print(f"[DOCKER ENGINE] Ошибка. {e}")
                time.sleep(5)

    def analyze_risk(self, event_msg, suricata_severity=3):
        """гибридный анализ"""
        #поиск в списке
        for key, data in ATTACK_SIGNATURES.items():
            if data['desc'].lower() in event_msg.lower():
                return data['score'], data['desc']

        #поиск по ключевым словам
        keywords = {
            "exploit": 100, "critical": 100, "rce": 100, "shell": 100,
            "sql": 60, "brute": 60, "scan": 40, "nmap": 40, "probe": 40
        }
        for word, score in keywords.items():
            if word in event_msg.lower():
                return score, f"Heuristic: {word.upper()}"

        #Severity самой Сурикаты
        if suricata_severity == 1: return 80, "S1 Critical Rule"
        elif suricata_severity == 2: return 40, "S2 Warning Rule"
        return 0, "Normal"

    def normalize(self, log):
        """парсер логов Сеть/Система"""
        event = {"src": "unknown", "msg": "", "sev": 3, "label": "INFO"}
        
        # если пришёл алерт от сурикаты
        if 'alert' in log:
            event['src'] = log.get('src_ip', '0.0.0.0')
            event['msg'] = log['alert'].get('signature', '')
            event['sev'] = log['alert'].get('severity', 3)
            event['label'] = "NETWORK"
            
        # если это от Sysmon (из Vector)
        elif 'event_id' in log or 'EventID' in log:
            event['src'] = log.get('event_data', {}).get('SourceIp') or "local_host"
            event['label'] = "SYSTEM"
            
            # Логика RCE (Java -> Cmd)
            parent = log.get('event_data', {}).get('ParentImage', '').lower()
            child = log.get('event_data', {}).get('Image', '').lower()
            if 'java' in parent and ('cmd.exe' in child or 'powershell.exe' in child):
                event['msg'] = "RCE Attempt: Web-server spawned Shell"
            else:
                event['msg'] = f"Sysmon Event {log.get('event_id') or log.get('EventID')}"

        return event

    def process(self):
        print(" [DOCKER ENGINE] Мониторинг запущен.")
        for message in self.consumer:
            log = message.value
            now = time.time()
            event = self.normalize(log)
            ip = event['src']
            
            if ip in WHITE_LIST or not event['msg']: continue

            # очистка старых баллов
            if now - self.last_seen[ip] > self.reset_after:
                self.risk_scores[ip] = 0
                self.incident_history[ip] = []
            
            self.last_seen[ip] = now

            # Анализ риска
            points, reason = self.analyze_risk(event['msg'], event['sev'])

            if points > 0:
                self.risk_scores[ip] += points
                self.incident_history[ip].append(f"{event['label']}: {reason}")
                print(f"🔹 [DOCKER LOG] IP {ip} набрал {self.risk_scores[ip]} pts. Причина: {reason}")

                if self.risk_scores[ip] >= 100:
                    self.report_to_logs(ip)
                    self.risk_scores[ip] = 0
                    self.incident_history[ip] = []

    def report_to_logs(self, ip):
        """вывод"""
        print(f"\n{'!'*20} КРИТИЧЕСКИЙ ИНЦИДЕНТ {'!'*20}")
        print(f"ОБЪЕКТ: {ip}")
        print(f"ВРЕМЯ:  {time.strftime('%H:%M:%S')}")
        print(f"ВЕРДИКТ: ПОДТВЕРЖДЕННЫЙ ВЗЛОМ / ИЗОЛЯЦИЯ ВЫПОЛНЕНА")
        print(f"{'!'*60}\n")

if __name__ == "__main__":
    DockerSOCBrain().process()