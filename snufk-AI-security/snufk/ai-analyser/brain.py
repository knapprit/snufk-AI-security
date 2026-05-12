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
        self.risk_map = defaultdict(int)
        self.history = defaultdict(list)
        self.consumer = self.connect_to_kafka()

    def connect_to_kafka(self):
        """Метод для ожидания Кафки внутри Docker сети"""
        print("[DOCKER ENGINE] Инициализация аналитического ядра...")
        while True:
            try:
                # Внутри Docker используем порт 29092
                consumer = KafkaConsumer(
                    'unified-logs',
                    bootstrap_servers=['kafka:29092'], 
                    value_deserializer=lambda m: json.loads(m.decode('utf-8')),
                    auto_offset_reset='latest',
                    group_id='docker-brain-group'
                )
                print("[DOCKER ENGINE] Соединение с Kafka установлено")
                return consumer
            except NoBrokersAvailable:
                print(" [DOCKER ENGINE] Kafka еще не готова, жду 5 секунд...")
                time.sleep(5)
            except Exception as e:
                print(f"[DOCKER ENGINE] Ошибка подключения: {e}")
                time.sleep(5)

    def normalize(self, log):
        """Приводит логи Suricata и Sysmon к общему виду"""
        event = {"src": "unknown", "msg": "Traffic", "type": "info"}
        
        
        if 'alert' in log:
            event = {
                "src": log.get('src_ip', 'unknown'),
                "msg": log['alert'].get('signature', ''),
                "type": "network"
            }

        elif 'event_id' in log or 'EventID' in log:
            event_data = log.get('event_data', {})
            #найти IP в сетевом событии Sysmon (Event ID 3)
            ip = event_data.get('SourceIp') or "host_machine"
            
            #RCE
            parent = event_data.get('ParentImage', '').lower()
            child = event_data.get('Image', '').lower()
            
            msg = f"Sysmon Event {log.get('event_id') or log.get('EventID')}"
            if 'java' in parent and ('cmd.exe' in child or 'powershell.exe' in child):
                msg = "Web-server spawned Shell (RCE Attempt)"

            event = {
                "src": ip,
                "msg": msg,
                "type": "system"
            }
        return event

    def process(self):
        """Основной цикл обработки логов"""
        print(" [DOCKER ENGINE] Аналитика запущена...")
        for message in self.consumer:
            log = message.value
            event = self.normalize(log)
            ip = event['src']
            
            # Проверка белого списка
            if ip in WHITE_LIST:
                continue

            # суммирование баллов риска на основе сигнатур
            for key, data in ATTACK_SIGNATURES.items():
                if data['desc'].lower() in event['msg'].lower():
                    self.risk_map[ip] += data['score']
                    self.history[ip].append(event)
                    print(f"🔹 [DOCKER] Анализ {ip}: {data['desc']} (+{data['score']} pts)")

            # Если риск превысил порог 100 баллов
            if self.risk_map[ip] >= 100:
                self.report(ip)
                self.risk_map[ip] = 0 # Сброс
                self.history[ip] = []

    def report(self, ip):
        """Текстовый отчет для логов Docker"""
        print("\n" + "!"*40)
        print(f"!!! КРИТИЧЕСКИЙ ИНЦИДЕНТ В DOCKER LOGS !!!")
        print(f"ОБЪЕКТ: {ip}")
        print(f"ИТОГ: Данный субъект представляет угрозу. Блокировка инициирована.")
        print("!"*40 + "\n")

if __name__ == "__main__":
    brain = DockerSOCBrain()
    brain.process()