ATTACK_SIGNATURES = {
    # РАЗВЕДКА
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