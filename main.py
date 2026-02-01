#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
VPN Checker v3.1 - Улучшенная проверка соединений
Добавлено:
- Проверка открытия SOCKS5 порта
- Retry логика для нестабильных соединений
- Увеличенные таймауты
- Измерение времени ответа
- Детальное логирование проблем
"""

import os
import json
import time
import subprocess
import tempfile
import requests
import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Optional, Tuple
from dataclasses import dataclass
import signal

# ==================== КОНФИГУРАЦИЯ ====================
@dataclass
class Config:
    """Настройки приложения"""
    XRAY_PATH: str = "/home/misha/vpn-checker-backend-fox/Xray-linux-64/xray"

    # Структура папок
    CHECKED_DIR: str = "checked"
    RU_DIR: str = "checked/RU_Best"
    EURO_DIR: str = "checked/My_Euro"

    SOCKS_PORT_START: int = 20000

    # УЛУЧШЕННЫЕ ТАЙМАУТЫ
    XRAY_STARTUP_WAIT: int = 5  # Было 3, стало 5
    CONNECTION_TIMEOUT: int = 8  # Timeout на подключение
    REQUEST_TIMEOUT: int = 15    # Timeout на запрос (было 10)
    TOTAL_TIMEOUT: int = 20      # Общий timeout на проверку ключа

    # RETRY НАСТРОЙКИ
    RETRY_ATTEMPTS: int = 2      # Количество попыток
    RETRY_DELAY: int = 2         # Задержка между попытками

    MAX_WORKERS: int = 10
    MAX_KEYS: int = 99999

    # URL для проверки
    RUSSIAN_TEST_SITES: List[str] = None
    FOREIGN_TEST_SITES: List[str] = None
    SOURCES: List[str] = None

    def __post_init__(self):
        if self.RUSSIAN_TEST_SITES is None:
            self.RUSSIAN_TEST_SITES = [
                "https://vk.com",
                "https://yandex.ru",
                "https://mail.ru"
            ]

        if self.FOREIGN_TEST_SITES is None:
            self.FOREIGN_TEST_SITES = [
                "https://www.google.com",
                "https://www.youtube.com",
                "https://www.facebook.com"
            ]

        if self.SOURCES is None:
            self.SOURCES = [
                "https://raw.githubusercontent.com/zieng2/wl/main/vless.txt",
                "https://raw.githubusercontent.com/LowiKLive/BypassWhitelistRu/refs/heads/main/WhiteList-Bypass_Ru.txt",
                "https://raw.githubusercontent.com/zieng2/wl/main/vless_universal.txt",
                "https://raw.githubusercontent.com/vsevjik/OBSpiskov/refs/heads/main/wwh",
                "https://etoneya.a9fm.site/1",
                "https://raw.githubusercontent.com/Kirillo4ka/vpn-configs-for-russia/refs/heads/main/Vless-Rus-Mobile-White-List.txt",
                "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/refs/heads/main/Vless-Reality-White-Lists-Rus-Mobile.txt",
                "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/refs/heads/main/Vless-Reality-White-Lists-Rus-Cable.txt",
                "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/refs/heads/main/BLACK_SS%2BAll_RUS.txt",
                "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/refs/heads/main/BLACK_VLESS_RUS.txt",
                "https://raw.githubusercontent.com/Mosifree/-FREE2CONFIG/refs/heads/main/Reality",
                "https://raw.githubusercontent.com/STR97/STRUGOV/refs/heads/main/STR.BYPASS",
                "https://raw.githubusercontent.com/AvenCores/goida-vpn-configs/refs/heads/main/githubmirror/26.txt",
                "https://raw.githubusercontent.com/kort0881/vpn-vless-configs-russia/refs/heads/main/githubmirror/new/all_new.txt",
                "https://raw.githubusercontent.com/crackbest/V2ray-Config/refs/heads/main/config.txt",
                "https://raw.githubusercontent.com/miladtahanian/multi-proxy-config-fetcher/refs/heads/main/configs/proxy_configs.txt",
                "https://raw.githubusercontent.com/SoliSpirit/v2ray-configs/refs/heads/main/Countries/Latvia.txt",
                "https://raw.githubusercontent.com/STR97/STRUGOV/refs/heads/main/BYPASS",
                "https://raw.githubusercontent.com/AvenCores/goida-vpn-configs/refs/heads/main/githubmirror/22.txt",
                "https://etoneya.a9fm.site/whitelist",
                "https://alley.serv00.net/whitelist",
                "https://etoneya.a9fm.site/youtube",
                "https://translate.yandex.ru/translate?url=https://etoneya.a9fm.site/youtube&lang=en-ru",
                "https://etoneya.a9fm.site/other",
                "https://translate.yandex.ru/translate?url=https://etoneya.a9fm.site/other&lang=en-ru",
                "https://vlesstrojan.alexanderyurievich88.workers.dev?token=sub",
                "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/main/Vless-Reality-White-Lists-Rus-Mobile.txt",
                "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/main/Vless-Reality-White-Lists-Rus-Mobile-2.txt",
                "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/main/BLACK_VLESS_RUS_mobile.txt",
            ]

CFG = Config()

# ==================== XRAY MANAGER ====================
class XrayManager:
    """Управление процессом Xray"""

    def __init__(self, config_path: str, port: int):
        self.config_path = config_path
        self.port = port
        self.process = None

    def start(self) -> bool:
        """Запускает Xray"""
        try:
            if not os.path.exists(CFG.XRAY_PATH):
                return False

            self.process = subprocess.Popen(
                [CFG.XRAY_PATH, "run", "-config", self.config_path],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                preexec_fn=os.setsid
            )

            # УЛУЧШЕНИЕ: Увеличенное время ожидания
            time.sleep(CFG.XRAY_STARTUP_WAIT)

            if self.process.poll() is not None:
                return False

            return True
        except:
            return False

    def stop(self):
        """Останавливает Xray"""
        if self.process:
            try:
                os.killpg(os.getpgid(self.process.pid), signal.SIGTERM)
                self.process.wait(timeout=3)
            except:
                try:
                    os.killpg(os.getpgid(self.process.pid), signal.SIGKILL)
                except:
                    pass
            self.process = None

# ==================== CONFIG GENERATOR ====================
def create_xray_config(key: str, port: int) -> dict:
    """Создает конфигурацию Xray"""
    config = {
        "log": {"loglevel": "none"},
        "inbounds": [{
            "port": port,
            "protocol": "socks",
            "settings": {"auth": "noauth", "udp": True}
        }],
        "outbounds": [{"protocol": "freedom", "settings": {}}]
    }

    try:
        if key.startswith("vless://"):
            outbound = parse_vless(key)
        elif key.startswith("vmess://"):
            outbound = parse_vmess(key)
        elif key.startswith("trojan://"):
            outbound = parse_trojan(key)
        elif key.startswith("ss://"):
            outbound = parse_shadowsocks(key)
        else:
            return None

        if outbound:
            config["outbounds"].insert(0, outbound)
            return config
    except:
        pass

    return None

def parse_vless(key: str) -> Optional[dict]:
    """Парсит VLESS ключ"""
    from urllib.parse import parse_qs, unquote

    key = key.replace("vless://", "")
    if "@" not in key:
        return None

    uuid, rest = key.split("@", 1)

    if "?" in rest:
        server_port, params_label = rest.split("?", 1)
    else:
        server_port = rest
        params_label = ""

    if "#" in params_label:
        params, _ = params_label.split("#", 1)
    else:
        params = params_label

    if ":" not in server_port:
        return None

    server, port = server_port.rsplit(":", 1)
    query = parse_qs(params)

    outbound = {
        "protocol": "vless",
        "settings": {
            "vnext": [{
                "address": server,
                "port": int(port),
                "users": [{"id": uuid, "encryption": "none"}]
            }]
        },
        "streamSettings": {"network": query.get("type", ["tcp"])[0]}
    }

    security = query.get("security", ["none"])[0]
    outbound["streamSettings"]["security"] = security

    if security in ["tls", "reality"]:
        tls_settings = {}
        if "sni" in query:
            tls_settings["serverName"] = query["sni"][0]

        if security == "reality":
            tls_settings["show"] = False
            if "pbk" in query:
                tls_settings["publicKey"] = query["pbk"][0]
            if "sid" in query:
                tls_settings["shortId"] = query["sid"][0]
            if "fp" in query:
                tls_settings["fingerprint"] = query["fp"][0]
            if "spx" in query:
                tls_settings["spiderX"] = unquote(query["spx"][0])
            outbound["streamSettings"]["realitySettings"] = tls_settings
        else:
            outbound["streamSettings"]["tlsSettings"] = tls_settings

    if outbound["streamSettings"]["network"] == "ws":
        ws_settings = {}
        if "path" in query:
            ws_settings["path"] = unquote(query["path"][0])
        if "host" in query:
            ws_settings["headers"] = {"Host": query["host"][0]}
        outbound["streamSettings"]["wsSettings"] = ws_settings

    if outbound["streamSettings"]["network"] == "grpc":
        grpc_settings = {}
        if "serviceName" in query:
            grpc_settings["serviceName"] = query["serviceName"][0]
        outbound["streamSettings"]["grpcSettings"] = grpc_settings

    if "flow" in query:
        outbound["settings"]["vnext"][0]["users"][0]["flow"] = query["flow"][0]

    return outbound

def parse_vmess(key: str) -> Optional[dict]:
    """Парсит VMess ключ"""
    import base64

    key = key.replace("vmess://", "")
    try:
        missing_padding = len(key) % 4
        if missing_padding:
            key += '=' * (4 - missing_padding)
        decoded = base64.b64decode(key).decode('utf-8')
        vmess_config = json.loads(decoded)
    except:
        return None

    outbound = {
        "protocol": "vmess",
        "settings": {
            "vnext": [{
                "address": vmess_config.get("add", ""),
                "port": int(vmess_config.get("port", 443)),
                "users": [{
                    "id": vmess_config.get("id", ""),
                    "alterId": int(vmess_config.get("aid", 0)),
                    "security": vmess_config.get("scy", "auto")
                }]
            }]
        },
        "streamSettings": {"network": vmess_config.get("net", "tcp")}
    }

    if vmess_config.get("tls") == "tls":
        outbound["streamSettings"]["security"] = "tls"
        tls_settings = {}
        if "sni" in vmess_config and vmess_config["sni"]:
            tls_settings["serverName"] = vmess_config["sni"]
        outbound["streamSettings"]["tlsSettings"] = tls_settings

    if outbound["streamSettings"]["network"] == "ws":
        ws_settings = {}
        if "path" in vmess_config and vmess_config["path"]:
            ws_settings["path"] = vmess_config["path"]
        if "host" in vmess_config and vmess_config["host"]:
            ws_settings["headers"] = {"Host": vmess_config["host"]}
        outbound["streamSettings"]["wsSettings"] = ws_settings

    return outbound

def parse_trojan(key: str) -> Optional[dict]:
    """Парсит Trojan ключ"""
    from urllib.parse import parse_qs

    key = key.replace("trojan://", "")
    if "@" not in key:
        return None

    password, rest = key.split("@", 1)

    if "?" in rest:
        server_port, params_label = rest.split("?", 1)
    else:
        server_port = rest
        params_label = ""

    if "#" in params_label:
        params, _ = params_label.split("#", 1)
    else:
        params = params_label

    if ":" not in server_port:
        return None

    server, port = server_port.rsplit(":", 1)
    query = parse_qs(params)

    outbound = {
        "protocol": "trojan",
        "settings": {
            "servers": [{
                "address": server,
                "port": int(port),
                "password": password
            }]
        },
        "streamSettings": {"network": query.get("type", ["tcp"])[0], "security": "tls"}
    }

    tls_settings = {}
    if "sni" in query:
        tls_settings["serverName"] = query["sni"][0]
    outbound["streamSettings"]["tlsSettings"] = tls_settings

    return outbound

def parse_shadowsocks(key: str) -> Optional[dict]:
    """Парсит Shadowsocks ключ"""
    import base64

    key = key.replace("ss://", "")
    try:
        if "@" in key:
            encoded, server_port = key.split("@", 1)
            missing_padding = len(encoded) % 4
            if missing_padding:
                encoded += '=' * (4 - missing_padding)
            method_password = base64.b64decode(encoded).decode('utf-8')
            method, password = method_password.split(":", 1)
        else:
            missing_padding = len(key) % 4
            if missing_padding:
                key += '=' * (4 - missing_padding)
            decoded = base64.b64decode(key).decode('utf-8')
            if "@" not in decoded:
                return None
            method_password, server_port = decoded.split("@", 1)
            method, password = method_password.split(":", 1)

        if "#" in server_port:
            server_port, _ = server_port.split("#", 1)

        server, port = server_port.rsplit(":", 1)

        return {
            "protocol": "shadowsocks",
            "settings": {
                "servers": [{
                    "address": server,
                    "port": int(port),
                    "method": method,
                    "password": password
                }]
            }
        }
    except:
        return None

# ==================== УЛУЧШЕННОЕ ТЕСТИРОВАНИЕ ====================

def check_socks_port(port: int, timeout: int = 3) -> Tuple[bool, str]:
    """
    НОВОЕ: Проверяет что SOCKS5 порт реально открыт
    Возвращает: (успех, сообщение)
    """
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex(('127.0.0.1', port))
        sock.close()

        if result == 0:
            return True, "Порт открыт"
        else:
            return False, f"Порт {port} закрыт (код: {result})"
    except Exception as e:
        return False, f"Ошибка проверки порта: {str(e)[:30]}"


def test_site_with_retry(port: int, url: str, retries: int = None) -> Tuple[bool, str, float]:
    """
    УЛУЧШЕНО: Проверяет доступность сайта через прокси с retry
    Возвращает: (успех, причина, время_ответа)
    """
    if retries is None:
        retries = CFG.RETRY_ATTEMPTS

    for attempt in range(retries):
        try:
            start_time = time.time()

            result = subprocess.run(
                [
                    "curl",
                    "-x", f"socks5h://127.0.0.1:{port}",
                    "-m", str(CFG.REQUEST_TIMEOUT),
                    "--connect-timeout", str(CFG.CONNECTION_TIMEOUT),
                    "-s", "-o", "/dev/null",
                    "-w", "%{http_code}",
                    "--max-time", str(CFG.REQUEST_TIMEOUT),
                    url
                ],
                capture_output=True,
                timeout=CFG.REQUEST_TIMEOUT + 2
            )

            elapsed_time = time.time() - start_time
            response_code = result.stdout.decode().strip()

            if response_code in ["200", "204", "301", "302"]:
                return True, f"OK ({response_code})", elapsed_time

            # Если не последняя попытка - делаем паузу
            if attempt < retries - 1:
                time.sleep(CFG.RETRY_DELAY)
            else:
                return False, f"Bad code: {response_code}", elapsed_time

        except subprocess.TimeoutExpired:
            # ВАЖНО: Timeout = пакеты ушли в никуда
            if attempt < retries - 1:
                time.sleep(CFG.RETRY_DELAY)
            else:
                return False, "Timeout (нет ответа)", CFG.REQUEST_TIMEOUT
        except Exception as e:
            if attempt < retries - 1:
                time.sleep(CFG.RETRY_DELAY)
            else:
                return False, f"Error: {str(e)[:20]}", 0

    return False, "Все попытки failed", 0


def is_russian_cidr(ip: str) -> bool:
    """Проверяет российские IP диапазоны"""
    russian_prefixes = [
        "5.", "31.", "37.", "46.", "62.", "77.", "78.", "79.",
        "80.", "81.", "82.", "83.", "84.", "85.", "87.", "88.",
        "89.", "90.", "91.", "92.", "93.", "94.", "95.", "109.",
        "141.", "178.", "185.", "188.", "194.", "195.", "212.", "213.", "217."
    ]
    return any(ip.startswith(prefix) for prefix in russian_prefixes)


def is_russian_domain(domain: str) -> bool:
    """Проверяет российские домены"""
    if not domain:
        return False

    domain = domain.lower()
    russian_keywords = [
        '.ru', '.рф', 'vk.com', 'yandex', 'mail.ru', 'gosuslugi',
        'sberbank', 'tinkoff', 'alfabank', 'vtb', 'ozon', 'wildberries'
    ]
    return any(keyword in domain for keyword in russian_keywords)


def has_white_markers(key: str) -> bool:
    """Проверяет маркеры белого списка в ключе"""
    key_lower = key.lower()
    white_markers = [
        'white', 'whitelist', 'bypass', 'обход', 'белый',
        'россия', 'russia', 'mobile', 'cable', 'ru-'
    ]
    return any(marker in key_lower for marker in white_markers)


def check_key_type(key: str, port: int) -> Tuple[str, str]:
    """
    УЛУЧШЕНО: Определяет тип ключа с детальным логированием
    Возвращает: (тип, причина)
    """
    # 1. Проверяем SOCKS5 порт
    port_ok, port_msg = check_socks_port(port, timeout=3)
    if not port_ok:
        return "none", f"Порт: {port_msg}"

    # 2. Проверяем CIDR и SNI в самом ключе
    try:
        from urllib.parse import parse_qs

        if "?" in key:
            params_part = key.split("?")[1].split("#")[0]
            query = parse_qs(params_part)

            # Проверяем SNI
            sni = query.get("sni", [None])[0]
            if sni and is_russian_domain(sni):
                # Проверяем что хоть что-то работает
                success, reason, elapsed = test_site_with_retry(port, CFG.RUSSIAN_TEST_SITES[0], retries=1)
                if success:
                    return "white", f"SNI={sni} (РФ домен)"

            # Проверяем dest (CIDR)
            dest = query.get("dest", [None])[0]
            if dest and is_russian_cidr(dest):
                success, reason, elapsed = test_site_with_retry(port, CFG.RUSSIAN_TEST_SITES[0], retries=1)
                if success:
                    return "white", f"CIDR={dest} (РФ IP)"

        # Проверяем host в самом адресе
        if "@" in key:
            host_part = key.split("@")[1].split(":")[0].split("?")[0]
            if is_russian_cidr(host_part):
                success, reason, elapsed = test_site_with_retry(port, CFG.RUSSIAN_TEST_SITES[0], retries=1)
                if success:
                    return "white", f"Host={host_part} (РФ IP)"
    except:
        pass

    # 3. Проверяем маркеры в названии
    if has_white_markers(key):
        success, reason, elapsed = test_site_with_retry(port, CFG.RUSSIAN_TEST_SITES[0], retries=1)
        if success:
            return "white", f"Маркер белого списка ({reason}, {elapsed:.1f}s)"

    # 4. Полное тестирование через сайты (с retry)
    russian_works = False
    russian_time = 0
    russian_reason = ""

    for site in CFG.RUSSIAN_TEST_SITES:
        success, reason, elapsed = test_site_with_retry(port, site, retries=CFG.RETRY_ATTEMPTS)
        if success:
            russian_works = True
            russian_time = elapsed
            russian_reason = reason
            break

    if not russian_works:
        return "none", f"РФ сайты недоступны"

    # Проверяем зарубежные сайты (меньше retry для скорости)
    foreign_works = False
    foreign_time = 0

    for site in CFG.FOREIGN_TEST_SITES:
        success, reason, elapsed = test_site_with_retry(port, site, retries=1)
        if success:
            foreign_works = True
            foreign_time = elapsed
            break

    # Определяем тип
    if russian_works and not foreign_works:
        return "white", f"Только РФ ({russian_time:.1f}s)"
    elif russian_works and foreign_works:
        return "universal", f"РФ+Зарубеж ({russian_time:.1f}s + {foreign_time:.1f}s)"
    else:
        return "none", "Частично работает"

# ==================== KEY LOADING ====================
def fetch_keys_from_url(url: str) -> List[str]:
    """Загружает ключи из URL"""
    try:
        print(f"📥 {url[:60]}...")
        response = requests.get(url, timeout=30)
        response.raise_for_status()
        content = response.text.strip()

        if not any(content.startswith(p) for p in ["vless://", "vmess://", "trojan://", "ss://"]):
            try:
                import base64
                missing_padding = len(content) % 4
                if missing_padding:
                    content += '=' * (4 - missing_padding)
                content = base64.b64decode(content).decode('utf-8')
            except:
                pass

        lines = content.replace('\r\n', '\n').replace('\r', '\n').split('\n')
        keys = [line.strip() for line in lines
                if line.strip() and any(line.startswith(p) for p in ["vless://", "vmess://", "trojan://", "ss://"])]

        print(f"   ✅ {len(keys)} ключей")
        return keys
    except Exception as e:
        print(f"   ❌ {e}")
        return []


def load_all_keys(sources: List[str], max_keys: int) -> List[str]:
    """Загружает все ключи"""
    print("\n" + "="*70)
    print("ЗАГРУЗКА КЛЮЧЕЙ")
    print("="*70)

    all_keys = []
    for url in sources:
        keys = fetch_keys_from_url(url)
        all_keys.extend(keys)

    unique_keys = list(dict.fromkeys(all_keys))
    if len(unique_keys) > max_keys:
        unique_keys = unique_keys[:max_keys]

    print(f"\n📊 Уникальных ключей: {len(unique_keys)}")
    return unique_keys

# ==================== KEY CHECKING ====================
def check_single_key(key: str, key_index: int) -> Tuple[bool, str, Optional[str], str, str]:
    """
    УЛУЧШЕНО: Проверяет один ключ с детальной диагностикой
    Возвращает: (успех, причина, ключ, тип, детали)
    """
    port = CFG.SOCKS_PORT_START + (key_index % 500)
    config = create_xray_config(key, port)

    if not config:
        return False, "Ошибка парсинга", None, "none", "Не удалось разобрать ключ"

    with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
        json.dump(config, f, indent=2)
        config_path = f.name

    xray = None
    try:
        xray = XrayManager(config_path, port)

        # Запускаем Xray
        if not xray.start():
            xray.stop()
            os.unlink(config_path)
            return False, "Xray не запустился", None, "none", "Процесс Xray упал"

        # Проверяем что процесс жив
        if xray.process.poll() is not None:
            xray.stop()
            os.unlink(config_path)
            return False, "Xray упал", None, "none", "Процесс завершился сразу"

        # Определяем тип ключа (с детальной диагностикой)
        key_type, details = check_key_type(key, port)

        xray.stop()
        os.unlink(config_path)

        if key_type == "white":
            return True, "Белый список", key, "white", details
        elif key_type == "universal":
            return True, "Универсальный", key, "universal", details
        else:
            return False, "Не работает", None, "none", details

    except Exception as e:
        if xray:
            xray.stop()
        try:
            os.unlink(config_path)
        except:
            pass
        return False, f"Ошибка", None, "none", str(e)[:50]


def check_keys(keys: List[str], max_workers: int) -> Tuple[List[str], List[str]]:
    """Проверяет ключи"""
    print("\n" + "="*70)
    print("ПРОВЕРКА КЛЮЧЕЙ (УЛУЧШЕННАЯ)")
    print("="*70)
    print(f"\n⚙️  Настройки:")
    print(f"   • Startup wait: {CFG.XRAY_STARTUP_WAIT}s")
    print(f"   • Connection timeout: {CFG.CONNECTION_TIMEOUT}s")
    print(f"   • Request timeout: {CFG.REQUEST_TIMEOUT}s")
    print(f"   • Retry попыток: {CFG.RETRY_ATTEMPTS}")
    print(f"   • Задержка retry: {CFG.RETRY_DELAY}s")
    print(f"\n⚠️  Проверка типа ключа:")
    print(f"   🏳️  Белый список = РФ работает, зарубеж НЕТ")
    print(f"   🌍 Универсальный = всё работает\n")

    white_keys = []
    universal_keys = []
    total = len(keys)
    checked = 0
    failed = 0

    print(f"🔄 Проверка {total} ключей (потоков: {max_workers})...\n")

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {
            executor.submit(check_single_key, key, idx): (key, idx)
            for idx, key in enumerate(keys)
        }

        for future in as_completed(futures):
            checked += 1
            try:
                success, reason, working_key, key_type, details = future.result(timeout=CFG.TOTAL_TIMEOUT)

                if success and working_key:
                    if key_type == "white":
                        white_keys.append(working_key)
                        print(f"🏳️  [{checked}/{total}] {reason} - {details} (Белых: {len(white_keys)})")
                    elif key_type == "universal":
                        universal_keys.append(working_key)
                        print(f"🌍 [{checked}/{total}] {reason} - {details} (Универс: {len(universal_keys)})")
                else:
                    failed += 1
                    # Показываем каждую 10-ю ошибку с деталями
                    if checked % 10 == 0:
                        print(f"❌ [{checked}/{total}] {reason} - {details} (Всего не работает: {failed})")
            except Exception as e:
                failed += 1
                print(f"⚠️  [{checked}/{total}] Timeout/Error: {str(e)[:30]}")

    print(f"\n{'='*70}")
    print(f"📊 РЕЗУЛЬТАТ:")
    print(f"   🏳️  Белый список: {len(white_keys)}")
    print(f"   🌍 Универсальные: {len(universal_keys)}")
    print(f"   ❌ Не работают: {failed}")
    print(f"   📈 Успешных: {len(white_keys) + len(universal_keys)}/{total} ({((len(white_keys) + len(universal_keys))/total*100):.1f}%)")
    print(f"{'='*70}")

    return white_keys, universal_keys

# ==================== SAVING ====================
def save_keys(white_keys: List[str], universal_keys: List[str]):
    """Сохраняет ключи в правильную структуру"""
    print("\n" + "="*70)
    print("СОХРАНЕНИЕ")
    print("="*70)

    # Создаем директории
    os.makedirs(CFG.RU_DIR, exist_ok=True)
    os.makedirs(CFG.EURO_DIR, exist_ok=True)

    # 1. RU_Best/ru_white.txt
    if white_keys:
        ru_white_file = os.path.join(CFG.RU_DIR, "ru_white.txt")
        with open(ru_white_file, 'w', encoding='utf-8') as f:
            f.write('\n'.join(white_keys))
        print(f"\n🏳️  {ru_white_file}")
        print(f"   Белый список: {len(white_keys)} ключей")

    # 2. My_Euro/euro_universal.txt и euro_black.txt
    if universal_keys:
        euro_universal_file = os.path.join(CFG.EURO_DIR, "euro_universal.txt")
        with open(euro_universal_file, 'w', encoding='utf-8') as f:
            f.write('\n'.join(universal_keys))
        print(f"\n🌍 {euro_universal_file}")
        print(f"   Универсальные: {len(universal_keys)} ключей")

        # Создаем пустой black (пока)
        euro_black_file = os.path.join(CFG.EURO_DIR, "euro_black.txt")
        with open(euro_black_file, 'w', encoding='utf-8') as f:
            f.write("")
        print(f"\n⚫ {euro_black_file}")
        print(f"   Черный список: 0 ключей (пока пусто)")

    # 3. subscriptions_list.txt
    subscriptions_file = os.path.join(CFG.CHECKED_DIR, "subscriptions_list.txt")
    with open(subscriptions_file, 'w', encoding='utf-8') as f:
        f.write("=== 🇷🇺 РОССИЯ ===\n\n")
        f.write("⚪ БЕЛЫЙ СПИСОК:\n")
        f.write("https://raw.githubusercontent.com/Mihuil121/vpn-checker-backend-fox/main/checked/RU_Best/ru_white.txt\n\n")

        f.write("=== 🇪🇺 ЕВРОПА ===\n\n")
        f.write("⚫ ЧЕРНЫЙ СПИСОК:\n")
        f.write("https://raw.githubusercontent.com/Mihuil121/vpn-checker-backend-fox/main/checked/My_Euro/euro_black.txt\n\n")
        f.write("🔘 УНИВЕРСАЛЬНЫЕ:\n")
        f.write("https://raw.githubusercontent.com/Mihuil121/vpn-checker-backend-fox/main/checked/My_Euro/euro_universal.txt\n")

    print(f"\n📋 {subscriptions_file}")
    print(f"   Файл подписок создан")

# ==================== MAIN ====================
def main():
    print("\n" + "="*70)
    print(" VPN Checker v3.1 - УЛУЧШЕННАЯ ПРОВЕРКА СОЕДИНЕНИЙ")
    print("="*70)
    print("\n📌 Что нового:")
    print("   ✅ Проверка открытия SOCKS5 портов")
    print("   ✅ Retry логика (2 попытки с задержкой)")
    print("   ✅ Увеличенные таймауты (5s startup, 15s request)")
    print("   ✅ Измерение времени ответа")
    print("   ✅ Детальное логирование ошибок\n")

    if not os.path.exists(CFG.XRAY_PATH):
        print(f"\n❌ Xray не найден: {CFG.XRAY_PATH}")
        return

    try:
        subprocess.run(["curl", "--version"], capture_output=True, check=True)
    except:
        print("\n❌ curl не установлен")
        return

    try:
        keys = load_all_keys(CFG.SOURCES, CFG.MAX_KEYS)

        if not keys:
            print("\n❌ Не удалось загрузить ключи")
            return

        white_keys, universal_keys = check_keys(keys, CFG.MAX_WORKERS)

        if white_keys or universal_keys:
            save_keys(white_keys, universal_keys)
        else:
            print("\n⚠️  Рабочих ключей не найдено")

        print("\n✅ ГОТОВО!\n")

    except KeyboardInterrupt:
        print("\n\n⚠️  Прервано")
    except Exception as e:
        print(f"\n\n❌ Ошибка: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    main()
