#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
VPN Checker v3.0 - Проверка с определением белого списка
Распределение: RU_Best/ru_white.txt и My_Euro/euro_*.txt
"""

import os
import json
import time
import subprocess
import tempfile
import requests
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Optional, Tuple
from dataclasses import dataclass
import signal

# ==================== КОНФИГУРАЦИЯ ====================
@dataclass
class Config:
    """Настройки приложения"""
    XRAY_PATH: str = "/home/misha/vpn-checker-backend-fox/Xray-linux-64/xray"

    # Новая структура папок
    CHECKED_DIR: str = "checked"
    RU_DIR: str = "checked/RU_Best"
    EURO_DIR: str = "checked/My_Euro"

    SOCKS_PORT_START: int = 20000
    TIMEOUT: int = 15

    MAX_WORKERS: int = 10
    MAX_KEYS: int = 99999

    # URL для проверки белого списка
    RUSSIAN_TEST_SITES: List[str] = None
    FOREIGN_TEST_SITES: List[str] = None

    SOURCES: List[str] = None

    def __post_init__(self):
        # Сайты для проверки белого списка
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

            time.sleep(3)

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

# ==================== TESTING ====================
def test_site(port: int, url: str, timeout: int = 10) -> bool:
    """Проверяет доступность сайта через прокси"""
    try:
        result = subprocess.run(
            ["curl", "-x", f"socks5h://127.0.0.1:{port}", "-m", str(timeout),
             "-s", "-o", "/dev/null", "-w", "%{http_code}", url],
            capture_output=True,
            timeout=timeout + 2
        )
        response_code = result.stdout.decode().strip()
        return response_code in ["200", "204", "301", "302"]
    except:
        return False

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

def check_key_type(key: str, port: int) -> str:
    """
    Определяет тип ключа с приоритетом:
    1. CIDR (если российские IP)
    2. SNI/домен (если российский)
    3. Маркеры в названии
    4. Тест через сайты
    """
    # 1. Проверяем CIDR и SNI в самом ключе
    try:
        from urllib.parse import parse_qs, unquote

        # Извлекаем параметры из ключа
        if "?" in key:
            params_part = key.split("?")[1].split("#")[0]
            query = parse_qs(params_part)

            # Проверяем SNI
            sni = query.get("sni", [None])[0]
            if sni and is_russian_domain(sni):
                return "white"

            # Проверяем dest (CIDR)
            dest = query.get("dest", [None])[0]
            if dest and is_russian_cidr(dest):
                return "white"

        # Проверяем host в самом адресе
        if "@" in key:
            host_part = key.split("@")[1].split(":")[0].split("?")[0]
            if is_russian_cidr(host_part):
                return "white"
    except:
        pass

    # 2. Проверяем маркеры в названии/комментарии
    if has_white_markers(key):
        # Если есть маркеры белого списка - проверяем что хоть что-то работает
        if test_site(port, CFG.RUSSIAN_TEST_SITES[0], timeout=5):
            return "white"

    # 3. Тест через сайты (только если не определили по параметрам)
    russian_works = False
    for site in CFG.RUSSIAN_TEST_SITES:
        if test_site(port, site, timeout=8):
            russian_works = True
            break

    if not russian_works:
        return "none"

    # Проверяем зарубежные сайты
    foreign_works = False
    for site in CFG.FOREIGN_TEST_SITES:
        if test_site(port, site, timeout=8):
            foreign_works = True
            break

    # Определяем тип
    if russian_works and not foreign_works:
        return "white"
    elif russian_works and foreign_works:
        return "universal"
    else:
        return "none"

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
def check_single_key(key: str, key_index: int) -> Tuple[bool, str, Optional[str], str]:
    """Проверяет один ключ. Возвращает: (успех, причина, ключ, тип)"""
    port = CFG.SOCKS_PORT_START + (key_index % 500)
    config = create_xray_config(key, port)

    if not config:
        return False, "Ошибка парсинга", None, "none"

    with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
        json.dump(config, f, indent=2)
        config_path = f.name

    xray = None
    try:
        xray = XrayManager(config_path, port)

        if not xray.start():
            xray.stop()
            os.unlink(config_path)
            return False, "Xray не запустился", None, "none"

        # Определяем тип ключа (передаем сам ключ для анализа)
        key_type = check_key_type(key, port)

        xray.stop()
        os.unlink(config_path)

        if key_type == "white":
            return True, "Белый список", key, "white"
        elif key_type == "universal":
            return True, "Универсальный", key, "universal"
        else:
            return False, "Не работает", None, "none"

    except Exception as e:
        if xray:
            xray.stop()
        try:
            os.unlink(config_path)
        except:
            pass
        return False, f"Ошибка: {str(e)[:30]}", None, "none"

def check_keys(keys: List[str], max_workers: int) -> Tuple[List[str], List[str]]:
    """Проверяет ключи. Возвращает: (white_keys, universal_keys)"""
    print("\n" + "="*70)
    print("ПРОВЕРКА КЛЮЧЕЙ")
    print("="*70)
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
                success, reason, working_key, key_type = future.result(timeout=CFG.TIMEOUT + 15)

                if success and working_key:
                    if key_type == "white":
                        white_keys.append(working_key)
                        print(f"🏳️  [{checked}/{total}] {reason} (Белых: {len(white_keys)})")
                    elif key_type == "universal":
                        universal_keys.append(working_key)
                        print(f"🌍 [{checked}/{total}] {reason} (Универс: {len(universal_keys)})")
                else:
                    failed += 1
                    if checked % 10 == 0:
                        print(f"❌ [{checked}/{total}] {reason} (Не работает: {failed})")
            except:
                failed += 1
                print(f"⚠️  [{checked}/{total}] Timeout")

    print(f"\n{'='*70}")
    print(f"📊 РЕЗУЛЬТАТ:")
    print(f"   🏳️  Белый список: {len(white_keys)}")
    print(f"   🌍 Универсальные: {len(universal_keys)}")
    print(f"   ❌ Не работают: {failed}")
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
        # Разделим на черный список и универсальные (пока все в universal)
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
    print(" VPN Checker v3.0 - Белый список + структура")
    print("="*70)

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
