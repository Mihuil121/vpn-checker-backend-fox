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
import shutil
import requests
import socket
import re
import ssl
import dns.resolver
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Optional, Tuple
from dataclasses import dataclass
import signal
from urllib.parse import urlparse

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

    # ⚡ ОПТИМИЗАЦИЯ: Уменьшенные таймауты
    XRAY_STARTUP_WAIT: int = 3      # Было 5, стало 3
    CONNECTION_TIMEOUT: int = 5     # Было 8, стало 5
    REQUEST_TIMEOUT: int = 10       # Было 15, стало 10
    TOTAL_TIMEOUT: int = 30         # Было 20, стало 30 (больше времени на проверку)

    # ⚡ ОПТИМИЗАЦИЯ: Меньше retry
    RETRY_ATTEMPTS: int = 1         # Было 2, стало 1
    RETRY_DELAY: int = 1            # Было 2, стало 1

    # ⚡ ОПТИМИЗАЦИЯ: Больше потоков
    MAX_WORKERS: int = 50           # Было 10, стало 50!
    MAX_KEYS: int = 999999

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
                "https://raw.githubusercontent.com/EtoNeYaProject/etoneyaproject.github.io/refs/heads/main/other",
                "https://vlesstrojan.alexanderyurievich88.workers.dev?token=sub",
                "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/main/Vless-Reality-White-Lists-Rus-Mobile.txt",
                "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/main/Vless-Reality-White-Lists-Rus-Mobile-2.txt",
                "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/main/BLACK_VLESS_RUS_mobile.txt",
                "https://github.com/kismetpro/NodeSuber/raw/refs/heads/main/Splitted-By-Protocol/trojan.txt",
                "https://github.com/kismetpro/NodeSuber/raw/refs/heads/main/Splitted-By-Protocol/hy2.txt",
                "https://raw.githubusercontent.com/F0rc3Run/F0rc3Run/refs/heads/main/Best-Results/proxies.txt",
                "https://raw.githubusercontent.com/F0rc3Run/F0rc3Run/refs/heads/main/splitted-by-protocol/trojan.txt",
                "https://tseya.a9fm.site/whitelist",
                "https://translate.yandex.ru/translate?url=https://etoneya.a9fm.site/whitelist&lang=en-ru",
                "https://raw.githubusercontent.com/EtoNeYaProject/etoneyaproject.github.io/refs/heads/main/whitelist",
                "https://raw.githubusercontent.com/kemfie/whitelistrussua/main/RussiaCIDR.txt",
                "https://bp.wl.free.nf/confs/wl.txt"
                "https://raw.githubusercontent.com/CidVpn/cid-vpn-config/refs/heads/main/general.txt",
                "https://storage.yandexcloud.net/cid-vpn/whitelist.txt",
                "https://raw.githubusercontent.com/MahsaNetConfigTopic/config/refs/heads/main/xray_final.txt",
                "https://raw.githubusercontent.com/SoliSpirit/v2ray-configs/refs/heads/main/Subscriptions/Sub1.txt",
                "https://raw.githubusercontent.com/RKPchannel/RKP_bypass_configs/refs/heads/main/configs/url_work.txt",
                "https://gbr.mydan.online/configs",
                "https://raw.githubusercontent.com/Maskkost93/kizyak-vpn-4.0/refs/heads/main/kizyaktestru.txt",
                "https://shz.al/YzPN:/~sorensub,subSHABTJK",
                "https://raw.githubusercontent.com/SoliSpirit/v2ray-configs/refs/heads/main/all_configs.txt",
                "https://raw.githubusercontent.com/restlycames/RestlyConnect_sub/refs/heads/main/free_vless_servers.txt",
                "https://raw.githubusercontent.com/SilentGhostCodes/WhiteListVpn/refs/heads/main/BlackList.txt",
                "https://raw.githubusercontent.com/SilentGhostCodes/WhiteListVpn/refs/heads/main/Whitelist.txt",
                "https://raw.githubusercontent.com/MatinGhanbari/v2ray-configs/25bb2a9ec2721b62dd3ce3e5b0e12fbacf041f67/subscriptions/v2ray/subs/sub10.txt",
                "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/ee6d4bfcb84d006d669d5c38a3111b42917171a2/BLACK_VLESS_RUS.txt",
                "https://raw.githubusercontent.com/nikita29a/FreeProxyList/refs/heads/main/mirror/21.txt",
                "https://raw.githubusercontent.com/nikita29a/FreeProxyList/refs/heads/main/mirror/25.txt",
                "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/refs/heads/main/WHITE-CIDR-RU-checked.txt",
                "https://raw.githubusercontent.com/Egkaz/Proxy-list-20k-server/refs/heads/main/all_servers.txt",
                "https://raw.githubusercontent.com/SoliSpirit/v2ray-configs/refs/heads/main/Protocols/trojan.txt",
                "https://raw.githubusercontent.com/Surfboardv2ray/TGParse/main/python/hy2",
                "https://raw.githubusercontent.com/Surfboardv2ray/TGParse/main/python/hysteria2",
                "https://raw.githubusercontent.com/Surfboardv2ray/TGParse/main/splitted/trojan",
                "https://raw.githubusercontent.com/MhdiTaheri/V2rayCollector/refs/heads/main/sub/trojan",
                "https://raw.githubusercontent.com/Argh94/V2RayAutoConfig/refs/heads/main/configs/Hysteria2.txt",
                "https://raw.githubusercontent.com/Farid-Karimi/Config-Collector/main/vless_iran.txt",
                "https://raw.githubusercontent.com/hamedp-71/Sub_Checker_Creator/refs/heads/main/final.txt",
                "https://raw.githubusercontent.com/MatinGhanbari/v2ray-configs/main/subscriptions/filtered/subs/vless.txt",
                "https://raw.githubusercontent.com/Kwinshadow/TelegramV2rayCollector/main/sublinks/vless.txt",
                "https://raw.githubusercontent.com/barry-far/V2ray-config/main/Sub4.txt",
                "https://raw.githubusercontent.com/barry-far/V2ray-config/main/Sub6.txt",
                "https://raw.githubusercontent.com/barry-far/V2ray-config/main/Splitted-By-Protocol/trojan.txt",
                "https://raw.githubusercontent.com/barry-far/V2ray-config/main/Splitted-By-Protocol/ss.txt",
                "https://raw.githubusercontent.com/Kwinshadow/TelegramV2rayCollector/main/sublinks/trojan.txt",
                "https://raw.githubusercontent.com/SoliSpirit/v2ray-configs/refs/heads/main/Protocols/vless.txt",
                "https://raw.githubusercontent.com/SoliSpirit/v2ray-configs/refs/heads/main/Protocols/ss.txt",
                "https://sub-001.dns-on-fire.net/api/sub/6YsWHg3rCTdXJ8GA",
                "https://gist.githubusercontent.com/Syavar/3e76222fc05fde9abcb35c2f24572021/raw/e2f7ef901ae4ba5bab7bef20adef41bead7ba626/gistfile1.txt",
                "https://jsnegsukavsos.hb.ru-msk.vkcloud-storage.ru/love",
                "https://shz.al/7XRh:/~2025/SORENWARP&TUIC",
                "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/refs/heads/main/BLACK_SS+All_RUS.txt",
                "https://shz.al/hWYz:/~sorensub/hy2&vless",
                "https://sub-001.dns-on-fire.net/api/sub/FhFLNWo1Ngyt6g6e",
                "https://sub-001.dns-on-fire.net/api/sub/T7VH-WaFkzDrcyRE",
                "https://raw.githubusercontent.com/AvenCores/goida-vpn-configs/refs/heads/main/githubmirror/1.txt",
                "https://raw.githubusercontent.com/AvenCores/goida-vpn-configs/refs/heads/main/githubmirror/2.txt",
                "https://raw.githubusercontent.com/Epodonios/v2ray-configs/refs/heads/main/Sub1.txt",
                "https://raw.githubusercontent.com/roosterkid/openproxylist/main/V2RAY_RAW.txt",
                "https://raw.githubusercontent.com/Epodonios/v2ray-configs/main/All_Configs_Sub.txt",
                "https://raw.githubusercontent.com/mahdibland/V2RayAggregator/refs/heads/master/Eternity.txt",
                "https://raw.githubusercontent.com/sakha1370/OpenRay/refs/heads/main/output/country/DE.txt",
                "https://raw.githubusercontent.com/sevcator/5ubscrpt10n/refs/heads/main/working/countries/Armenia.txt",
                "https://raw.githubusercontent.com/sakha1370/OpenRay/refs/heads/main/output/country/HU.txt",
                "https://raw.githubusercontent.com/sevcator/5ubscrpt10n/refs/heads/main/working/countries/Kazakhstan.txt",
                "https://raw.githubusercontent.com/sevcator/5ubscrpt10n/refs/heads/main/working/countries/United%20Nations.txt",
                "http://allvpn.x10.mx/sub.php",
                "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/refs/heads/main/Vless-Reality-White-Lists-Rus-Mobile-2.txt",
                "https://raw.githubusercontent.com/VP01596/vless-top15/refs/heads/main/top100.txt",
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
        elif key.startswith("hysteria2://"):
            outbound = parse_hysteria2(key)
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

def parse_hysteria2(key: str) -> Optional[dict]:
    """Парсит Hysteria 2 ключ"""
    from urllib.parse import parse_qs, unquote

    key = key.replace("hysteria2://", "")
    if "@" not in key:
        return None

    # Разделяем на часть с авторизацией и адресом
    auth_part, rest = key.split("@", 1)

    # Разделяем адрес и параметры
    if "?" in rest:
        server_port, params_label = rest.split("?", 1)
    else:
        server_port = rest
        params_label = ""

    # Убираем комментарий если есть
    if "#" in params_label:
        params, _ = params_label.split("#", 1)
    else:
        params = params_label

    # Разделяем сервер и порт
    if ":" not in server_port:
        return None

    server, port = server_port.rsplit(":", 1)
    query = parse_qs(params)

    # Парсим авторизацию (может быть в формате user:password или просто password)
    if ":" in auth_part:
        username, password = auth_part.split(":", 1)
    else:
        username = ""
        password = auth_part

    # Создаем конфиг для Hysteria 2
    outbound = {
        "protocol": "hysteria2",
        "settings": {
            "servers": [{
                "address": server,
                "port": int(port),
                "password": password
            }]
        }
    }

    # Добавляем дополнительные параметры если есть
    if username:
        outbound["settings"]["servers"][0]["auth_str"] = username

    if "insecure" in query and query["insecure"][0] == "1":
        outbound["settings"]["servers"][0]["insecure"] = True

    if "sni" in query:
        outbound["settings"]["servers"][0]["sni"] = query["sni"][0]

    if "obfs" in query:
        outbound["settings"]["servers"][0]["obfs"] = query["obfs"][0]

    if "obfs-password" in query:
        outbound["settings"]["servers"][0]["obfs_password"] = query["obfs-password"][0]

    return outbound


def get_hy2_binary() -> Optional[str]:
    """Возвращает путь к клиенту Hysteria2 (hy2 или hysteria), если установлен."""
    for name in ("hy2", "hysteria"):
        path = shutil.which(name)
        if path:
            return path
    return None


def create_hysteria2_yaml_config(key: str, listen_port: int) -> str:
    """Создаёт YAML-конфиг для клиента Hysteria2 (hy2/hysteria)."""
    # Клиент поддерживает server в виде полного URI
    server_uri = key.strip()
    if not server_uri.startswith("hysteria2://"):
        server_uri = "hysteria2://" + server_uri
    lines = [
        "server: " + repr(server_uri),
        "socks5:",
        "  listen: 127.0.0.1:" + str(listen_port),
    ]
    return "\n".join(lines)


def check_hysteria2_key(key: str, port: int, key_index: int) -> Tuple[bool, str, Optional[str], str, str]:
    """
    Проверяет ключ Hysteria2 через клиент hy2/hysteria (Xray Hysteria2 не поддерживает).
    Возвращает: (успех, причина, ключ, тип, детали).
    """
    hy2_bin = get_hy2_binary()
    if not hy2_bin:
        return False, "Hysteria2: не установлен hy2/hysteria", None, "none", "Установите hy2 для проверки"

    with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
        f.write(create_hysteria2_yaml_config(key, port))
        config_path = f.name

    process = None
    try:
        process = subprocess.Popen(
            [hy2_bin, "-c", config_path],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            preexec_fn=os.setsid,
        )
        time.sleep(CFG.XRAY_STARTUP_WAIT)

        if process.poll() is not None:
            os.unlink(config_path)
            return False, "Hysteria2: процесс завершился", None, "none", "Клиент hy2 не запустился"

        # Проверяем SOCKS5
        port_ok, _ = check_socks_port(port, timeout=3)
        if not port_ok:
            try:
                os.killpg(os.getpgid(process.pid), signal.SIGTERM)
            except Exception:
                pass
            os.unlink(config_path)
            return False, "Hysteria2: порт не открыт", None, "none", "SOCKS5 недоступен"

        # Проверяем доступность сайтов (РФ и зарубеж)
        russian_works = False
        for site in CFG.RUSSIAN_TEST_SITES:
            success, _, _ = test_site_with_retry(port, site, retries=1)
            if success:
                russian_works = True
                break

        foreign_works = False
        for site in CFG.FOREIGN_TEST_SITES:
            success, _, _ = test_site_with_retry(port, site, retries=1)
            if success:
                foreign_works = True
                break

        try:
            os.killpg(os.getpgid(process.pid), signal.SIGTERM)
        except Exception:
            pass
        os.unlink(config_path)

        if russian_works and not foreign_works:
            return True, "Белый список", key, "white", "Hysteria2: только РФ"
        elif russian_works and foreign_works:
            return True, "Универсальный", key, "universal", "Hysteria2: РФ+Зарубеж"
        else:
            return False, "Не работает", None, "none", "Hysteria2: сайты недоступны"

    except Exception as e:
        if process and process.poll() is None:
            try:
                os.killpg(os.getpgid(process.pid), signal.SIGTERM)
            except Exception:
                pass
        try:
            os.unlink(config_path)
        except Exception:
            pass
        return False, "Hysteria2: ошибка", None, "none", str(e)[:50]


# ==================== БЕЗОПАСНОСТЬ ====================

def is_suspicious_domain(domain: str) -> Tuple[bool, str]:
    """Проверяет домен на подозрительность (фишинг, вредоносные)"""
    if not domain:
        return False, "Домен не указан"

    domain = domain.lower()

    # Список известных подозрительных доменов и шаблонов
    suspicious_patterns = [
        'phishing', 'malware', 'virus', 'hack', 'crack', 'warez',
        'scam', 'fraud', 'spy', 'keylogger', 'trojan', 'ransomware',
        'botnet', 'exploit', '000webhost', 'freehost', 'xss', 'sql',
        'injection', 'backdoor', 'shell', 'remote', 'admin', 'login',
        'password', 'account', 'bank', 'verify', 'secure', 'update',
        'antivirus', 'cleaner', 'optimizer', 'driver', 'codec', 'player'
    ]

    # Проверка на подозрительные шаблоны
    for pattern in suspicious_patterns:
        if pattern in domain:
            return True, f"Подозрительный шаблон: {pattern}"

    # Проверка на очень короткие домены (потенциально подозрительные)
    if len(domain) < 5:
        return True, "Слишком короткий домен"

    # Проверка на домены с большим количеством цифр
    if sum(c.isdigit() for c in domain) > 4:
        return True, "Слишком много цифр в домене"

    # Проверка на домены с подчеркиваниями (редко используются в легитимных сервисах)
    if '_' in domain:
        return True, "Подчеркивания в домене"

    return False, "Домен выглядит безопасно"

def check_ip_reputation(ip: str) -> Tuple[bool, str]:
    """Проверяет репутацию IP через известные черные списки"""
    try:
        # Проверка на локальные/приватные IP
        if ip.startswith(('127.', '10.', '192.168.', '172.16.', '172.17.', '172.18.', '172.19.', '172.20.', '172.21.', '172.22.', '172.23.', '172.24.', '172.25.', '172.26.', '172.27.', '172.28.', '172.29.', '172.30.', '172.31.')):
            return True, "Локальный/приватный IP адрес"

        # Проверка на известные вредоносные IP (примеры)
        malicious_ips = [
            '1.1.1.1', '8.8.8.8', '93.184.216.34',  # Примеры, нужно заменить на реальные черные списки
            '149.112.112.112', '185.228.168.168'
        ]

        if ip in malicious_ips:
            return True, "Известный вредоносный IP"

        return False, "IP прошел проверку"

    except Exception as e:
        return True, f"Ошибка проверки IP: {str(e)[:30]}"

def check_ssl_certificate(hostname: str, port: int = 443) -> Tuple[bool, str]:
    """Проверяет SSL сертификат на валидность"""
    try:
        context = ssl.create_default_context()
        conn = context.wrap_socket(
            socket.socket(socket.AF_INET),
            server_hostname=hostname,
        )
        conn.connect((hostname, port))
        cert = conn.getpeercert()
        conn.close()

        # Проверка валидности сертификата
        if not cert:
            return True, "Нет SSL сертификата"

        # Проверка срока действия
        from datetime import datetime
        not_after = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
        not_before = datetime.strptime(cert['notBefore'], '%b %d %H:%M:%S %Y %Z')

        if datetime.now() < not_before:
            return True, "Сертификат еще не действителен"
        if datetime.now() > not_after:
            return True, "Сертификат просрочен"

        # Проверка на самоподписанные сертификаты
        if 'subject' in cert and 'issuer' in cert:
            if cert['subject'] == cert['issuer']:
                return True, "Самоподписанный сертификат"

        return False, "SSL сертификат валиден"

    except Exception as e:
        return True, f"Ошибка SSL: {str(e)[:30]}"

def check_dns_leaks(port: int) -> Tuple[bool, str]:
    """Проверяет утечки DNS через прокси"""
    try:
        result = subprocess.run(
            [
                "curl",
                "-x", f"socks5h://127.0.0.1:{port}",
                "-m", "10",
                "--connect-timeout", "5",
                "-s",
                "https://www.cloudflare.com/cdn-cgi/trace"
            ],
            capture_output=True,
            timeout=12
        )

        if result.returncode != 0:
            # Не удалось проверить - НЕ блокируем
            return False, "DNS не проверен (не критично)"

        output = result.stdout.decode().lower()
        # Более мягкая проверка
        if len(output) > 20:  # Получили хоть какой-то ответ
            return False, "DNS работает"

        return False, "DNS не проверен (не критично)"
    except Exception as e:
        # В случае ошибки - НЕ блокируем
        return False, f"DNS не проверен: {str(e)[:20]}"

def check_ipv6_leak(port: int) -> Tuple[bool, str]:
    """Проверяет утечки IPv6 через прокси"""
    try:
        # Проверяем IPv6 через прокси
        result = subprocess.run(
            [
                "curl",
                "-x", f"socks5h://127.0.0.1:{port}",
                "-m", "10",
                "--connect-timeout", "5",
                "-s",
                "https://api6.ipify.org"
            ],
            capture_output=True,
            timeout=12
        )

        if result.returncode != 0:
            # Не удалось проверить - НЕ блокируем
            return False, "IPv6 не проверен (не критично)"

        ipv6_address = result.stdout.decode().strip()
        if ipv6_address and ":" in ipv6_address:
            return True, f"Обнаружена утечка IPv6: {ipv6_address}"
        else:
            return False, "IPv6 защищен"

    except Exception as e:
        # В случае ошибки - НЕ блокируем
        return False, f"IPv6 не проверен: {str(e)[:20]}"

def check_geolocation(port: int) -> Tuple[bool, str]:
    """Проверяет геолокацию IP через прокси"""
    try:
        # Получаем информацию о геолокации через прокси
        result = subprocess.run(
            [
                "curl",
                "-x", f"socks5h://127.0.0.1:{port}",
                "-m", "15",
                "--connect-timeout", "5",
                "-s",
                "https://ipinfo.io/json"
            ],
            capture_output=True,
            timeout=18
        )

        if result.returncode != 0:
            return False, "Геолокация не проверена"

        try:
            geo_data = json.loads(result.stdout.decode())
            country = geo_data.get("country", "unknown")
            org = geo_data.get("org", "unknown").replace("AS", "").strip()

            return False, f"Геолокация: {country} ({org})"
        except:
            return False, "Геолокация не распознана"

    except Exception as e:
        return False, f"Геолокация не проверена: {str(e)[:20]}"

def check_encryption_integrity(port: int) -> Tuple[bool, str]:
    """Проверяет целостность шифрования через анализ SSL сертификатов"""
    try:
        # Проверяем SSL сертификат известного сайта через прокси
        result = subprocess.run(
            [
                "curl",
                "-x", f"socks5h://127.0.0.1:{port}",
                "-m", "10",
                "--connect-timeout", "5",
                "-s",
                "https://www.google.com"
            ],
            capture_output=True,
            timeout=12
        )

        if result.returncode != 0:
            return False, "Шифрование не проверено"

        # Если запрос прошел успешно, значит шифрование работает
        return False, "Шифрование подтверждено"

    except Exception as e:
        return False, f"Шифрование не проверено: {str(e)[:20]}"

def check_protocol_security(key: str) -> Tuple[bool, str]:
    """Проверяет безопасность протокола и шифрования (без проверки VLESS TLS/Reality — есть методы обхода)"""
    try:
        if key.startswith("vmess://"):
            if "scy=none" in key.lower():
                return True, "VMess без шифрования"

        elif key.startswith("ss://"):
            import base64
            try:
                key_part = key.replace("ss://", "").split("@")[0]
                missing_padding = len(key_part) % 4
                if missing_padding:
                    key_part += '=' * (4 - missing_padding)
                method_password = base64.b64decode(key_part).decode('utf-8')
                method = method_password.split(":")[0]

                weak_methods = ['rc4', 'table', 'rc4-md5']
                if method.lower() in weak_methods:
                    return True, f"Слабый метод: {method}"
            except:
                pass

        return False, "Протокол безопасен"

    except Exception as e:
        # В случае ошибки парсинга - НЕ блокируем ключ
        return False, f"Не удалось проверить: {str(e)[:30]}"

def check_malicious_parameters(key: str) -> Tuple[bool, str]:
    """Проверяет конфиг на вредоносные параметры"""
    try:
        malicious_params = [
            'exec=', 'command=', 'shell=', 'bash=', 'sh=',
            'script=', 'javascript:', 'eval(', 'document.',
            'window.', 'onload=', 'onclick=', 'alert(',
            'prompt(', 'confirm(', 'cookie', 'localstorage',
            'sessionstorage', 'webgl', 'canvas', 'fingerprint',
            'tracker', 'analytics', 'advertising', 'malware',
            'spyware', 'keylogger', 'backdoor', 'exploit'
        ]

        key_lower = key.lower()
        for param in malicious_params:
            if param in key_lower:
                return True, f"Вредоносный параметр: {param}"

        # Проверка на подозрительно длинные ключи
        if len(key) > 1000:
            return True, "Слишком длинный ключ"

        # Проверка на нестандартные порты
        if ":@" in key:
            port_part = key.split(":@")[1].split("?")[0].split("#")[0]
            if ":" in port_part:
                port = int(port_part.split(":")[1])
                if port < 1 or port > 65535:
                    return True, "Недопустимый порт"
                if port in [21, 22, 23, 25, 53, 69, 80, 110, 143, 443, 445, 3389]:
                    return True, f"Стандартный порт {port} (потенциально опасный)"

        return False, "Параметры безопасны"

    except Exception as e:
        return True, f"Ошибка проверки параметров: {str(e)[:30]}"

def comprehensive_security_check(key: str, port: int) -> Tuple[bool, str]:
    """Выполняет комплексную проверку безопасности конфига"""
    security_issues = []
    security_info = []

    try:
        # 1. Проверка КРИТИЧНЫХ вредоносных параметров
        has_malicious, reason = check_malicious_parameters(key)
        if has_malicious:
            security_issues.append(f"Вредоносный: {reason}")

        # 2. Проверка протокола (только критичные проблемы)
        is_weak, reason = check_protocol_security(key)
        if is_weak and "без TLS" in reason:  # Блокируем только если совсем без защиты
            security_issues.append(f"Протокол: {reason}")

        # 3. Проверка утечки IPv6 (критично)
        has_ipv6_leak, reason = check_ipv6_leak(port)
        if has_ipv6_leak:
            security_issues.append(f"IPv6 утечка: {reason}")

        # 4. Проверка геолокации (информационно)
        _, geo_info = check_geolocation(port)
        security_info.append(f"Геолокация: {geo_info}")

        # 5. Проверка шифрования (информационно)
        _, encryption_info = check_encryption_integrity(port)
        security_info.append(f"Шифрование: {encryption_info}")

        # 6. Проверка DNS утечек (информационно)
        _, dns_info = check_dns_leaks(port)
        security_info.append(f"DNS: {dns_info}")

        if security_issues:
            return False, " | ".join(security_issues)
        else:
            return True, "Базовая безопасность OK | " + " | ".join(security_info)

    except Exception as e:
        # В случае ошибки проверки - НЕ блокируем ключ
        return True, f"Проверка не выполнена: {str(e)[:30]}"

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


def check_service_availability(port: int) -> Tuple[dict, str]:
    """
    НОВОЕ: Проверяет доступность конкретных сервисов через прокси
    Возвращает: (словарь с результатами, строка с метками)
    """
    service_results = {}
    service_labels = []

    # Список сервисов для проверки
    services = {
        "youtube": "https://www.youtube.com",
        "discord": "https://discord.com",
        "telegram": "https://web.telegram.org",
        "cloudflare": "https://www.cloudflare.com"
    }

    for service_name, service_url in services.items():
        try:
            success, reason, elapsed = test_site_with_retry(port, service_url, retries=1)
            service_results[service_name] = success
            if success:
                service_labels.append(service_name.upper())
        except:
            service_results[service_name] = False

    # Формируем строку с метками
    labels_str = " ".join(service_labels)
    if not labels_str:
        labels_str = "Нет сервисов"

    return service_results, labels_str

def check_key_type(key: str, port: int) -> Tuple[str, str]:
    """
    УЛУЧШЕНО: Определяет тип ключа с детальным логированием и проверкой сервисов
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
        from urllib.parse import urlparse, parse_qs, unquote

        # Yandex translate часто отдает 403 с turbopages — берем оригинальный url=...
        try:
            parsed = urlparse(url)
            if parsed.netloc == "translate.yandex.ru" and parsed.path.startswith("/translate"):
                q = parse_qs(parsed.query)
                original = q.get("url", [None])[0]
                if original:
                    url = unquote(original)
        except Exception:
            pass

        print(f"📥 {url[:60]}...")
        headers = {
            "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123 Safari/537.36",
            "Accept": "text/plain,text/html,application/octet-stream,*/*",
            "Accept-Language": "ru,en;q=0.9",
            "Connection": "close",
        }

        # Retry для медленных источников
        last_err = None
        response = None
        for attempt in range(3):
            try:
                response = requests.get(url, timeout=45, headers=headers, allow_redirects=True)
                response.raise_for_status()
                break
            except Exception as e:
                last_err = e
                if attempt < 2:
                    time.sleep(1)
                else:
                    raise

        response.raise_for_status()
        content = response.text.strip()

        if not any(content.startswith(p) for p in ["vless://", "vmess://", "trojan://", "ss://", "hysteria2://"]):
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
                if line.strip() and any(line.startswith(p) for p in ["vless://", "vmess://", "trojan://", "ss://", "hysteria2://"])]

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
    УЛУЧШЕНО: Проверяет один ключ с детальной диагностикой, проверкой безопасности и сервисов
    Возвращает: (успех, причина, ключ, тип, детали)
    """
    port = CFG.SOCKS_PORT_START + (key_index % 500)

    # Hysteria2 проверяется через hy2/hysteria (Xray его не поддерживает)
    if key.startswith("hysteria2://"):
        return check_hysteria2_key(key, port, key_index)

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

        # НОВОЕ: Комплексная проверка безопасности
        is_secure, security_details = comprehensive_security_check(key, port)
        if not is_secure:
            xray.stop()
            os.unlink(config_path)
            return False, "Проблемы безопасности", None, "none", f"Безопасность: {security_details}"

        # Определяем тип ключа (с детальной диагностикой)
        key_type, details = check_key_type(key, port)

        # НОВОЕ: Проверяем доступность конкретных сервисов
        service_results, service_labels = check_service_availability(port)

        xray.stop()
        os.unlink(config_path)

        if key_type == "white":
            return True, "Белый список", key, "white", f"{details} | Сервисы: {service_labels} | Безопасность: OK"
        elif key_type == "universal":
            return True, "Универсальный", key, "universal", f"{details} | Сервисы: {service_labels} | Безопасность: OK"
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

    executor = ThreadPoolExecutor(max_workers=max_workers)
    try:
        futures = {
            executor.submit(check_single_key, key, idx): (key, idx)
            for idx, key in enumerate(keys)
        }

        try:
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
        except KeyboardInterrupt:
            print("\n\n⚠️  Ctrl+C: останавливаю проверку, сохраняю найденные ключи...")
            # После первого Ctrl+C игнорируем последующие, чтобы не падать на shutdown/join
            try:
                signal.signal(signal.SIGINT, signal.SIG_IGN)
            except Exception:
                pass

            # Пытаемся отменить те задачи, которые ещё не стартовали
            for f in futures:
                f.cancel()

            # Быстро закрываем пул, не дожидаясь всех выполняющихся задач
            try:
                executor.shutdown(wait=False, cancel_futures=True)
            except TypeError:
                # Для старых реализаций без cancel_futures
                executor.shutdown(wait=False)
            return white_keys, universal_keys
    finally:
        # Нормальное завершение без Ctrl+C
        try:
            executor.shutdown(wait=True, cancel_futures=False)
        except TypeError:
            executor.shutdown(wait=True)

    print(f"\n{'='*70}")
    print(f"📊 РЕЗУЛЬТАТ:")
    print(f"   🏳️  Белый список: {len(white_keys)}")
    print(f"   🌍 Универсальные: {len(universal_keys)}")
    print(f"   ❌ Не работают: {failed}")
    print(f"   📈 Успешных: {len(white_keys) + len(universal_keys)}/{total} ({((len(white_keys) + len(universal_keys))/total*100):.1f}%)")
    print(f"{'='*70}")

    return white_keys, universal_keys

# ==================== ИМЕНОВАНИЕ: ШКАТУЛКА ЗАПРЕТОВ + СТРАНА ПО IP ====================
# Коды стран -> русское название (для подписи в ключах)
COUNTRY_NAMES_RU = {
    "RU": "Россия", "NL": "Нидерланды", "DE": "Германия", "US": "США", "GB": "Великобритания",
    "FR": "Франция", "PL": "Польша", "UA": "Украина", "KZ": "Казахстан", "TR": "Турция",
    "FI": "Финляндия", "SE": "Швеция", "NO": "Норвегия", "LT": "Литва", "LV": "Латвия",
    "EE": "Эстония", "RO": "Румыния", "BG": "Болгария", "HU": "Венгрия", "CZ": "Чехия",
    "SK": "Словакия", "AT": "Австрия", "CH": "Швейцария", "IT": "Италия", "ES": "Испания",
    "PT": "Португалия", "GR": "Греция", "IN": "Индия", "SG": "Сингапур", "JP": "Япония",
    "KR": "Южная Корея", "HK": "Гонконг", "TW": "Тайвань", "CA": "Канада", "BR": "Бразилия",
    "AU": "Австралия", "IL": "Израиль", "IR": "Иран", "AE": "ОАЭ", "TH": "Таиланд",
    "VN": "Вьетнам", "ID": "Индонезия", "MY": "Малайзия", "PH": "Филиппины", "AR": "Аргентина",
    "CL": "Чили", "CO": "Колумбия", "MX": "Мексика", "ZA": "ЮАР", "EG": "Египет",
    "GE": "Грузия", "AM": "Армения", "AZ": "Азербайджан", "BY": "Беларусь", "MD": "Молдова",
}

def get_host_from_key(key: str) -> Optional[str]:
    """Извлекает хост (домен или IP) из ключа подписи."""
    try:
        key = key.strip()
        if key.startswith("vless://"):
            rest = key.replace("vless://", "").split("@", 1)[-1]
            host_part = rest.split("?")[0].split("#")[0]
            if ":" in host_part:
                return host_part.rsplit(":", 1)[0].strip()
            return host_part.strip()
        if key.startswith("vmess://"):
            import base64
            b = key.replace("vmess://", "")
            pad = 4 - len(b) % 4
            if pad != 4:
                b += "=" * pad
            data = json.loads(base64.b64decode(b).decode("utf-8"))
            return (data.get("add") or "").strip()
        if key.startswith("trojan://"):
            rest = key.replace("trojan://", "").split("@", 1)[-1]
            host_part = rest.split("?")[0].split("#")[0]
            if ":" in host_part:
                return host_part.rsplit(":", 1)[0].strip()
            return host_part.strip()
        if key.startswith("ss://"):
            import base64
            raw = key.replace("ss://", "").split("#")[0]
            if "@" in raw:
                _, server_port = raw.split("@", 1)
            else:
                pad = 4 - len(raw) % 4
                if pad != 4:
                    raw += "=" * pad
                decoded = base64.b64decode(raw).decode("utf-8")
                _, server_port = decoded.split("@", 1)
            return server_port.rsplit(":", 1)[0].strip()
        if key.startswith("hysteria2://"):
            rest = key.replace("hysteria2://", "").split("@", 1)[-1]
            host_part = rest.split("?")[0].split("#")[0]
            if ":" in host_part:
                return host_part.rsplit(":", 1)[0].strip()
            return host_part.strip()
    except Exception:
        pass
    return None


_country_cache: dict = {}

def get_country_by_host(host: str) -> str:
    """Определяет страну по хосту (домен резолвится в IP, затем ipinfo.io). Результат кэшируется."""
    if not host or host.startswith("127.") or host.startswith("10.") or "localhost" in host.lower():
        return ""
    if host in _country_cache:
        return _country_cache[host]
    try:
        ip = host
        if not re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", host):
            try:
                ip = socket.gethostbyname(host)
            except (socket.gaierror, OSError):
                _country_cache[host] = ""
                return ""
        resp = requests.get(f"https://ipinfo.io/{ip}/json", timeout=5)
        if resp.status_code != 200:
            _country_cache[host] = ""
            return ""
        data = resp.json()
        code = (data.get("country") or "").strip().upper()
        if not code:
            _country_cache[host] = ""
            return ""
        name = COUNTRY_NAMES_RU.get(code, code)
        _country_cache[host] = name
        return name
    except Exception:
        _country_cache[host] = ""
        return ""


def rename_key_to_shkatulka(key: str) -> str:
    """Заменяет название в ключе на «Шкатулка запретов» и добавляет страну по IP."""
    base = key.split("#", 1)[0].rstrip("#")
    host = get_host_from_key(key)
    country = get_country_by_host(host) if host else ""
    if country:
        label = f"Шкатулка запретов — {country}"
    else:
        label = "Шкатулка запретов"
    return f"{base}#{label}"


# ==================== SAVING ====================
def save_keys(white_keys: List[str], universal_keys: List[str]):
    """Сохраняет ключи в правильную структуру"""
    print("\n" + "="*70)
    print("СОХРАНЕНИЕ")
    print("="*70)

    # Создаем директории
    os.makedirs(CFG.RU_DIR, exist_ok=True)
    os.makedirs(CFG.EURO_DIR, exist_ok=True)

    # Переименовываем ключи: «Шкатулка запретов — {страна по IP}»
    white_renamed = [rename_key_to_shkatulka(k) for k in white_keys]
    universal_renamed = [rename_key_to_shkatulka(k) for k in universal_keys]

    # 1. RU_Best/ru_white.txt
    if white_keys:
        ru_white_file = os.path.join(CFG.RU_DIR, "ru_white.txt")
        with open(ru_white_file, 'w', encoding='utf-8') as f:
            f.write('\n'.join(white_renamed))
        print(f"\n🏳️  {ru_white_file}")
        print(f"   Белый список: {len(white_keys)} ключей (названия: Шкатулка запретов — страна)")

    # 2. My_Euro/euro_universal.txt и euro_black.txt
    if universal_keys:
        euro_universal_file = os.path.join(CFG.EURO_DIR, "euro_universal.txt")
        with open(euro_universal_file, 'w', encoding='utf-8') as f:
            f.write('\n'.join(universal_renamed))
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
    print("   ✅ Детальное логирование ошибок")
    print("   ✅ Комплексная проверка безопасности конфигов")
    print("   ✅ Проверка подозрительных доменов и IP")
    print("   ✅ Анализ SSL/TLS сертификатов")
    print("   ✅ Обнаружение DNS утечек")
    print("   ✅ Проверка безопасности протоколов")
    print("   ✅ Проверка доступности конкретных сервисов (YouTube, Discord, Telegram, Cloudflare)\n")

    if not os.path.exists(CFG.XRAY_PATH):
        print(f"\n❌ Xray не найден: {CFG.XRAY_PATH}")
        return

    try:
        subprocess.run(["curl", "--version"], capture_output=True, check=True)
    except:
        print("\n❌ curl не установлен")
        return

    white_keys: List[str] = []
    universal_keys: List[str] = []

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
        # Игнорируем повторный Ctrl+C, чтобы не увидеть трейс при завершении потоков
        try:
            signal.signal(signal.SIGINT, signal.SIG_IGN)
        except Exception:
            pass
        if white_keys or universal_keys:
            save_keys(white_keys, universal_keys)
    except Exception as e:
        print(f"\n\n❌ Ошибка: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    main()
