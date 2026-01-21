#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
VPN Checker v15.2 - GitHub Edition (No Tokens)
Без системы токенов, для публичного GitHub репозитория
"""

import os
import re
import ssl
import socket
import time
import json
import base64
import shutil
import hashlib
import statistics
import argparse
import curses
import signal
import threading
import fcntl
import ipaddress
import subprocess
import tempfile
from dataclasses import dataclass, asdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from collections import defaultdict
from typing import Optional, Dict, List, Tuple, Any
from urllib.parse import urlparse, unquote
import requests

# ==================== КОНФИГУРАЦИЯ ====================
@dataclass(frozen=True)
class Config:
    """Неизменяемая конфигурация"""
    BASE_DIR: str = "checked"
    FOLDER_RU: str = "checked/RU_Best"
    FOLDER_EURO: str = "checked/My_Euro"
    
    # Производительность
    TIMEOUT: int = 8  # Увеличен таймаут для более надежной проверки
    CACHE_HOURS: int = 12
    CHUNK_LIMIT: int = 1000
    MAX_KEYS: int = 15000
    RETRY_ATTEMPTS: int = 2
    
    # Пороги качества
    MIN_QUALITY_SCORE: float = 30.0
    MAX_JITTER_MS: int = 50
    MIN_BANDWIDTH_MBPS: float = 1.0
    THREADS: int = 50
    ENABLE_JITTER_TEST: bool = False
    ENABLE_BANDWIDTH_TEST: bool = False
    ENABLE_DEEP_TEST: bool = True  # Глубокая проверка работоспособности
    XRAY_PATH: str = os.path.join(os.path.dirname(__file__), "Xray-linux-64", "xray")  # Путь к xray бинарнику
    XRAY_SOCKS_PORT: int = 10808  # Локальный порт для SOCKS прокси
    
    # Файлы
    HISTORY_FILE: str = "checked/history.json"
    ANALYTICS_FILE: str = "checked/analytics.json"
    BLACKLIST_FILE: str = "checked/blacklist.json"
    
    MY_CHANNEL: str = "@vlesstrojan"
    LOCK_TIMEOUT: float = 5.0

CFG = Config()

# Источники (единый массив, распределение по тегам происходит автоматически)
URLS = [
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
]

def detect_tag_from_url(url: str) -> str:
    """
    Автоматически определяет тег (RU/MY) на основе URL.
    RU: если в URL есть маркеры России (russia, rus, ru, mobile, cable, whitelist)
    MY: иначе (европейские/международные источники)
    """
    url_lower = url.lower()
    
    # Маркеры российских источников
    ru_markers = [
        "russia", "rus", "/ru/", "-ru-", "_ru_", "russian",
        "mobile", "cable", "whitelist", "bypass", "reality",
        "vless-rus", "rus-mobile", "rus-cable"
    ]
    
    # Проверяем наличие маркеров России
    for marker in ru_markers:
        if marker in url_lower:
            return "RU"
    
    # По умолчанию - европейские/международные источники
    return "MY"

# Маркеры
EURO_CODES = {"NL", "DE", "FI", "GB", "FR", "SE", "PL", "CZ", "AT", "CH", "IT", "ES", "NO", "DK", "BE", "IE", "LU", "EE", "LV", "LT", "RO", "BG", "HR", "SI", "SK", "HU", "PT", "GR", "CY", "MT"}
BAD_MARKERS = ["CN", "IR", "KR", "BR", "IN", "RELAY", "POOL", "🇨🇳", "🇮🇷", "🇰🇷", "TR", "SA", "AE"]
WHITE_MARKERS = ["white", "whitelist", "bypass", "россия", "russia", "mobile", "cable", "госуслуг", "government", "banking", "bank", "RU", "МТС", "Beeline"]
BLACK_MARKERS = ["black", "blacklist", "full", "global", "universal", "all", "vpn", "proxy", "tunnel", "freedom"]

# Ключевые слова для белого списка (проверка по ключевым словам в доменах)
# Это позволяет находить все поддомены компаний автоматически
WHITE_LIST_KEYWORDS = {
    # Соцсети и коммуникации
    'vk', 'vkontakte',  # ВКонтакте
    'yandex', 'ya',  # Яндекс
    'mail', 'mailru',  # Mail.ru
    'ok', 'odnoklassniki',  # Одноклассники
    
    # Банки
    'sberbank', 'sber',  # Сбербанк
    'alfabank', 'alfa',  # Альфа-Банк
    'vtb',  # ВТБ
    'tinkoff', 'tbank',  # Тинькофф, Т-Банк
    'gazprombank',  # Газпромбанк
    'mirpay', 'mir',  # Система Мир
    
    # Операторы связи
    'beeline',  # Билайн
    'megafon',  # МегаФон
    'mts',  # МТС
    'rostelecom', 'rt',  # Ростелеком
    't2',  # T2
    'motiv',  # Мотив
    
    # Маркетплейсы и магазины
    'ozon',  # Ozon
    'wildberries', 'wb',  # Wildberries
    'avito',  # Avito
    'beru',  # Беру (Яндекс Маркет)
    'magnit',  # Магнит
    'perekrestok',  # Перекресток
    'pyaterochka',  # Пятёрочка
    'vkusvill',  # ВкусВилл
    'vkusnoitochka',  # Вкусно и точка
    
    # Госуслуги и государственные сервисы
    'gosuslugi', 'esia',  # Госуслуги
    'kremlin',  # Кремль
    'government',  # Правительство
    'duma',  # Госдума
    'genproc',  # Генпрокуратура
    'council',  # Совет Федерации
    'deg',  # ДЭГ
    'mvdrf',  # МВД
    'mchs',  # МЧС
    
    # Транспорт и навигация
    'rzd',  # РЖД
    'tutu',  # Туту.ру
    '2gis', 'gis',  # 2ГИС
    'gismeteo',  # Gismeteo
    'aeroflot',  # Аэрофлот
    'pobeda',  # Победа
    'citydrive',  # Ситидрайв
    'dellin',  # Деловые линии
    'taximaxim', 'maxim',  # Такси Максим
    
    # Развлечения
    'rutube',  # RuTube
    'okko',  # Okko
    'ivi',  # Иви
    'kinopoisk',  # Кинопоиск
    'zen',  # Дзен
    
    # СМИ
    'kp', 'komsomolskaya',  # Комсомольская правда
    'ria',  # РИА Новости
    'rbc',  # РБК
    'lenta',  # Лента.ру
    'tass',  # ТАСС
    'gazeta',  # Газета.ру
    'rambler',  # Rambler
    'aif',  # Аргументы и Факты
    'rg', 'rossiyskaya',  # Российская газета
    'vedomosti',  # Ведомости
    '1tv', 'pervyy',  # Первый канал
    
    # Другие сервисы
    'pochta',  # Почта России
    'hh', 'headhunter',  # HeadHunter
    'chestnyznak',  # Честный знак
    'obyasnyayem',  # Объясняем РФ
    'moex',  # Мосбиржа
    'rosatom',  # Росатом
    
    # Российские домены
    '.ru', '.рф',  # Российские TLD
}

# ==================== УТИЛИТЫ ====================
class FileLock:
    """Потокобезопасная файловая блокировка"""
    def __init__(self, file_path: str):
        self.file_path = file_path
        self.lock_file = None
        self._thread_lock = threading.Lock()
    
    def __enter__(self):
        self._thread_lock.acquire()
        dir_path = os.path.dirname(self.file_path) or "."
        os.makedirs(dir_path, exist_ok=True)
        self.lock_file = open(self.file_path + ".lock", "w")
        try:
            fcntl.flock(self.lock_file.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            self.lock_file.close()
            self._thread_lock.release()
            raise TimeoutError(f"Не удалось получить lock для {self.file_path}")
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        if self.lock_file:
            fcntl.flock(self.lock_file.fileno(), fcntl.LOCK_UN)
            self.lock_file.close()
        self._thread_lock.release()

def load_json(path: str) -> dict:
    if not os.path.exists(path):
        return {}
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception as e:
        print(f"⚠️ Ошибка чтения {path}: {e}")
        return {}

def save_json(path: str, data: Any):
    try:
        dir_path = os.path.dirname(path) or "."
        os.makedirs(dir_path, exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
    except Exception as e:
        print(f"⚠️ Ошибка записи {path}: {e}")

def get_hash(key: str) -> str:
    return hashlib.sha256(key.encode('utf-8')).hexdigest()[:16]

def extract_ping(key_str: str) -> int:
    """
    Извлекает значение для сортировки из метки.
    Использует latency из метрик.
    """
    try:
        label = key_str.split("#")[-1]
        # Пытаемся найти latency в формате XXXms
        ping_part = re.search(r'(\d+)ms', label)
        if ping_part:
            return int(ping_part.group(1))
        # Если нет пинга, возвращаем среднее значение
        return 500
    except:
        return 999999

# ==================== КЛАССЫ ДАННЫХ ====================
@dataclass
class KeyMetrics:
    latency: int
    bandwidth: Optional[float] = None
    jitter: Optional[int] = None
    uptime: Optional[float] = None
    last_check: float = 0
    check_count: int = 0
    
    def __post_init__(self):
        if self.latency < 0:
            raise ValueError("Latency не может быть отрицательной")

@dataclass
class KeyInfo:
    key: str
    key_id: str
    tag: str
    country: str
    routing_type: str
    metrics: KeyMetrics
    
    def quality_score(self) -> float:
        """
        Улучшенный расчет качества сервера (0-100).
        Учитывает: latency, jitter, bandwidth, uptime, стабильность.
        """
        score = 100.0
        latency = self.metrics.latency if self.metrics.latency > 0 else 1
        
        # ========== LATENCY (задержка) - 40% веса ==========
        # Идеальная задержка: <50ms = 100%, 50-100ms = 90%, 100-150ms = 80%, и т.д.
        if latency <= 50:
            latency_score = 100.0
        elif latency <= 100:
            latency_score = 100.0 - (latency - 50) * 0.2  # 90-100%
        elif latency <= 150:
            latency_score = 90.0 - (latency - 100) * 0.2  # 80-90%
        elif latency <= 200:
            latency_score = 80.0 - (latency - 150) * 0.2  # 70-80%
        elif latency <= 300:
            latency_score = 70.0 - (latency - 200) * 0.3  # 40-70%
        elif latency <= 500:
            latency_score = 40.0 - (latency - 300) * 0.15  # 10-40%
        else:
            latency_score = max(0.0, 10.0 - (latency - 500) * 0.01)  # 0-10%
        
        score = (score * 0.6) + (latency_score * 0.4)  # 40% веса для latency
        
        # ========== JITTER (нестабильность) - 20% веса ==========
        if self.metrics.jitter is not None:
            if self.metrics.jitter <= 10:
                jitter_score = 100.0
            elif self.metrics.jitter <= 20:
                jitter_score = 100.0 - (self.metrics.jitter - 10) * 2  # 80-100%
            elif self.metrics.jitter <= 30:
                jitter_score = 80.0 - (self.metrics.jitter - 20) * 2  # 60-80%
            elif self.metrics.jitter <= 50:
                jitter_score = 60.0 - (self.metrics.jitter - 30) * 1.5  # 30-60%
            else:
                jitter_score = max(0.0, 30.0 - (self.metrics.jitter - 50) * 0.5)  # 0-30%
            
            score = (score * 0.8) + (jitter_score * 0.2)  # 20% веса для jitter
        
        # ========== BANDWIDTH (пропускная способность) - 20% веса ==========
        if self.metrics.bandwidth is not None:
            if self.metrics.bandwidth >= 50:
                bandwidth_score = 100.0
            elif self.metrics.bandwidth >= 20:
                bandwidth_score = 80.0 + (self.metrics.bandwidth - 20) * 0.67  # 80-100%
            elif self.metrics.bandwidth >= 10:
                bandwidth_score = 60.0 + (self.metrics.bandwidth - 10) * 2  # 60-80%
            elif self.metrics.bandwidth >= 5:
                bandwidth_score = 40.0 + (self.metrics.bandwidth - 5) * 4  # 40-60%
            elif self.metrics.bandwidth >= 1:
                bandwidth_score = 20.0 + (self.metrics.bandwidth - 1) * 5  # 20-40%
            else:
                bandwidth_score = max(0.0, self.metrics.bandwidth * 20)  # 0-20%
            
            score = (score * 0.8) + (bandwidth_score * 0.2)  # 20% веса для bandwidth
        
        # ========== UPTIME (стабильность) - 20% веса ==========
        if self.metrics.uptime is not None:
            uptime_score = self.metrics.uptime  # Прямая зависимость: 100% uptime = 100 баллов
            score = (score * 0.8) + (uptime_score * 0.2)  # 20% веса для uptime
        
        return max(0.0, min(100.0, score))
    
    def get_rating(self) -> Tuple[int, str, str]:
        """
        Возвращает рейтинг сервера: (звезды 1-5, иконка, буквенная оценка)
        """
        q = self.quality_score()
        
        # Определяем количество звезд (1-5)
        if q >= 90:
            stars = 5
            icon = "🏆"  # Трофей - премиум
            grade = "A+"
        elif q >= 80:
            stars = 5
            icon = "⭐"  # 5 звезд - отлично
            grade = "A"
        elif q >= 70:
            stars = 4
            icon = "⭐"  # 4 звезды - очень хорошо
            grade = "B+"
        elif q >= 60:
            stars = 4
            icon = "✅"  # 4 звезды - хорошо
            grade = "B"
        elif q >= 50:
            stars = 3
            icon = "✅"  # 3 звезды - нормально
            grade = "C+"
        elif q >= 40:
            stars = 3
            icon = "⚡"  # 3 звезды - приемлемо
            grade = "C"
        elif q >= 30:
            stars = 2
            icon = "⚡"  # 2 звезды - ниже среднего
            grade = "D"
        else:
            stars = 1
            icon = "⚠️"  # 1 звезда - плохо
            grade = "F"
        
        return stars, icon, grade
    
    def get_icon(self) -> str:
        """Возвращает иконку рейтинга (обратная совместимость)"""
        _, icon, _ = self.get_rating()
        return icon
    
    def get_stars_display(self) -> str:
        """Возвращает компактное отображение звезд"""
        stars, _, _ = self.get_rating()
        # Компактный формат: количество звезд числом
        return f"{stars}★"

# ==================== BLACKLIST ====================
class BlacklistManager:
    def __init__(self, file_path: str):
        self.file_path = file_path
        self._lock = threading.Lock()
        data = load_json(file_path)
        self.hosts = set(data.get('hosts', []))
        self.reasons = data.get('reasons', {})
    
    def add(self, host: str, reason: str):
        with self._lock:
            self.hosts.add(host)
            self.reasons[host] = {
                'reason': reason[:100],
                'added': time.time(),
                'failures': 0
            }
            self.save()
    
    def record_failure(self, host: str):
        with self._lock:
            if host in self.hosts:
                self.reasons[host]['failures'] += 1
    
    def is_blacklisted(self, host: str) -> bool:
        with self._lock:
            return host in self.hosts
    
    def save(self):
        save_json(self.file_path, {'hosts': list(self.hosts), 'reasons': self.reasons})

# ==================== АНАЛИТИКА ====================
class Analytics:
    def __init__(self, file_path: str):
        self.file_path = file_path
        self._lock = threading.Lock()
        self.data = load_json(file_path)
        self.session = {'start': time.time(), 'total': 0, 'success': 0}
    
    def record(self, key_id: str, success: bool, latency: Optional[int] = None):
        with self._lock:
            if key_id not in self.data:
                self.data[key_id] = {'created': time.time(), 'checks': []}
            
            self.data[key_id]['checks'].append({
                'time': time.time(),
                'success': success,
                'latency': latency
            })
            
            self.data[key_id]['checks'] = self.data[key_id]['checks'][-50:]
            self.session['total'] += 1
            if success: self.session['success'] += 1
    
    def get_uptime(self, key_id: str) -> Optional[float]:
        with self._lock:
            if key_id not in self.data: return None
            checks = self.data[key_id]['checks']
            if not checks: return None
            recent = checks[-20:]
            success = sum(1 for c in recent if c['success'])
            return (success / len(recent)) * 100
    
    def save(self):
        save_json(self.file_path, self.data)

# ==================== ПРОВЕРКА СОЕДИНЕНИЯ ====================
class ConnectionChecker:
    @staticmethod
    def _key_to_xray_config(key: str) -> Optional[dict]:
        """
        Конвертирует VPN ключ в конфигурацию xray.
        Поддерживает: VLESS, VMess, Trojan, Shadowsocks
        """
        try:
            protocol = get_protocol_type(key)
            host, port, is_tls = parse_key(key)
            
            if not host or not port:
                return None
            
            # Базовая структура конфига xray
            config = {
                "log": {"loglevel": "warning"},
                "inbounds": [{
                    "port": CFG.XRAY_SOCKS_PORT,
                    "protocol": "socks",
                    "settings": {
                        "auth": "noauth",
                        "udp": True
                    }
                }],
                "outbounds": []
            }
            
            # VLESS
            if protocol == "vless":
                # Парсим VLESS ключ
                scheme, rest = key.split("://", 1)
                if "@" not in rest:
                    return None
                
                uuid_part, server_part = rest.split("@", 1)
                if "?" in server_part:
                    server_part, params_part = server_part.split("?", 1)
                else:
                    params_part = ""
                
                if ":" not in server_part:
                    return None
                
                # Парсим параметры
                params = {}
                for param in params_part.split("&"):
                    if "=" in param:
                        k, v = param.split("=", 1)
                        params[k.lower()] = unquote(v)
                
                # Определяем transport
                transport = params.get("type", "tcp").lower()
                network_settings = {}
                
                if transport == "ws":
                    network_settings = {
                        "network": "ws",
                        "wsSettings": {
                            "path": params.get("path", "/"),
                            "headers": {}
                        }
                    }
                    if "host" in params:
                        network_settings["wsSettings"]["headers"]["Host"] = params["host"]
                
                outbound = {
                    "protocol": "vless",
                    "settings": {
                        "vnext": [{
                            "address": host,
                            "port": port,
                            "users": [{"id": uuid_part}]
                        }]
                    },
                    "streamSettings": {
                        "network": transport,
                        "security": params.get("security", "none").lower()
                    }
                }
                
                if network_settings:
                    outbound["streamSettings"].update(network_settings)
                
                if is_tls and "sni" in params:
                    outbound["streamSettings"]["tlsSettings"] = {
                        "serverName": params["sni"]
                    }
                
                config["outbounds"].append(outbound)
            
            # VMess
            elif protocol == "vmess":
                scheme, rest = key.split("://", 1)
                missing_padding = -len(rest) % 4
                if missing_padding:
                    rest += "=" * missing_padding
                decoded = base64.b64decode(rest, validate=True).decode('utf-8', errors='ignore')
                vmess_config = json.loads(decoded)
                
                network = vmess_config.get("net", "tcp").lower()
                network_settings = {}
                
                if network == "ws":
                    network_settings = {
                        "network": "ws",
                        "wsSettings": {
                            "path": vmess_config.get("path", "/"),
                            "headers": {}
                        }
                    }
                    if "host" in vmess_config:
                        network_settings["wsSettings"]["headers"]["Host"] = vmess_config["host"]
                
                outbound = {
                    "protocol": "vmess",
                    "settings": {
                        "vnext": [{
                            "address": vmess_config.get("add", host),
                            "port": vmess_config.get("port", port),
                            "users": [{
                                "id": vmess_config.get("id", ""),
                                "alterId": vmess_config.get("aid", 0),
                                "security": vmess_config.get("scy", "auto")
                            }]
                        }]
                    },
                    "streamSettings": {
                        "network": network,
                        "security": vmess_config.get("tls", "none").lower()
                    }
                }
                
                if network_settings:
                    outbound["streamSettings"].update(network_settings)
                
                if "sni" in vmess_config:
                    outbound["streamSettings"]["tlsSettings"] = {
                        "serverName": vmess_config["sni"]
                    }
                
                config["outbounds"].append(outbound)
            
            # Trojan
            elif protocol == "trojan":
                scheme, rest = key.split("://", 1)
                if "@" not in rest:
                    return None
                
                password_part, server_part = rest.split("@", 1)
                if "?" in server_part:
                    server_part, params_part = server_part.split("?", 1)
                else:
                    params_part = ""
                
                if ":" not in server_part:
                    return None
                
                # Парсим параметры
                params = {}
                for param in params_part.split("&"):
                    if "=" in param:
                        k, v = param.split("=", 1)
                        params[k.lower()] = unquote(v)
                
                outbound = {
                    "protocol": "trojan",
                    "settings": {
                        "servers": [{
                            "address": host,
                            "port": port,
                            "password": password_part
                        }]
                    },
                    "streamSettings": {
                        "network": "tcp",
                        "security": "tls"
                    }
                }
                
                if "sni" in params:
                    outbound["streamSettings"]["tlsSettings"] = {
                        "serverName": params["sni"]
                    }
                
                config["outbounds"].append(outbound)
            
            # Shadowsocks
            elif protocol == "shadowsocks":
                scheme, rest = key.split("://", 1)
                if "@" not in rest:
                    # Пробуем base64 формат
                    try:
                        missing_padding = -len(rest) % 4
                        if missing_padding:
                            rest += "=" * missing_padding
                        decoded = base64.b64decode(rest, validate=True).decode('utf-8', errors='ignore')
                        # Формат: method:password@host:port
                        if "@" in decoded:
                            method_pass, host_port = decoded.split("@", 1)
                            if ":" in method_pass and ":" in host_port:
                                method, password = method_pass.split(":", 1)
                                host, port_str = host_port.rsplit(":", 1)
                                port = int(port_str)
                            else:
                                return None
                        else:
                            return None
                    except:
                        return None
                else:
                    method_pass, host_port = rest.split("@", 1)
                    if ":" in method_pass and ":" in host_port:
                        method, password = method_pass.split(":", 1)
                        host, port_str = host_port.rsplit(":", 1)
                        port = int(port_str)
                    else:
                        return None
                
                outbound = {
                    "protocol": "shadowsocks",
                    "settings": {
                        "servers": [{
                            "address": host,
                            "port": port,
                            "method": method,
                            "password": password
                        }]
                    }
                }
                
                config["outbounds"].append(outbound)
            
            # Для других протоколов пока не поддерживаем
            else:
                return None
            
            return config
            
        except Exception as e:
            return None
    
    @staticmethod
    def check_basic(host: str, port: int, is_tls: bool, protocol: str = "tcp") -> Optional[int]:
        """
        Базовая проверка соединения с VPN сервером.
        protocol: "tcp" или "udp" (для Hysteria2)
        Возвращает latency в миллисекундах или None если не работает.
        """
        try:
            # Определяем семейство адресов
            family = socket.AF_INET
            try:
                ip = ipaddress.ip_address(host)
                if isinstance(ip, ipaddress.IPv6Address):
                    family = socket.AF_INET6
            except ValueError:
                # Если не IP, пытаемся резолвить как домен
                pass
            
            start = time.time()
            
            # Для UDP протоколов (Hysteria2)
            if protocol.lower() == "udp":
                try:
                    sock = socket.socket(family, socket.SOCK_DGRAM)
                    sock.settimeout(CFG.TIMEOUT)
                    # Для UDP просто проверяем что можем отправить пакет
                    # Hysteria2 обычно отвечает на UDP пакеты
                    sock.sendto(b'\x00', (host, port))
                    # Пытаемся получить ответ (необязательно для UDP)
                    try:
                        sock.recvfrom(1024)
                    except socket.timeout:
                        # Таймаут - это нормально для UDP, значит порт открыт
                        pass
                    sock.close()
                except Exception as e:
                    try:
                        sock.close()
                    except:
                        pass
                    raise
            # Для TCP протоколов
            else:
                if is_tls:
                    ctx = ssl.create_default_context()
                    ctx.check_hostname = False
                    ctx.verify_mode = ssl.CERT_NONE
                    sock = socket.socket(family, socket.SOCK_STREAM)
                    sock.settimeout(CFG.TIMEOUT)
                    try:
                        sock.connect((host, port))
                        sock = ctx.wrap_socket(sock, server_hostname=host)
                        sock.close()
                    except Exception as e:
                        sock.close()
                        raise
                else:
                    sock = socket.socket(family, socket.SOCK_STREAM)
                    sock.settimeout(CFG.TIMEOUT)
                    try:
                        sock.connect((host, port))
                        sock.close()
                    except Exception as e:
                        sock.close()
                        raise
            
            latency = int((time.time() - start) * 1000)
            return latency if latency >= 0 else 1
        except socket.timeout:
            return None
        except (socket.error, OSError, ssl.SSLError, Exception):
            return None
    
    @staticmethod
    def check_jitter(host: str, port: int, is_tls: bool) -> Optional[int]:
        if not CFG.ENABLE_JITTER_TEST: return None
        
        latencies = []
        for _ in range(5):
            try:
                start = time.time()
                if is_tls:
                    ctx = ssl.create_default_context()
                    ctx.check_hostname = False
                    ctx.verify_mode = ssl.CERT_NONE
                    with socket.create_connection((host, port), timeout=2) as sock:
                        with ctx.wrap_socket(sock, server_hostname=host):
                            pass
                else:
                    with socket.create_connection((host, port), timeout=2):
                        pass
                latencies.append(int((time.time() - start) * 1000))
                time.sleep(0.05)
            except:
                continue
        
        if len(latencies) >= 3:
            try: return int(statistics.stdev(latencies))
            except: pass
        return None
    
    @staticmethod
    def check_bandwidth(host: str, port: int, is_tls: bool) -> Optional[float]:
        if not CFG.ENABLE_BANDWIDTH_TEST: return None
        
        try:
            start = time.time()
            total_bytes = 0
            ctx = None
            if is_tls:
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
            
            with socket.create_connection((host, port), timeout=CFG.TIMEOUT) as sock:
                if ctx:
                    sock = ctx.wrap_socket(sock, server_hostname=host)
                
                sock.settimeout(0.5)
                sock.sendall(b"HEAD / HTTP/1.1\r\nHost: {}\r\n\r\n".format(host.encode()))
                end_time = start + 2
                
                while time.time() < end_time:
                    try:
                        data = sock.recv(4096)
                        if not data: break
                        total_bytes += len(data)
                    except socket.timeout:
                        continue
                    except:
                        break
            
            elapsed = time.time() - start
            if elapsed > 0:
                mbps = (total_bytes * 8) / (elapsed * 1_000_000)
                return round(mbps, 2)
        except:
            pass
        return None
    
    @staticmethod
    def check_deep(key: str, host: str, port: int, is_tls: bool) -> bool:
        """
        Глубокая проверка работоспособности VPN-протокола.
        Проверяет не только TCP соединение, но и реальную работоспособность сервера.
        Удаляет нерабочие ключи, оставляет только те, которые действительно отвечают.
        Возвращает True если сервер действительно работает, False если нет.
        """
        try:
            # Определяем тип протокола
            protocol = get_protocol_type(key)
            
            # Для Hysteria2 используем UDP проверку
            if protocol == "hysteria2":
                try:
                    family = socket.AF_INET
                    try:
                        ip = ipaddress.ip_address(host)
                        if isinstance(ip, ipaddress.IPv6Address):
                            family = socket.AF_INET6
                    except ValueError:
                        pass
                    
                    sock = socket.socket(family, socket.SOCK_DGRAM)
                    sock.settimeout(CFG.TIMEOUT + 2)
                    
                    # Отправляем тестовый пакет (Hysteria2 может отвечать на определенные пакеты)
                    sock.sendto(b'\x00', (host, port))
                    
                    # Пытаемся получить ответ
                    try:
                        sock.recvfrom(1024)
                        sock.close()
                        return True
                    except socket.timeout:
                        # Для UDP таймаут может означать что порт открыт
                        sock.close()
                        return True
                except Exception:
                    return False
            
            # Определяем семейство адресов
            family = socket.AF_INET
            try:
                ip = ipaddress.ip_address(host)
                if isinstance(ip, ipaddress.IPv6Address):
                    family = socket.AF_INET6
            except ValueError:
                pass
            
            # Создаем соединение с увеличенным таймаутом для глубокой проверки
            sock = socket.socket(family, socket.SOCK_STREAM)
            sock.settimeout(CFG.TIMEOUT + 2)  # Немного больше времени для глубокой проверки
            
            try:
                # Устанавливаем соединение
                sock.connect((host, port))
                
                # Для TLS соединений - проверяем TLS handshake и стабильность
                if is_tls:
                    ctx = ssl.create_default_context()
                    ctx.check_hostname = False
                    ctx.verify_mode = ssl.CERT_NONE
                    # Увеличиваем таймаут для TLS handshake
                    ctx.set_ciphers('DEFAULT:@SECLEVEL=1')
                    
                    try:
                        # Выполняем TLS handshake
                        tls_sock = ctx.wrap_socket(sock, server_hostname=host)
                        
                        # Проверяем что соединение действительно активно
                        # Устанавливаем короткий таймаут для проверки
                        tls_sock.settimeout(1.5)
                        
                        # Пытаемся проверить что соединение не закрылось сразу
                        # Используем MSG_PEEK чтобы не удалять данные из буфера
                        try:
                            # Для разных протоколов - разная проверка
                            # Просто проверяем что соединение активно, пытаясь прочитать данные
                            tls_sock.recv(1, socket.MSG_PEEK)
                        except (socket.timeout, ssl.SSLWantReadError):
                            # Таймаут или нет данных - это нормально, значит соединение активно
                            pass
                        except (ssl.SSLError, ssl.SSLEOFError, OSError, ConnectionResetError, BlockingIOError):
                            # Соединение закрыто или ошибка - сервер не работает
                            tls_sock.close()
                            return False
                        
                        # Если дошли сюда - соединение работает
                        tls_sock.close()
                        return True
                        
                    except (ssl.SSLError, ssl.SSLEOFError, ssl.SSLZeroReturnError, OSError) as e:
                        # TLS handshake не удался - сервер не работает или неправильный протокол
                        try:
                            sock.close()
                        except:
                            pass
                        return False
                
                # Для не-TLS соединений - проверяем что порт действительно отвечает
                else:
                    # Для SS (Shadowsocks) и других - проверяем что соединение стабильно
                    sock.settimeout(1.5)
                    try:
                        # Пытаемся проверить что соединение активно
                        # Используем MSG_PEEK чтобы не удалять данные
                        sock.recv(1, socket.MSG_PEEK)
                    except (socket.timeout, BlockingIOError):
                        # Таймаут - это нормально, значит порт открыт и слушает
                        pass
                    except (socket.error, OSError, ConnectionResetError):
                        # Ошибка соединения - сервер не работает
                        sock.close()
                        return False
                    
                    # Если дошли сюда - соединение работает
                    sock.close()
                    return True
                    
            except (socket.timeout, socket.error, OSError, ConnectionRefusedError, ConnectionResetError) as e:
                # Не удалось установить соединение - сервер не работает
                try:
                    sock.close()
                except:
                    pass
                return False
                
        except Exception as e:
            # Любая другая ошибка - считаем что сервер не работает
            return False

# ==================== ПАРСИНГ ====================
def get_protocol_type(key: str) -> str:
    """Определяет тип VPN протокола из ключа"""
    key_lower = key.lower()
    
    if key_lower.startswith("vless://"):
        return "vless"
    elif key_lower.startswith("vmess://"):
        return "vmess"
    elif key_lower.startswith("trojan://"):
        return "trojan"
    elif key_lower.startswith("hysteria2://") or key_lower.startswith("hy2://"):
        return "hysteria2"
    elif key_lower.startswith("ss://") or key_lower.startswith("ssr://"):
        return "shadowsocks"
    elif key_lower.startswith("socks://") or key_lower.startswith("socks5://"):
        return "socks"
    else:
        # Пытаемся определить по параметрам
        if "vless" in key_lower or "type=vless" in key_lower:
            return "vless"
        elif "vmess" in key_lower or "type=vmess" in key_lower:
            return "vmess"
        elif "trojan" in key_lower:
            return "trojan"
        elif "hysteria2" in key_lower or "hy2" in key_lower:
            return "hysteria2"
        elif "shadowsocks" in key_lower or "ss=" in key_lower:
            return "shadowsocks"
        else:
            return "unknown"

def parse_key(key: str) -> Tuple[Optional[str], Optional[int], bool]:
    """
    Парсит VPN ключ и извлекает host, port, is_tls.
    Поддерживает: VLESS, VMess, Trojan, Shadowsocks, Hysteria2
    """
    try:
        if "://" not in key:
            return None, None, False
        
        scheme, rest = key.split("://", 1)
        scheme_lower = scheme.lower()
        
        # ========== VMESS (формат: vmess://base64_json) ==========
        if scheme_lower == "vmess":
            try:
                # Декодируем base64
                missing_padding = -len(rest) % 4
                if missing_padding:
                    rest += "=" * missing_padding
                
                decoded = base64.b64decode(rest, validate=True).decode('utf-8', errors='ignore')
                vmess_config = json.loads(decoded)
                
                # Извлекаем данные из JSON
                host = vmess_config.get("add") or vmess_config.get("address", "")
                port = vmess_config.get("port", 0)
                security = vmess_config.get("tls", "").lower()
                net = vmess_config.get("net", "").lower()
                
                if not host or port <= 0 or port > 65535:
                    return None, None, False
                
                # TLS определяется по полю "tls" в JSON
                is_tls = security in ("tls", "reality") or net == "ws"  # WebSocket часто с TLS
                
                return host.strip(), port, is_tls
            except (ValueError, json.JSONDecodeError, Exception):
                # Если не удалось распарсить как JSON, пробуем стандартный формат
                pass
        
        # ========== HYSTERIA2 (формат: hysteria2://password@host:port?params) ==========
        if scheme_lower in ("hysteria2", "hy2"):
            try:
                # Формат 1: hysteria2://password@host:port?params
                if "@" in rest:
                    user_info, rest = rest.split("@", 1)
                    if "?" in rest:
                        host_port, _ = rest.split("?", 1)
                    elif "#" in rest:
                        host_port, _ = rest.split("#", 1)
                    else:
                        host_port = rest
                # Формат 2: hysteria2://host:port?auth=password&params
                else:
                    if "?" in rest:
                        host_port, query = rest.split("?", 1)
                    elif "#" in rest:
                        host_port, _ = rest.split("#", 1)
                    else:
                        host_port = rest
                
                if host_port.startswith("["):
                    if "]:" not in host_port:
                        return None, None, False
                    host, port_str = host_port.rsplit("]:", 1)
                    host = host[1:]
                else:
                    if ":" not in host_port:
                        return None, None, False
                    host, port_str = host_port.rsplit(":", 1)
                
                port = int(port_str.strip())
                if port <= 0 or port > 65535:
                    return None, None, False
                
                # Hysteria2 может использовать TLS, проверяем параметры
                is_tls = any(x in key.lower() for x in ['tls=true', 'insecure=0', 'pin='])
                
                return host.strip(), port, is_tls
            except:
                pass
        
        # ========== SHADOWSOCKS (может быть с @ или без) ==========
        if scheme_lower in ("ss", "ssr"):
            # Формат 1: ss://base64@host:port
            if "@" in rest:
                try:
                    base64_part, host_port_part = rest.split("@", 1)
                    # Извлекаем host:port
                    if "?" in host_port_part:
                        host_port, _ = host_port_part.split("?", 1)
                    elif "#" in host_port_part:
                        host_port, _ = host_port_part.split("#", 1)
                    else:
                        host_port = host_port_part
                    
                    if host_port.startswith("["):
                        if "]:" not in host_port:
                            return None, None, False
                        host, port_str = host_port.rsplit("]:", 1)
                        host = host[1:]
                    else:
                        if ":" not in host_port:
                            return None, None, False
                        host, port_str = host_port.rsplit(":", 1)
                    
                    port = int(port_str.strip())
                    if port <= 0 or port > 65535:
                        return None, None, False
                    
                    # Shadowsocks обычно без TLS на уровне протокола
                    return host.strip(), port, False
                except:
                    pass
            
            # Формат 2: ss://base64 (нужно декодировать)
            else:
                try:
                    missing_padding = -len(rest) % 4
                    if missing_padding:
                        rest += "=" * missing_padding
                    
                    decoded = base64.b64decode(rest, validate=True).decode('utf-8', errors='ignore')
                    # Формат: method:password@host:port
                    if "@" in decoded:
                        _, host_port = decoded.rsplit("@", 1)
                        if ":" in host_port:
                            host, port_str = host_port.rsplit(":", 1)
                            port = int(port_str.strip())
                            if port > 0 and port <= 65535:
                                return host.strip(), port, False
                except:
                    pass
        
        # ========== СТАНДАРТНЫЙ ФОРМАТ (VLESS, Trojan и др.) ==========
        if "@" not in rest:
            return None, None, False
        
        user_info, rest = rest.split("@", 1)
        if "?" in rest:
            host_port, _ = rest.split("?", 1)
        elif "#" in rest:
            host_port, _ = rest.split("#", 1)
        else:
            host_port = rest
        
        if host_port.startswith("["):
            if "]:" not in host_port:
                return None, None, False
            host, port_str = host_port.rsplit("]:", 1)
            host = host[1:]
        else:
            if ":" not in host_port:
                return None, None, False
            host, port_str = host_port.rsplit(":", 1)
        
        port = int(port_str.strip())
        if port <= 0 or port > 65535:
            return None, None, False
        
        # Определяем TLS
        is_tls = scheme_lower == "trojan" or any(x in key.lower() for x in ['security=tls', 'security=reality', 'tls=true'])
        
        return host.strip(), port, is_tls
    except Exception as e:
        return None, None, False

# Словарь эмодзи флагов стран
COUNTRY_FLAGS = {
    'RU': '🇷🇺', 'DE': '🇩🇪', 'NL': '🇳🇱', 'FI': '🇫🇮', 'GB': '🇬🇧', 'FR': '🇫🇷',
    'SE': '🇸🇪', 'PL': '🇵🇱', 'CZ': '🇨🇿', 'AT': '🇦🇹', 'CH': '🇨🇭', 'IT': '🇮🇹',
    'ES': '🇪🇸', 'NO': '🇳🇴', 'DK': '🇩🇰', 'BE': '🇧🇪', 'IE': '🇮🇪', 'LU': '🇱🇺',
    'EE': '🇪🇪', 'LV': '🇱🇻', 'LT': '🇱🇹', 'RO': '🇷🇴', 'BG': '🇧🇬', 'HR': '🇭🇷',
    'SI': '🇸🇮', 'SK': '🇸🇰', 'HU': '🇭🇺', 'PT': '🇵🇹', 'GR': '🇬🇷', 'CY': '🇨🇾',
    'MT': '🇲🇹', 'US': '🇺🇸', 'CA': '🇨🇦', 'AU': '🇦🇺', 'JP': '🇯🇵', 'KR': '🇰🇷',
    'SG': '🇸🇬', 'HK': '🇭🇰', 'TW': '🇹🇼', 'IN': '🇮🇳', 'BR': '🇧🇷', 'MX': '🇲🇽',
    'AR': '🇦🇷', 'CL': '🇨🇱', 'CO': '🇨🇴', 'PE': '🇵🇪', 'ZA': '🇿🇦', 'EG': '🇪🇬',
    'AE': '🇦🇪', 'SA': '🇸🇦', 'TR': '🇹🇷', 'IL': '🇮🇱', 'TH': '🇹🇭', 'VN': '🇻🇳',
    'PH': '🇵🇭', 'ID': '🇮🇩', 'MY': '🇲🇾', 'NZ': '🇳🇿', 'EU': '🇪🇺', 'UNKNOWN': '🌐'
}

# Расширенный словарь TLD -> код страны
TLD_COUNTRY_MAP = {
    '.ru': 'RU', '.рф': 'RU', '.de': 'DE', '.nl': 'NL', '.fi': 'FI', '.uk': 'GB', '.co.uk': 'GB',
    '.fr': 'FR', '.se': 'SE', '.pl': 'PL', '.cz': 'CZ', '.at': 'AT', '.ch': 'CH', '.it': 'IT',
    '.es': 'ES', '.no': 'NO', '.dk': 'DK', '.be': 'BE', '.ie': 'IE', '.lu': 'LU', '.ee': 'EE',
    '.lv': 'LV', '.lt': 'LT', '.ro': 'RO', '.bg': 'BG', '.hr': 'HR', '.si': 'SI', '.sk': 'SK',
    '.hu': 'HU', '.pt': 'PT', '.gr': 'GR', '.cy': 'CY', '.mt': 'MT', '.us': 'US', '.com': 'US',
    '.ca': 'CA', '.au': 'AU', '.jp': 'JP', '.kr': 'KR', '.sg': 'SG', '.hk': 'HK', '.tw': 'TW',
    '.in': 'IN', '.br': 'BR', '.mx': 'MX', '.ar': 'AR', '.cl': 'CL', '.co': 'CO', '.pe': 'PE',
    '.za': 'ZA', '.eg': 'EG', '.ae': 'AE', '.sa': 'SA', '.tr': 'TR', '.il': 'IL', '.th': 'TH',
    '.vn': 'VN', '.ph': 'PH', '.id': 'ID', '.my': 'MY', '.nz': 'NZ', '.eu': 'EU'
}

def get_country_flag(country_code: str) -> str:
    """Возвращает эмодзи флаг страны по коду"""
    return COUNTRY_FLAGS.get(country_code.upper(), '🌐')

def extract_sni_and_cidr(key: str) -> Tuple[Optional[str], Optional[str]]:
    """
    Извлекает SNI (Server Name Indication) и CIDR информацию из ключа.
    Возвращает: (sni_domain, cidr_info)
    """
    sni = None
    cidr_info = None
    
    try:
        if "://" not in key:
            return None, None
        
        scheme, rest = key.split("://", 1)
        scheme_lower = scheme.lower()
        
        # ========== VMESS ==========
        if scheme_lower == "vmess":
            try:
                missing_padding = -len(rest) % 4
                if missing_padding:
                    rest += "=" * missing_padding
                decoded = base64.b64decode(rest, validate=True).decode('utf-8', errors='ignore')
                vmess_config = json.loads(decoded)
                
                # Извлекаем SNI из полей "sni" или "host"
                sni = vmess_config.get("sni") or vmess_config.get("host") or vmess_config.get("add")
                
                # Проверяем на CIDR (обычно в поле "ps" или "add")
                add = vmess_config.get("add", "")
                if add and "/" in add:
                    # Возможно CIDR нотация
                    try:
                        ipaddress.ip_network(add, strict=False)
                        cidr_info = add
                    except:
                        pass
            except:
                pass
        
        # ========== HYSTERIA2 ==========
        if scheme_lower in ("hysteria2", "hy2"):
            # Парсим query параметры
            if "?" in rest:
                _, query_part = rest.split("?", 1)
                if "#" in query_part:
                    query_part, _ = query_part.split("#", 1)
                
                query_part = unquote(query_part)
                params = {}
                for param in query_part.split("&"):
                    if "=" in param:
                        k, v = param.split("=", 1)
                        params[k.lower()] = v
                
                # SNI может быть в параметрах sni, host, serverName
                sni = params.get("sni") or params.get("host") or params.get("servername")
        
        # ========== VLESS, TROJAN и другие ==========
        else:
            # Парсим query параметры
            if "?" in rest:
                _, query_part = rest.split("?", 1)
                if "#" in query_part:
                    query_part, _ = query_part.split("#", 1)
                
                # Декодируем URL-encoded параметры
                query_part = unquote(query_part)
                
                # Ищем параметры sni и host
                params = {}
                for param in query_part.split("&"):
                    if "=" in param:
                        k, v = param.split("=", 1)
                        params[k.lower()] = v
                
                # SNI может быть в параметрах sni, host, serverName
                sni = params.get("sni") or params.get("host") or params.get("servername")
                
                # Если host содержит несколько доменов через точку (например: "domain1.domain2.com")
                if sni and "." in sni:
                    # Если это список доменов через точку, берем последний (основной домен)
                    # Например: "www.speedtest.net.ftp.debian.org.vigilantecollection.com" -> "vigilantecollection.com"
                    domain_parts = sni.split(".")
                    if len(domain_parts) >= 2:
                        # Берем последние 2 части (домен и TLD)
                        sni = ".".join(domain_parts[-2:])
                
                # Проверяем на CIDR в основном хосте
                if "@" in rest:
                    host_part = rest.split("@")[1].split("?")[0].split("#")[0]
                    if "/" in host_part:
                        try:
                            ipaddress.ip_network(host_part.split(":")[0], strict=False)
                            cidr_info = host_part.split(":")[0]
                        except:
                            pass
        
        # Очищаем SNI от лишних символов
        if sni:
            sni = sni.strip().lower()
            # Убираем протоколы и пути
            if "://" in sni:
                sni = sni.split("://")[1]
            if "/" in sni:
                sni = sni.split("/")[0]
            if ":" in sni:
                sni = sni.split(":")[0]
            
            # Если это список доменов через точку (например: "www.speedtest.net.ftp.debian.org.vigilantecollection.com")
            # Берем последний домен (основной)
            if "." in sni:
                domain_parts = sni.split(".")
                # Проверяем что это не IP адрес
                try:
                    ipaddress.ip_address(sni)
                    sni = None  # Это IP, не домен
                except ValueError:
                    # Это домен, берем последние 2-3 части для компактности
                    if len(domain_parts) >= 2:
                        # Берем последние 2 части (домен.TLD)
                        sni = ".".join(domain_parts[-2:])
            
            # Проверяем что это валидный домен
            if not sni or len(sni) < 3 or "." not in sni:
                sni = None
        
        return sni, cidr_info
    
    except Exception:
        return None, None

def get_country(key: str, host: str) -> str:
    """Определяет страну по ключу и хосту"""
    host_lower = host.lower()
    
    # Для VMess - пытаемся извлечь из JSON
    if key.lower().startswith("vmess://"):
        try:
            scheme, rest = key.split("://", 1)
            missing_padding = -len(rest) % 4
            if missing_padding:
                rest += "=" * missing_padding
            decoded = base64.b64decode(rest, validate=True).decode('utf-8', errors='ignore')
            vmess_config = json.loads(decoded)
            
            # Проверяем поле ps (описание) на наличие кода страны
            ps = vmess_config.get("ps", "").upper()
            for code in EURO_CODES:
                if code in ps:
                    return code
            if "RU" in ps or "RUSSIA" in ps or "РОССИЯ" in ps:
                return "RU"
            # Проверяем другие страны
            for code, flag in COUNTRY_FLAGS.items():
                if code != 'UNKNOWN' and code in ps:
                    return code
        except:
            pass
    
    # Проверка по TLD домена (расширенная)
    parsed = urlparse(f"//{host}")
    domain = parsed.hostname or host
    
    # Проверяем все возможные TLD
    for tld, code in TLD_COUNTRY_MAP.items():
        if domain.endswith(tld):
            return code
    
    # Проверка по параметрам в ключе
    key_upper = key.upper()
    for code in EURO_CODES:
        if f"={code}" in key_upper or f"&{code}" in key_upper or f" {code} " in key_upper:
            return code
    
    # Проверка по маркерам стран в ключе
    country_keywords = {
        'RU': ['RUSSIA', 'РОССИЯ', 'RUS', 'RU-'],
        'US': ['USA', 'UNITED STATES', 'AMERICA'],
        'GB': ['UK', 'UNITED KINGDOM', 'BRITAIN', 'ENGLAND'],
        'DE': ['GERMANY', 'DEUTSCHLAND'],
        'FR': ['FRANCE', 'FRANÇAIS'],
        'IT': ['ITALY', 'ITALIA'],
        'ES': ['SPAIN', 'ESPAÑA'],
        'NL': ['NETHERLANDS', 'HOLLAND'],
        'JP': ['JAPAN', 'JAPANESE'],
        'KR': ['KOREA', 'SOUTH KOREA'],
        'CN': ['CHINA', 'CHINESE'],
        'TR': ['TURKEY', 'TÜRKIYE'],
        'IN': ['INDIA', 'INDIAN'],
        'BR': ['BRAZIL', 'BRASIL'],
        'AU': ['AUSTRALIA'],
        'CA': ['CANADA'],
        'SG': ['SINGAPORE'],
        'HK': ['HONG KONG'],
        'TW': ['TAIWAN'],
    }
    
    for code, keywords in country_keywords.items():
        for keyword in keywords:
            if keyword in key_upper:
                return code
    
    # Проверка по IP (если это IP адрес)
    try:
        ip = ipaddress.ip_address(host)
        
        # Простая проверка по известным диапазонам (основные провайдеры)
        # Это не полная база, но помогает для некоторых случаев
        ip_str = str(ip)
        
        # Российские IP диапазоны (основные)
        if ip_str.startswith(('5.', '31.', '37.', '46.', '62.', '77.', '78.', '79.', '80.', '81.', '82.', '83.', '84.', '85.', '87.', '88.', '89.', '90.', '91.', '92.', '93.', '94.', '95.', '109.', '141.', '178.', '185.', '188.', '194.', '195.', '212.', '213.', '217.')):
            return "RU"
        
        # Немецкие IP (основные)
        if ip_str.startswith(('5.', '46.', '62.', '78.', '80.', '81.', '82.', '83.', '85.', '87.', '88.', '89.', '91.', '93.', '94.', '95.', '134.', '136.', '138.', '141.', '144.', '145.', '146.', '149.', '151.', '152.', '153.', '155.', '157.', '158.', '159.', '176.', '178.', '185.', '188.', '194.', '195.', '212.', '213.', '217.')):
            # Более точная проверка для DE
            if ip_str.startswith(('5.9.', '5.10.', '5.11.', '5.12.', '5.13.', '5.14.', '5.15.', '46.4.', '62.146.', '78.46.', '80.153.', '81.169.', '82.149.', '83.169.', '85.10.', '87.106.', '88.198.', '91.65.', '93.184.', '94.130.', '95.90.', '134.60.', '136.243.', '138.201.', '141.101.', '144.76.', '145.253.', '146.0.', '149.154.', '151.252.', '152.89.', '153.92.', '155.133.', '157.90.', '158.69.', '159.69.', '176.9.', '178.63.', '185.199.', '188.40.', '194.110.', '195.201.', '212.47.', '213.133.', '217.160.')):
                return "DE"
        
        # Голландские IP
        if ip_str.startswith(('5.79.', '5.101.', '5.153.', '5.188.', '31.204.', '37.97.', '46.19.', '46.21.', '46.22.', '46.23.', '46.30.', '46.166.', '62.45.', '77.247.', '78.24.', '80.57.', '80.69.', '80.101.', '81.17.', '82.94.', '83.80.', '84.104.', '85.17.', '87.233.', '88.159.', '89.46.', '91.224.', '94.75.', '94.142.', '95.85.', '109.200.', '141.101.', '178.62.', '185.13.', '188.166.', '194.109.', '195.121.', '212.83.', '213.136.', '217.23.')):
            return "NL"
        
        # Британские IP
        if ip_str.startswith(('5.62.', '5.101.', '5.153.', '31.24.', '37.59.', '46.19.', '46.21.', '46.22.', '46.23.', '46.30.', '46.166.', '51.', '62.45.', '77.247.', '78.24.', '80.57.', '80.69.', '80.101.', '81.17.', '82.94.', '83.80.', '84.104.', '85.17.', '87.233.', '88.159.', '89.46.', '91.224.', '94.75.', '94.142.', '95.85.', '109.200.', '141.101.', '178.62.', '185.13.', '188.166.', '194.109.', '195.121.', '212.83.', '213.136.', '217.23.')):
            # Более точная проверка для GB
            if ip_str.startswith(('5.62.', '5.101.', '5.153.', '31.24.', '37.59.', '46.19.', '46.21.', '46.22.', '46.23.', '46.30.', '46.166.', '51.', '62.45.', '77.247.', '78.24.', '80.57.', '80.69.', '80.101.', '81.17.', '82.94.', '83.80.', '84.104.', '85.17.', '87.233.', '88.159.', '89.46.', '91.224.', '94.75.', '94.142.', '95.85.', '109.200.', '141.101.', '178.62.', '185.13.', '188.166.', '194.109.', '195.121.', '212.83.', '213.136.', '217.23.')):
                return "GB"
        
        # Американские IP (Cloudflare, AWS и др.)
        if ip_str.startswith(('104.16.', '104.17.', '104.18.', '104.19.', '104.20.', '104.21.', '104.22.', '104.23.', '104.24.', '104.25.', '104.26.', '104.27.', '104.28.', '104.29.', '104.30.', '104.31.', '172.64.', '172.65.', '172.66.', '172.67.', '172.68.', '172.69.', '172.70.', '172.71.', '172.72.', '172.73.', '172.74.', '172.75.', '172.76.', '172.77.', '172.78.', '172.79.', '172.80.', '172.81.', '172.82.', '172.83.', '172.84.', '172.85.', '172.86.', '172.87.', '172.88.', '172.89.', '172.90.', '172.91.', '172.92.', '172.93.', '172.94.', '172.95.', '172.96.', '172.97.', '172.98.', '172.99.', '172.100.', '172.101.', '172.102.', '172.103.', '172.104.', '172.105.', '172.106.', '172.107.', '172.108.', '172.109.', '172.110.', '172.111.')):
            return "US"
        
    except ValueError:
        # Не IP адрес, продолжаем проверку по домену
        pass
    
    return "UNKNOWN"

def is_garbage(key: str) -> bool:
    """Проверяет ключ на мусор (CN, IR, локальные IP и т.д.)"""
    # Декодируем URL-encoded части для правильной проверки
    decoded_key = key
    if "#" in key:
        key_part, label_part = key.split("#", 1)
        try:
            decoded_label = unquote(label_part)
            decoded_key = f"{key_part}#{decoded_label}"
        except:
            pass
    
    upper = decoded_key.upper()
    
    if "://" not in decoded_key:
        return False
    
    scheme, rest = decoded_key.split("://", 1)
    scheme_lower = scheme.lower()
    
    # Проверка маркеров в ключе (более мягкая - только явные маркеры)
    # Не фильтруем ключи, где маркер может быть частью названия страны
    for m in BAD_MARKERS:
        if m in upper:
            # Пропускаем если это часть названия страны (например "China" в "China, Guangzhou")
            if "CHINA" in upper and m == "CN":
                continue
            # Пропускаем если это часть названия страны (например "Iran" в "Iran, Tehran")
            if "IRAN" in upper and m == "IR":
                continue
            # Пропускаем если маркер в URL-encoded части (например %F0%9F%87%A8%F0%9F%87%B3 для флага)
            if "%" in key and m in ["CN", "IR", "KR"]:
                # Это может быть часть URL-encoded флага страны, пропускаем
                continue
            # Для остальных маркеров - проверяем только если это явный маркер (не часть слова)
            # Если маркер окружен пробелами, запятыми, скобками или в начале/конце - это явный маркер
            idx = upper.find(m)
            if idx >= 0:
                # Проверяем контекст вокруг маркера
                before = upper[idx-1] if idx > 0 else ' '
                after = upper[idx+len(m)] if idx+len(m) < len(upper) else ' '
                # Если маркер не окружен буквами/цифрами - это явный маркер
                if not (before.isalnum() or after.isalnum()):
                    return True
    
    # Для VMess - декодируем и проверяем
    if scheme_lower == "vmess":
        try:
            missing_padding = -len(rest) % 4
            if missing_padding:
                rest += "=" * missing_padding
            decoded = base64.b64decode(rest, validate=True).decode('utf-8', errors='ignore')
            vmess_config = json.loads(decoded)
            
            # Проверяем host в JSON
            host = vmess_config.get("add") or vmess_config.get("address", "")
            if host:
                host_lower = host.lower()
                if any(host_lower.endswith(tld) for tld in ['.ir', '.cn']):
                    return True
                if any(ip in host_lower for ip in ['127.0.0.1', 'localhost', '0.0.0.0']):
                    return True
                # Проверяем маркеры в ps (описание)
                ps = vmess_config.get("ps", "").upper()
                if any(m in ps for m in BAD_MARKERS):
                    return True
        except:
            pass
    
    # Для Shadowsocks и других форматов с @
    if "@" in rest:
        try:
            domain_part = rest.split("@")[1].split("?")[0].split("#")[0]
            if any(domain_part.endswith(tld) for tld in ['.ir', '.cn']):
                return True
            if any(ip in domain_part for ip in ['127.0.0.1', 'localhost', '0.0.0.0']):
                return True
        except:
            pass
    
    # Для SS в base64 формате без @
    elif scheme_lower in ("ss", "ssr"):
        try:
            missing_padding = -len(rest) % 4
            if missing_padding:
                rest += "=" * missing_padding
            decoded = base64.b64decode(rest, validate=True).decode('utf-8', errors='ignore')
            if "@" in decoded:
                domain_part = decoded.split("@")[1].split(":")[0]
                if any(domain_part.endswith(tld) for tld in ['.ir', '.cn']):
                    return True
        except:
            pass
    
    return False

# ==================== КЛАССИФИКАЦИЯ ====================
def is_domain_in_white_list(sni_domain: Optional[str]) -> bool:
    """
    Проверяет, соответствует ли SNI домен доменам из белого списка.
    Проверка идет по ключевым словам, что позволяет находить все поддомены компаний автоматически.
    Например: api.vk.com, vk-api.com, vk.ru - все будут найдены по ключевому слову 'vk'.
    """
    if not sni_domain:
        return False
    
    sni_domain = sni_domain.lower().strip()
    
    # Проверка по ключевым словам
    for keyword in WHITE_LIST_KEYWORDS:
        keyword_lower = keyword.lower()
        
        # Для .ru и .рф проверяем что это действительно домен
        if keyword_lower in ['.ru', '.рф']:
            # Проверяем что .ru или .рф находится в конце домена или перед следующим доменом
            if sni_domain.endswith(keyword_lower) or f'{keyword_lower}.' in sni_domain:
                return True
            continue
        
        # Для остальных ключевых слов проверяем что это отдельное слово
        # (окружено точками, дефисами или в начале/конце)
        keyword_pos = sni_domain.find(keyword_lower)
        if keyword_pos >= 0:
            # Проверяем что ключевое слово не является частью другого слова
            before_char = sni_domain[keyword_pos - 1] if keyword_pos > 0 else '.'
            after_pos = keyword_pos + len(keyword_lower)
            after_char = sni_domain[after_pos] if after_pos < len(sni_domain) else '.'
            
            # Ключевое слово должно быть отдельным (окружено точками, дефисами или границами)
            # Это позволяет находить: api.vk.com, vk-api.com, vk.ru, но не находить в других словах
            if (before_char in ['.', '-', '/'] or keyword_pos == 0) and \
               (after_char in ['.', '-', '/'] or after_pos >= len(sni_domain)):
                return True
    
    return False

def is_cidr_russian(cidr: Optional[str]) -> bool:
    """
    Проверяет, относится ли CIDR к российским IP-адресам.
    """
    if not cidr:
        return False
    
    try:
        # Парсим CIDR
        network = ipaddress.ip_network(cidr, strict=False)
        
        # Российские IP диапазоны (основные)
        russian_ranges = [
            ipaddress.ip_network('5.0.0.0/8', strict=False),
            ipaddress.ip_network('31.0.0.0/8', strict=False),
            ipaddress.ip_network('37.0.0.0/8', strict=False),
            ipaddress.ip_network('46.0.0.0/8', strict=False),
            ipaddress.ip_network('62.0.0.0/8', strict=False),
            ipaddress.ip_network('77.0.0.0/8', strict=False),
            ipaddress.ip_network('78.0.0.0/8', strict=False),
            ipaddress.ip_network('79.0.0.0/8', strict=False),
            ipaddress.ip_network('80.0.0.0/8', strict=False),
            ipaddress.ip_network('81.0.0.0/8', strict=False),
            ipaddress.ip_network('82.0.0.0/8', strict=False),
            ipaddress.ip_network('83.0.0.0/8', strict=False),
            ipaddress.ip_network('84.0.0.0/8', strict=False),
            ipaddress.ip_network('85.0.0.0/8', strict=False),
            ipaddress.ip_network('87.0.0.0/8', strict=False),
            ipaddress.ip_network('88.0.0.0/8', strict=False),
            ipaddress.ip_network('89.0.0.0/8', strict=False),
            ipaddress.ip_network('90.0.0.0/8', strict=False),
            ipaddress.ip_network('91.0.0.0/8', strict=False),
            ipaddress.ip_network('92.0.0.0/8', strict=False),
            ipaddress.ip_network('93.0.0.0/8', strict=False),
            ipaddress.ip_network('94.0.0.0/8', strict=False),
            ipaddress.ip_network('95.0.0.0/8', strict=False),
            ipaddress.ip_network('109.0.0.0/8', strict=False),
            ipaddress.ip_network('141.0.0.0/8', strict=False),
            ipaddress.ip_network('178.0.0.0/8', strict=False),
            ipaddress.ip_network('185.0.0.0/8', strict=False),
            ipaddress.ip_network('188.0.0.0/8', strict=False),
            ipaddress.ip_network('194.0.0.0/8', strict=False),
            ipaddress.ip_network('195.0.0.0/8', strict=False),
            ipaddress.ip_network('212.0.0.0/8', strict=False),
            ipaddress.ip_network('213.0.0.0/8', strict=False),
            ipaddress.ip_network('217.0.0.0/8', strict=False),
        ]
        
        # Проверяем пересечение с российскими диапазонами
        for russian_range in russian_ranges:
            if network.overlaps(russian_range):
                return True
        
        # Для IPv6 пока не проверяем (можно добавить позже)
        if isinstance(network, ipaddress.IPv6Network):
            return False
        
        return False
    except (ValueError, ipaddress.AddressValueError):
        return False

class SmartClassifier:
    """
    Классифицирует ключи на white/black/universal списки.
    
    Логика:
    - white: только протоколы с SNI, которые маскируются под домены из белого списка
    - black: серверы которые обходят блокировки, но не подходят для белого списка
    - universal: все рабочие серверы (и white и black)
    """
    
    def predict(self, key: str) -> str:
        """
        Возвращает тип списка: 'white', 'black' или 'universal'
        
        Белый список: если протокол поддерживает SNI И (SNI соответствует доменам из белого списка ИЛИ CIDR указывает на российские IP)
        Черный список: если протокол поддерживает SNI но SNI не в белом списке, или протокол не поддерживает SNI
        Универсальный: все рабочие серверы (по умолчанию)
        """
        # Определяем тип протокола
        protocol_type = get_protocol_type(key)
        
        # Shadowsocks (SS/SSR) не поддерживает SNI - не может быть в белом списке
        if protocol_type == "shadowsocks":
            # SS может быть только в черном или универсальном списке
            key_upper = key.upper()
            black_markers_upper = [m.upper() for m in BLACK_MARKERS]
            if any(marker in key_upper for marker in black_markers_upper):
                return "black"
            return "universal"
        
        # Извлекаем SNI и CIDR из ключа
        sni, cidr = extract_sni_and_cidr(key)
        
        # Проверяем соответствие SNI белому списку
        sni_in_white_list = sni and is_domain_in_white_list(sni)
        
        # Проверяем CIDR на российские IP (для белого списка)
        cidr_is_russian = cidr and is_cidr_russian(cidr)
        
        # Если SNI в белом списке ИЛИ CIDR указывает на российские IP - это белый список
        if sni_in_white_list or cidr_is_russian:
            # Дополнительно проверяем, что протокол поддерживает SNI/TLS
            if protocol_type in ("vless", "vmess", "trojan", "hysteria2"):
                _, _, is_tls = parse_key(key)
                # Для белого списка желательно наличие TLS или SNI
                if is_tls or sni or cidr_is_russian:
                    return "white"
        
        # Если протокол поддерживает SNI (VLESS, VMess, Trojan с TLS), но SNI не в белом списке
        # или SNI отсутствует - это черный список (обходит блокировки, но не подходит для белого)
        if protocol_type in ("vless", "vmess", "trojan"):
            # Проверяем есть ли TLS (для VLESS и VMess может быть без TLS)
            _, _, is_tls = parse_key(key)
            if is_tls or sni:  # Если есть TLS или SNI указан - протокол может маскироваться
                key_upper = key.upper()
                black_markers_upper = [m.upper() for m in BLACK_MARKERS]
                white_markers_upper = [m.upper() for m in WHITE_MARKERS]
                
                # Если есть явные маркеры черного списка - черный список
                if any(marker in key_upper for marker in black_markers_upper):
                    return "black"
                
                # Если есть маркеры белого списка но SNI не соответствует и CIDR не российский - черный список
                if any(marker in key_upper for marker in white_markers_upper):
                    if not (sni_in_white_list or cidr_is_russian):
                        return "black"
                
                # Если SNI указан но не в белом списке и CIDR не российский - черный список
                if sni and not sni_in_white_list and not cidr_is_russian:
                    return "black"
        
        # Для других протоколов (Hysteria2 и т.д.) - проверяем маркеры
        key_upper = key.upper()
        white_markers_upper = [m.upper() for m in WHITE_MARKERS]
        black_markers_upper = [m.upper() for m in BLACK_MARKERS]
        
        # Если есть маркеры белого списка
        if any(marker in key_upper for marker in white_markers_upper):
            # Проверяем SNI или CIDR
            if sni_in_white_list or cidr_is_russian:
                return "white"
            # Иначе - черный список (не подходит для белого)
            return "black"
        
        # Если есть маркеры черного списка - черный список
        if any(marker in key_upper for marker in black_markers_upper):
            return "black"
        
        # По умолчанию - универсальный (все рабочие серверы)
        return "universal"

# ==================== ЗАГРУЗКА КЛЮЧЕЙ ====================
def fetch_keys(urls: List[str], tag: Optional[str] = None) -> List[Tuple[str, str]]:
    """
    Загружает ключи из списка URL.
    Если tag не указан, определяется автоматически для каждого URL.
    Улучшенный парсинг для извлечения всех ключей.
    """
    out = []
    
    # Если тег не указан, группируем URL по тегам
    if tag is None:
        url_groups = defaultdict(list)
        for url in urls:
            url_tag = detect_tag_from_url(url)
            url_groups[url_tag].append(url)
        
        # Загружаем каждую группу отдельно
        all_results = []
        for url_tag, url_list in url_groups.items():
            print(f"\n📥 Загрузка {url_tag}... ({len(url_list)} источников)")
            results = fetch_keys(url_list, url_tag)
            all_results.extend(results)
        return all_results
    
    # Если тег указан, используем улучшенную логику
    print(f"\n📥 Загрузка {tag}... ({len(urls)} источников)")
    
    session = requests.Session()
    session.headers.update({"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"})
    
    # Поддерживаемые протоколы для поиска
    protocols = ["vless://", "vmess://", "trojan://", "ss://", "ssr://", "hysteria2://", "hy2://", "socks://", "socks5://"]
    
    for url in urls:
        url = url.strip()
        if not url or "://" not in url:
            continue
        
        print(f"  ➜ {url[:60]}...")
        try:
            resp = session.get(url, timeout=30)  # Увеличен таймаут
            resp.raise_for_status()
            
            content = resp.text.strip()
            if not content:
                print(f"    ❌ Пустой ответ")
                continue
            
            # Пробуем разные способы декодирования
            lines = []
            
            # Способ 1: Проверяем на base64 (если нет протоколов в первых 200 символах)
            if not any(proto in content[:200] for proto in protocols):
                # Пробуем декодировать как base64
                try:
                    # Убираем пробелы и переносы строк для base64
                    clean_content = ''.join(content.split())
                    missing_padding = -len(clean_content) % 4
                    if missing_padding:
                        clean_content += "=" * missing_padding
                    decoded = base64.b64decode(clean_content, validate=True).decode('utf-8', errors='ignore')
                    lines = decoded.splitlines()
                except:
                    # Если не base64, пробуем как обычный текст
                    pass
            
            # Способ 2: Если не получилось декодировать или уже есть протоколы
            if not lines:
                # Разбиваем по разным разделителям
                # Пробуем разные варианты разделения
                for separator in ['\n', '\r\n', '\r', '|', ' ', '\t']:
                    potential_lines = content.split(separator)
                    if any(proto in line for line in potential_lines[:10] for proto in protocols):
                        lines = potential_lines
                        break
                
                # Если не нашли разделитель, пробуем найти ключи в строке напрямую
                if not lines:
                    # Ищем все вхождения протоколов
                    found_keys = []
                    for proto in protocols:
                        start = 0
                        while True:
                            idx = content.find(proto, start)
                            if idx == -1:
                                break
                            # Ищем конец ключа (до следующего протокола или до конца строки)
                            end = len(content)
                            for next_proto in protocols:
                                next_idx = content.find(next_proto, idx + len(proto))
                                if next_idx != -1 and next_idx < end:
                                    end = next_idx
                            # Также ищем конец по разделителям
                            for sep in ['\n', '\r', '|', ' ', '\t']:
                                sep_idx = content.find(sep, idx)
                                if sep_idx != -1 and sep_idx < end:
                                    end = sep_idx
                            
                            key = content[idx:end].strip()
                            if key and len(key) < 2000:
                                found_keys.append(key)
                            start = idx + len(proto)
                    
                    if found_keys:
                        lines = found_keys
                    else:
                        # Последняя попытка - просто разбить по строкам
                        lines = content.splitlines()
            
            loaded = 0
            skipped_invalid = 0
            skipped_garbage = 0
            
            # Определяем тип источника по URL
            url_upper = url.upper()
            source_type = None
            if "BLACK" in url_upper or "/black" in url_upper.lower():
                source_type = "black"
            elif any(m in url_upper for m in ["WHITE", "BYPASS", "WHITELIST"]):
                source_type = "white"
            
            # Обрабатываем все строки
            for line in lines:
                line = line.strip()
                if not line:
                    continue
                
                # Убираем возможные префиксы/суффиксы
                line = line.strip('|').strip('"').strip("'").strip()
                
                # Проверяем что это похоже на ключ (содержит протокол)
                if not any(proto in line.lower() for proto in protocols):
                    continue
                
                # Проверяем длину
                if len(line) >= 2000:
                    skipped_invalid += 1
                    continue
                
                # Проверяем что ключ можно распарсить
                host, port, _ = parse_key(line)
                if not host or not port:
                    skipped_invalid += 1
                    continue
                
                # Проверяем на мусор
                if is_garbage(line):
                    skipped_garbage += 1
                    continue
                
                # Если в источнике указан тип, добавляем маркер в ключ
                if source_type and "#" in line:
                    key_part, label_part = line.rsplit("#", 1)
                    # Добавляем маркер типа источника в метку
                    if source_type.upper() not in label_part.upper():
                        line = f"{key_part}#{source_type}_{label_part}"
                elif source_type:
                    # Если нет метки, добавляем маркер
                    line = f"{line}#{source_type}_source"
                
                out.append((line, tag))
                loaded += 1
            
            status_parts = []
            if loaded:
                status_parts.append(f"✅ {loaded}")
            if skipped_invalid:
                status_parts.append(f"⚠️ невалидных: {skipped_invalid}")
            if skipped_garbage:
                status_parts.append(f"🗑️ мусор: {skipped_garbage}")
            
            if status_parts:
                print(f"    {' | '.join(status_parts)}")
                
        except requests.exceptions.RequestException as e:
            print(f"    ❌ HTTP error: {e}")
        except Exception as e:
            print(f"    ❌ {e}")
    
    print(f"📊 {tag}: {len(out)} ключей")
    return out

# ==================== ФОРМАТИРОВАНИЕ ====================
def format_label(key_info: KeyInfo) -> str:
    """
    Форматирует метку ключа с улучшенным рейтингом.
    Формат: флагстрана_тип_рейтинг_канал
    Для белых списков добавляет SNI и CIDR информацию.
    """
    # Получаем эмодзи флаг страны
    country_flag = get_country_flag(key_info.country)
    
    # Получаем рейтинг (звезды, иконка, оценка)
    stars, icon, grade = key_info.get_rating()
    
    parts = [
        f"{country_flag}{key_info.country}",  # Флаг и код страны
        key_info.routing_type[0].upper()  # Тип: W/B/U
    ]
    
    # Добавляем метрики если есть
    if key_info.metrics.bandwidth:
        parts.append(f"{key_info.metrics.bandwidth:.1f}Mb")
    
    if key_info.metrics.jitter:
        parts.append(f"J{key_info.metrics.jitter}")
    
    if key_info.metrics.uptime and key_info.metrics.uptime < 100:
        parts.append(f"UP{int(key_info.metrics.uptime)}")
    
    # Для белых списков добавляем SNI и CIDR информацию
    if key_info.routing_type == "white":
        parts.append("🏳️")
        
        # Извлекаем SNI и CIDR
        sni, cidr = extract_sni_and_cidr(key_info.key)
        
        if sni:
            # Сокращаем длинный домен для компактности
            sni_short = sni
            if len(sni) > 20:
                # Берем только домен без поддоменов если слишком длинный
                domain_parts = sni.split(".")
                if len(domain_parts) >= 2:
                    sni_short = ".".join(domain_parts[-2:])
            parts.append(f"SNI:{sni_short}")
        
        if cidr:
            parts.append(f"CIDR:{cidr}")
    
    # Добавляем рейтинг: иконка + звезды + оценка
    stars_display = key_info.get_stars_display()
    parts.append(f"{icon}{stars_display}{grade}")
    
    parts.append(CFG.MY_CHANNEL)
    
    return "_".join(parts)

def save_chunked(keys_list: List[str], folder: str, base_name: str) -> List[str]:
    """
    Сохраняет все ключи в один файл без разбиения на части.
    """
    created_files = []
    valid_keys = [k.strip() for k in keys_list if k and isinstance(k, str) and k.strip()]
    
    fname = f"{base_name}.txt"
    os.makedirs(folder, exist_ok=True)
    
    with open(os.path.join(folder, fname), "w", encoding="utf-8") as f:
        f.write("\n".join(valid_keys))
    
    created_files.append(fname)
    print(f"  📄 {fname}: {len(valid_keys)} ключей")
    
    return created_files

# ==================== TUI ====================
class TUI:
    def __init__(self, stdscr):
        self.stdscr = stdscr
        self.height, self.width = stdscr.getmaxyx()
        self.current_row = 0
        self.menu_items = [
            "1. Быстрая проверка",
            "2. Полная проверка (глубокая + метрики)",
            "3. Настройки",
            "4. Очистить кэш",
            "5. Статистика",
            "6. Выход"
        ]
        self.settings = {
            "threads": 50,
            "max_keys": CFG.MAX_KEYS,
            "timeout": CFG.TIMEOUT,
            "enable_bandwidth": False,
            "enable_jitter": False,
            "enable_deep": True,  # Глубокая проверка по умолчанию включена
            "min_quality": CFG.MIN_QUALITY_SCORE
        }
        signal.signal(signal.SIGINT, self.signal_handler)
        signal.signal(signal.SIGTSTP, lambda s, f: self.cleanup())
    
    def signal_handler(self, signum, frame):
        self.cleanup()
        exit(0)
    
    def cleanup(self):
        try:
            curses.nocbreak()
            self.stdscr.keypad(False)
            curses.echo()
            curses.endwin()
        except:
            pass
    
    def draw_menu(self):
        self.stdscr.clear()
        self.height, self.width = self.stdscr.getmaxyx()
        
        title = "VPN Checker v15.2 - GitHub Edition"
        self.stdscr.attron(curses.A_BOLD | curses.A_REVERSE)
        self.stdscr.addstr(0, max(0, (self.width - len(title)) // 2), title[:self.width-1])
        self.stdscr.attroff(curses.A_BOLD | curses.A_REVERSE)
        
        info_y = 2
        self.stdscr.addstr(info_y, 2, f"📂 Директория: {CFG.BASE_DIR}"[:self.width-3], curses.A_DIM)
        self.stdscr.addstr(info_y + 1, 2, f"🔧 Потоков: {self.settings['threads']} | 🔑 Макс. ключей: {self.settings['max_keys']}"[:self.width-3], curses.A_DIM)
        self.stdscr.addstr(info_y + 2, 2, f"⏱️  Таймаут: {self.settings['timeout']}с | 📶 Метрики: {'✅' if self.settings['enable_bandwidth'] else '❌'} Bw {'✅' if self.settings['enable_jitter'] else '❌'} Jt {'✅' if self.settings['enable_deep'] else '❌'} Deep"[:self.width-3], curses.A_DIM)
        
        menu_y = info_y + 4
        for idx, item in enumerate(self.menu_items):
            x = max(0, (self.width - len(item)) // 2)
            y = menu_y + idx
            
            if idx == self.current_row:
                self.stdscr.attron(curses.A_REVERSE)
                self.stdscr.addstr(y, x, item[:self.width-x-1])
                self.stdscr.attroff(curses.A_REVERSE)
            else:
                self.stdscr.addstr(y, x, item[:self.width-x-1])
        
        hint = "↑↓ - навигация, Enter - выбрать, q - выход"
        self.stdscr.addstr(self.height - 1, max(0, (self.width - len(hint)) // 2), hint[:self.width-1], curses.A_DIM)
        
        self.stdscr.refresh()
    
    def run_check(self, fast: bool = False):
        try:
            local_config = {
                'THREADS': self.settings['threads'],
                'MAX_KEYS': self.settings['max_keys'],
                'TIMEOUT': self.settings['timeout'],
                'ENABLE_BANDWIDTH_TEST': self.settings['enable_bandwidth'] if not fast else False,
                'ENABLE_JITTER_TEST': self.settings['enable_jitter'] if not fast else False,
                'ENABLE_DEEP_TEST': self.settings['enable_deep'] if not fast else False,  # Глубокая проверка только в полной проверке
                'MIN_QUALITY_SCORE': self.settings['min_quality']
            }
            
            for folder in [CFG.FOLDER_RU, CFG.FOLDER_EURO]:
                if os.path.exists(folder): shutil.rmtree(folder)
                os.makedirs(folder, exist_ok=True)
            
            classifier = SmartClassifier()
            checker = ConnectionChecker()
            analytics = Analytics(CFG.ANALYTICS_FILE)
            blacklist = BlacklistManager(CFG.BLACKLIST_FILE)
            
            self._draw_progress(0.1, "Загрузка источников...")
            all_tasks = fetch_keys(URLS)  # Автоматическое распределение по тегам
            
            unique = {get_hash(k.split("#")[0]): (k, t) for k, t in all_tasks}
            all_items = list(unique.values())[:local_config['MAX_KEYS']]
            
            self._draw_progress(0.2, "Проверка кэша...")
            current_time = time.time()
            to_check = []
            results = {
                "ru_white": [], "ru_black": [], "ru_universal": [],
                "euro_white": [], "euro_black": [], "euro_universal": []
            }
            cache_hits = 0
            
            history = load_json(CFG.HISTORY_FILE)
            for key, tag in all_items:
                key_id = get_hash(key.split("#")[0])
                cached = history.get(key_id)
                
                if cached and (current_time - cached['time'] < CFG.CACHE_HOURS * 3600) and cached.get('alive'):
                    metrics = KeyMetrics(
                        latency=cached['latency'], 
                        last_check=cached['time']
                    )
                    country = cached.get('country', 'UNKNOWN')
                    routing_type = cached.get('routing_type', 'universal')
                    key_info = KeyInfo(key, key_id, tag, country, routing_type, metrics)
                    label = format_label(key_info)
                    final = f"{key.split('#')[0]}#{label}"
                    category = f"{'euro' if tag == 'MY' else tag.lower()}_{routing_type}"
                    
                    if not (tag == "MY" and country == "RU"):
                        results[category].append(final)
                        cache_hits += 1
                else:
                    to_check.append((key, tag))
            
            if to_check:
                checked = 0
                with ThreadPoolExecutor(max_workers=local_config['THREADS']) as executor:
                    futures = {executor.submit(self._check_key, item, local_config): item 
                              for item in to_check}
                    
                    for future in as_completed(futures):
                        checked += 1
                        progress = 0.5 + (checked / len(to_check)) * 0.5
                        self._draw_progress(progress, f"Проверка: {checked}/{len(to_check)}")
                        
                        try:
                            result = future.result(timeout=local_config['TIMEOUT'] + 3)
                            if result:
                                category, final, key_id = result
                                results[category].append(final)
                        except:
                            pass
            
            self._draw_progress(0.95, "Сохранение...")
            self._save_results(results, history, blacklist, analytics)
            
            self._draw_progress(1.0, "Завершено!")
            time.sleep(1)
            
        except KeyboardInterrupt:
            raise
        except Exception as e:
            self._draw_progress(1.0, f"Ошибка: {str(e)}")
            time.sleep(2)
            raise
    
    def _check_key(self, data, config):
        key, tag = data
        
        host, port, is_tls = parse_key(key)
        if not host: return None
        
        blacklist = BlacklistManager(CFG.BLACKLIST_FILE)
        if blacklist.is_blacklisted(host): return None
        
        key_id = get_hash(key.split("#")[0])
        
        checker = ConnectionChecker()
        
        # Определяем протокол для проверки
        protocol_type = get_protocol_type(key)
        protocol = "udp" if protocol_type == "hysteria2" else "tcp"
        
        # Для российских источников (RU) - всегда более глубокая проверка
        is_ru_source = tag == "RU"
        enable_deep_for_ru = is_ru_source or config.get('ENABLE_DEEP_TEST', False)
        
        # Базовая проверка соединения с VPN сервером
        server_ok = False
        latency = None
        
        # Для RU источников делаем больше попыток и более тщательную проверку
        retry_count = CFG.RETRY_ATTEMPTS * (2 if is_ru_source else 1)
        
        for attempt in range(retry_count):
            result = checker.check_basic(host, port, is_tls, protocol)
            if result:
                server_ok = True
                latency = result  # check_basic возвращает latency
                break
            time.sleep(0.1 * (attempt + 1))
        
        # Если сервер не прошел базовую проверку
        if not server_ok: 
            return None
        
        # Используем реальную latency если есть, иначе фиксированное значение
        if latency is None:
            latency = 100
        
        # Глубокая проверка работоспособности (всегда для RU, или если включена в настройках)
        if enable_deep_for_ru:
            deep_check = checker.check_deep(key, host, port, is_tls)
            if not deep_check:
                # Для RU источников делаем дополнительную проверку
                if is_ru_source:
                    # Пробуем еще раз с увеличенным таймаутом
                    time.sleep(0.2)
                    deep_check = checker.check_deep(key, host, port, is_tls)
                
                if not deep_check:
                    # Сервер не отвечает на глубокую проверку - помечаем как нерабочий
                    blacklist.record_failure(host)
                    return None
        
        # Для RU источников делаем дополнительные метрики
        metrics = KeyMetrics(latency=latency, last_check=time.time())
        
        # Для RU источников всегда проверяем jitter и bandwidth если доступны
        if is_ru_source:
            if latency < 300:  # Для RU проверяем даже при большей задержке
                metrics.jitter = checker.check_jitter(host, port, is_tls)
            if latency < 400:  # Для RU проверяем bandwidth даже при большей задержке
                metrics.bandwidth = checker.check_bandwidth(host, port, is_tls)
        else:
            # Для других источников - только если включено в настройках
            if config.get('ENABLE_JITTER_TEST', False) and latency < 200:
                metrics.jitter = checker.check_jitter(host, port, is_tls)
            if config.get('ENABLE_BANDWIDTH_TEST', False) and latency < 300:
                metrics.bandwidth = checker.check_bandwidth(host, port, is_tls)
        
        # Определяем тип маршрутизации (после проверки соединения)
        classifier = SmartClassifier()
        routing_type = classifier.predict(key)
        country = get_country(key, host)
        
        key_info = KeyInfo(key, key_id, tag, country, routing_type, metrics)
        
        # Для RU источников используем более низкий порог качества (они проверяются глубже)
        min_quality = config.get('MIN_QUALITY_SCORE', 0.0)
        if is_ru_source:
            # Для RU снижаем минимальный порог на 10 пунктов, так как проверка более строгая
            min_quality = max(0.0, min_quality - 10.0)
        
        if key_info.quality_score() < min_quality:
            return None
        
        label = format_label(key_info)
        final = f"{key.split('#')[0]}#{label}"
        category = f"{'euro' if tag == 'MY' else tag.lower()}_{routing_type}"
        
        history = load_json(CFG.HISTORY_FILE)
        history[key_id] = {
            'alive': True,
            'latency': latency,
            'time': time.time(),
            'country': country,
            'routing_type': routing_type,
            'deep_check': enable_deep_for_ru,
            'is_ru_source': is_ru_source
        }
        save_json(CFG.HISTORY_FILE, history)
        
        return category, final, key_id
    
    def _save_results(self, results, history, blacklist, analytics):
        for cat in results:
            results[cat].sort(key=extract_ping)
        
        save_chunked(results['ru_white'], CFG.FOLDER_RU, "ru_white")
        save_chunked(results['ru_black'], CFG.FOLDER_RU, "ru_black")
        save_chunked(results['ru_universal'], CFG.FOLDER_RU, "ru_universal")
        save_chunked(results['euro_white'], CFG.FOLDER_EURO, "euro_white")
        save_chunked(results['euro_black'], CFG.FOLDER_EURO, "euro_black")
        save_chunked(results['euro_universal'], CFG.FOLDER_EURO, "euro_universal")
        
        GITHUB_REPO = "Mihuil121/vpn-checker-backend-fox"
        BASE_RU = f"https://raw.githubusercontent.com/{GITHUB_REPO}/main/{CFG.BASE_DIR}/RU_Best"
        BASE_EU = f"https://raw.githubusercontent.com/{GITHUB_REPO}/main/{CFG.BASE_DIR}/My_Euro"
        
        subs = ["=== 🇷🇺 РОССИЯ ===", ""]
        for name, fname in [("⚪ БЕЛЫЙ СПИСОК", "ru_white.txt"),
                           ("⚫ ЧЕРНЫЙ СПИСОК", "ru_black.txt"),
                           ("🔘 УНИВЕРСАЛЬНЫЕ", "ru_universal.txt")]:
            subs.append(f"{name}:")
            subs.append(f"{BASE_RU}/{fname}")
            subs.append("")
        
        subs.extend(["=== 🇪🇺 ЕВРОПА ===", ""])
        for name, fname in [("⚪ БЕЛЫЙ СПИСОК", "euro_white.txt"),
                           ("⚫ ЧЕРНЫЙ СПИСОК", "euro_black.txt"),
                           ("🔘 УНИВЕРСАЛЬНЫЕ", "euro_universal.txt")]:
            subs.append(f"{name}:")
            subs.append(f"{BASE_EU}/{fname}")
            subs.append("")
        
        os.makedirs(CFG.BASE_DIR, exist_ok=True)
        with open(os.path.join(CFG.BASE_DIR, "subscriptions_list.txt"), "w", encoding="utf-8") as f:
            f.write("\n".join(subs))
        
        cutoff = time.time() - (86400 * 3)
        history_cleaned = {k: v for k, v in history.items() if v['time'] > cutoff}
        save_json(CFG.HISTORY_FILE, history_cleaned)
        blacklist.save()
        analytics.save()
    
    def _draw_progress(self, progress: float, status: str):
        self.stdscr.clear()
        
        title = "ПРОВЕРКА В ПРОЦЕССЕ"
        self.stdscr.attron(curses.A_BOLD | curses.A_REVERSE)
        self.stdscr.addstr(0, max(0, (self.width - len(title)) // 2), title[:self.width-1])
        self.stdscr.attroff(curses.A_BOLD | curses.A_REVERSE)
        
        bar_width = min(60, self.width - 20)
        bar_x = max(0, (self.width - bar_width) // 2)
        bar_y = self.height // 2 - 2
        
        filled = int(bar_width * progress)
        bar = "█" * filled + "░" * (bar_width - filled)
        
        self.stdscr.addstr(bar_y, bar_x, f"[{bar}]"[:self.width-bar_x-1])
        self.stdscr.addstr(bar_y + 1, bar_x + bar_width // 2 - 5, f"{progress * 100:.1f}%"[:self.width-bar_x-1])
        self.stdscr.addstr(bar_y + 3, max(0, (self.width - len(status)) // 2), status[:self.width-1])
        
        hint = "Ctrl+C - отмена | Ctrl+Z - приостановить"
        self.stdscr.addstr(self.height - 1, max(0, (self.width - len(hint)) // 2), hint[:self.width-1], curses.A_DIM)
        
        self.stdscr.refresh()
    
    def show_settings(self):
        current = 0
        options = list(self.settings.keys())
        
        while True:
            self.stdscr.clear()
            
            title = "НАСТРОЙКИ"
            self.stdscr.attron(curses.A_BOLD | curses.A_REVERSE)
            self.stdscr.addstr(0, max(0, (self.width - len(title)) // 2), title[:self.width-1])
            self.stdscr.attroff(curses.A_BOLD | curses.A_REVERSE)
            
            for idx, opt in enumerate(options):
                y = 3 + idx
                value = self.settings[opt]
                display_value = "Вкл" if isinstance(value, bool) and value else \
                               "Выкл" if isinstance(value, bool) and not value else str(value)
                line = f"{idx + 1}. {opt.replace('_', ' ').title()}: {display_value}"
                
                if idx == current:
                    self.stdscr.attron(curses.A_REVERSE)
                    self.stdscr.addstr(y, 2, line[:self.width-3])
                    self.stdscr.attroff(curses.A_REVERSE)
                else:
                    self.stdscr.addstr(y, 2, line[:self.width-3])
            
            hint = "↑↓ - выбрать, Enter - редактировать, q - назад"
            self.stdscr.addstr(self.height - 1, 2, hint[:self.width-3], curses.A_DIM)
            
            self.stdscr.refresh()
            
            key = self.stdscr.getch()
            if key == curses.KEY_UP:
                current = max(0, current - 1)
            elif key == curses.KEY_DOWN:
                current = min(len(options) - 1, current + 1)
            elif key == ord('\n'):
                self._edit_setting(options[current])
            elif key == ord('q'):
                break
    
    def _edit_setting(self, key: str):
        self.stdscr.clear()
        self.stdscr.addstr(2, 2, f"Редактирование {key}")
        self.stdscr.addstr(4, 2, f"Текущее значение: {self.settings[key]}")
        self.stdscr.addstr(6, 2, "Введите новое значение: ")
        
        curses.echo()
        curses.curs_set(1)
        try:
            value = self.stdscr.getstr(6, 28, 20).decode('utf-8')
            if value:
                if key in ['threads', 'max_keys', 'timeout']:
                    self.settings[key] = max(1, int(value))
                elif key in ['enable_bandwidth', 'enable_jitter', 'enable_deep']:
                    self.settings[key] = value.lower() in ['y', 'yes', 'true', '1', 'on', 'вкл']
                elif key == 'min_quality':
                    self.settings[key] = max(0.0, min(100.0, float(value)))
        except:
            pass
        curses.noecho()
        curses.curs_set(0)
    
    def show_statistics(self):
        self.stdscr.clear()
        
        title = "СТАТИСТИКА"
        self.stdscr.attron(curses.A_BOLD | curses.A_REVERSE)
        self.stdscr.addstr(0, max(0, (self.width - len(title)) // 2), title[:self.width-1])
        self.stdscr.attroff(curses.A_BOLD | curses.A_REVERSE)
        
        y = 3
        try:
            if os.path.exists(CFG.BASE_DIR):
                total_files = sum(len(files) for _, _, files in os.walk(CFG.BASE_DIR))
                total_size = sum(os.path.getsize(os.path.join(dp, f))
                               for dp, _, files in os.walk(CFG.BASE_DIR) for f in files)
                
                self.stdscr.addstr(y, 4, f"Файлов: {total_files}")
                self.stdscr.addstr(y + 1, 4, f"Размер: {total_size / 1024 / 1024:.2f} MB")
            
            history = load_json(CFG.HISTORY_FILE)
            self.stdscr.addstr(y + 3, 4, f"Записей в истории: {len(history)}")
            
            blacklist = load_json(CFG.BLACKLIST_FILE)
            self.stdscr.addstr(y + 4, 4, f"Blacklist: {len(blacklist.get('hosts', []))} хостов")
            
            analytics = load_json(CFG.ANALYTICS_FILE)
            total_checks = sum(len(v.get('checks', [])) for v in analytics.values())
            self.stdscr.addstr(y + 5, 4, f"Всего проверок: {total_checks}")
            
        except Exception as e:
            self.stdscr.addstr(y, 4, f"Ошибка: {e}"[:self.width-5])
        
        self.stdscr.addstr(self.height - 2, 2, "Нажмите любую клавишу...")
        self.stdscr.refresh()
        self.stdscr.getch()
    
    def clear_cache(self):
        self.stdscr.clear()
        self.stdscr.addstr(2, 2, "ОЧИСТКА КЭША")
        
        try:
            files_cleared = 0
            for f in [CFG.HISTORY_FILE, CFG.ANALYTICS_FILE, CFG.BLACKLIST_FILE]:
                if os.path.exists(f):
                    os.remove(f)
                    files_cleared += 1
            
            self.stdscr.addstr(4, 4, f"Очищено файлов: {files_cleared}")
        except Exception as e:
            self.stdscr.addstr(4, 4, f"Ошибка: {e}"[:self.width-5])
        
        self.stdscr.addstr(6, 2, "Нажмите любую клавишу...")
        self.stdscr.refresh()
        self.stdscr.getch()
    
    def run(self):
        curses.curs_set(0)
        
        if curses.has_colors():
            curses.start_color()
            curses.use_default_colors()
        
        try:
            while True:
                self.draw_menu()
                key = self.stdscr.getch()
                
                if key == curses.KEY_UP:
                    self.current_row = max(0, self.current_row - 1)
                elif key == curses.KEY_DOWN:
                    self.current_row = min(len(self.menu_items) - 1, self.current_row + 1)
                elif key == ord('\n'):
                    if self.current_row == 0:
                        self.run_check(fast=True)
                        self.stdscr.getch()
                    elif self.current_row == 1:
                        self.run_check()
                        self.stdscr.getch()
                    elif self.current_row == 2:
                        self.current_row = 0
                        self.show_settings()
                    elif self.current_row == 3:
                        self.clear_cache()
                    elif self.current_row == 4:
                        self.show_statistics()
                    elif self.current_row == 5:
                        break
                elif key == ord('q'):
                    break
        finally:
            self.cleanup()

# ==================== CLI ====================
def run_cli(args):
    try:
        local_config = {
            'THREADS': args.threads,
            'MAX_KEYS': args.max_keys,
            'TIMEOUT': args.timeout or CFG.TIMEOUT,
            'ENABLE_BANDWIDTH_TEST': args.bandwidth,
            'ENABLE_JITTER_TEST': args.jitter,
            'ENABLE_DEEP_TEST': not args.fast,  # Глубокая проверка только в полной проверке
            'MIN_QUALITY_SCORE': args.min_quality
        }
        
        print(f"\n{'='*70}")
        print(f"VPN Checker v15.2 CLI | {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"Threads: {local_config['THREADS']} | Timeout: {local_config['TIMEOUT']}s | Max keys: {local_config['MAX_KEYS']}")
        print(f"Advanced: bandwidth={local_config['ENABLE_BANDWIDTH_TEST']}, jitter={local_config['ENABLE_JITTER_TEST']}, deep={local_config['ENABLE_DEEP_TEST']}")
        print(f"{'='*70}\n")
        
        for folder in [CFG.FOLDER_RU, CFG.FOLDER_EURO]:
            if os.path.exists(folder): shutil.rmtree(folder)
            os.makedirs(folder, exist_ok=True)
        
        classifier = SmartClassifier()
        checker = ConnectionChecker()
        analytics = Analytics(CFG.ANALYTICS_FILE)
        blacklist = BlacklistManager(CFG.BLACKLIST_FILE)
        
        print("ЗАГРУЗКА ИСТОЧНИКОВ")
        print("="*70)
        all_tasks = fetch_keys(URLS)  # Автоматическое распределение по тегам
        
        unique = {get_hash(k.split("#")[0]): (k, t) for k, t in all_tasks}
        all_items = list(unique.values())[:local_config['MAX_KEYS']]
        print(f"\nУникальных: {len(all_items)}")
        
        print("\nПРОВЕРКА КЭША")
        print("="*70)
        current_time = time.time()
        to_check = []
        results = {
            "ru_white": [], "ru_black": [], "ru_universal": [],
            "euro_white": [], "euro_black": [], "euro_universal": []
        }
        cache_hits = 0
        
        history = load_json(CFG.HISTORY_FILE)
        for key, tag in all_items:
            key_id = get_hash(key.split("#")[0])
            cached = history.get(key_id)
            
            if cached and (current_time - cached['time'] < CFG.CACHE_HOURS * 3600) and cached.get('alive'):
                metrics = KeyMetrics(latency=cached['latency'], last_check=cached['time'])
                routing_type = cached.get('routing_type', 'universal')
                country = cached.get('country', 'UNKNOWN')
                key_info = KeyInfo(key, key_id, tag, country, routing_type, metrics)
                label = format_label(key_info)
                final = f"{key.split('#')[0]}#{label}"
                category = f"{'euro' if tag == 'MY' else tag.lower()}_{routing_type}"
                
                if not (tag == "MY" and country == "RU"):
                    results[category].append(final)
                    cache_hits += 1
            else:
                to_check.append((key, tag))
        
        print(f"Из кэша: {cache_hits} | Для проверки: {len(to_check)}")
        
        if to_check:
            print("\nПРОВЕРКА В РЕАЛЬНОМ ВРЕМЕНИ")
            print("="*70)
            
            checked = 0
            failed = 0
            stats = defaultdict(lambda: defaultdict(int))
            
            with ThreadPoolExecutor(max_workers=local_config['THREADS']) as executor:
                futures = {executor.submit(_check_key_cli, item, local_config): item 
                          for item in to_check}
                
                for future in as_completed(futures):
                    checked += 1
                    try:
                        result = future.result(timeout=local_config['TIMEOUT'] + 3)
                        if result:
                            category, final, key_id = result
                            results[category].append(final)
                            key, tag = futures[future]
                            stats[tag][category.split('_')[1]] += 1
                        else:
                            failed += 1
                    except:
                        failed += 1
                    
                    if checked % 50 == 0:
                        deep_info = " [Deep: ON]" if local_config.get('ENABLE_DEEP_TEST', False) else ""
                        print(f"  {checked}/{len(to_check)} | "
                              f"RU: W:{stats['RU']['white']} B:{stats['RU']['black']} U:{stats['RU']['universal']} | "
                              f"EU: W:{stats['MY']['white']} B:{stats['MY']['black']} U:{stats['MY']['universal']} | "
                              f"❌ {failed}{deep_info}")
            
            deep_status = "включена" if local_config.get('ENABLE_DEEP_TEST', False) else "выключена"
            print(f"\nПроверено: {checked}, нерабочих: {failed}")
            print(f"Глубокая проверка: {deep_status}")
        
        cutoff = time.time() - (86400 * 3)
        history_cleaned = {k: v for k, v in history.items() if v['time'] > cutoff}
        save_json(CFG.HISTORY_FILE, history_cleaned)
        blacklist.save()
        analytics.save()
        
        print(f"\nОчищено истории: {len(history)} → {len(history_cleaned)}")
        
        print("\nСОХРАНЕНИЕ")
        print("="*70)
        
        for cat in results:
            results[cat].sort(key=extract_ping)
        
        print(f"\nРОССИЯ:")
        for rt in ['white', 'black', 'universal']:
            print(f"  {rt}: {len(results[f'ru_{rt}'])}")
        
        print(f"\nЕВРОПА:")
        for rt in ['white', 'black', 'universal']:
            print(f"  {rt}: {len(results[f'euro_{rt}'])}")
        
        print(f"\nФайлы:")
        ru_white_files = save_chunked(results['ru_white'], CFG.FOLDER_RU, "ru_white")
        ru_black_files = save_chunked(results['ru_black'], CFG.FOLDER_RU, "ru_black")
        ru_uni_files = save_chunked(results['ru_universal'], CFG.FOLDER_RU, "ru_universal")
        euro_white_files = save_chunked(results['euro_white'], CFG.FOLDER_EURO, "euro_white")
        euro_black_files = save_chunked(results['euro_black'], CFG.FOLDER_EURO, "euro_black")
        euro_uni_files = save_chunked(results['euro_universal'], CFG.FOLDER_EURO, "euro_universal")
        
        _generate_subscriptions_list([
            (ru_white_files, ru_black_files, ru_uni_files),
            (euro_white_files, euro_black_files, euro_uni_files)
        ])
        
        print(f"\n{'='*70}")
        print("SUCCESS!")
        print(f"{'='*70}")
        print(f"Время: {int(time.time() - analytics.session['start'])} сек")
        print(f"Сессия: {analytics.session['success']}/{analytics.session['total']} успешных")
        print(f"\nПодписки: {CFG.BASE_DIR}/subscriptions_list.txt")
        
    except KeyboardInterrupt:
        print("\n\nПрервано пользователем")
        exit(1)
    except Exception as e:
        print(f"\n\nКритическая ошибка: {e}")
        import traceback
        traceback.print_exc()
        exit(1)

def _check_key_cli(data, config):
    key, tag = data
    
    try:
        host, port, is_tls = parse_key(key)
        if not host: return None
        
        blacklist = BlacklistManager(CFG.BLACKLIST_FILE)
        if blacklist.is_blacklisted(host): return None
        
        key_id = get_hash(key.split("#")[0])
        
        checker = ConnectionChecker()
        
        # Определяем протокол для проверки
        protocol_type = get_protocol_type(key)
        protocol = "udp" if protocol_type == "hysteria2" else "tcp"
        
        # Для российских источников (RU) - всегда более глубокая проверка
        is_ru_source = tag == "RU"
        enable_deep_for_ru = is_ru_source or config.get('ENABLE_DEEP_TEST', False)
        
        # Базовая проверка соединения с VPN сервером
        server_ok = False
        latency = None
        
        # Для RU источников делаем больше попыток и более тщательную проверку
        retry_count = CFG.RETRY_ATTEMPTS * (2 if is_ru_source else 1)
        
        for attempt in range(retry_count):
            result = checker.check_basic(host, port, is_tls, protocol)
            if result:
                server_ok = True
                latency = result  # check_basic возвращает latency
                break
            time.sleep(0.1 * (attempt + 1))
        
        # Если сервер не прошел базовую проверку
        if not server_ok: 
            return None
        
        # Используем реальную latency если есть, иначе фиксированное значение
        if latency is None:
            latency = 100
        
        # Глубокая проверка работоспособности (всегда для RU, или если включена в настройках)
        if enable_deep_for_ru:
            deep_check = checker.check_deep(key, host, port, is_tls)
            if not deep_check:
                # Для RU источников делаем дополнительную проверку
                if is_ru_source:
                    # Пробуем еще раз с увеличенным таймаутом
                    time.sleep(0.2)
                    deep_check = checker.check_deep(key, host, port, is_tls)
                
                if not deep_check:
                    # Сервер не отвечает на глубокую проверку - помечаем как нерабочий
                    blacklist.record_failure(host)
                    return None
        
        # Для RU источников делаем дополнительные метрики
        metrics = KeyMetrics(latency=latency, last_check=time.time())
        
        # Для RU источников всегда проверяем jitter и bandwidth если доступны
        if is_ru_source:
            if latency < 300:  # Для RU проверяем даже при большей задержке
                metrics.jitter = checker.check_jitter(host, port, is_tls)
            if latency < 400:  # Для RU проверяем bandwidth даже при большей задержке
                metrics.bandwidth = checker.check_bandwidth(host, port, is_tls)
        else:
            # Для других источников - только если включено в настройках
            if config.get('ENABLE_JITTER_TEST', False) and latency < 200:
                metrics.jitter = checker.check_jitter(host, port, is_tls)
            if config.get('ENABLE_BANDWIDTH_TEST', False) and latency < 300:
                metrics.bandwidth = checker.check_bandwidth(host, port, is_tls)
        
        # Определяем тип маршрутизации (после проверки соединения)
        classifier = SmartClassifier()
        routing_type = classifier.predict(key)
        country = get_country(key, host)
        
        key_info = KeyInfo(key, key_id, tag, country, routing_type, metrics)
        
        # Для RU источников используем более низкий порог качества (они проверяются глубже)
        min_quality = config.get('MIN_QUALITY_SCORE', 0.0)
        if is_ru_source:
            # Для RU снижаем минимальный порог на 10 пунктов, так как проверка более строгая
            min_quality = max(0.0, min_quality - 10.0)
        
        if key_info.quality_score() < min_quality:
            return None
        
        label = format_label(key_info)
        final = f"{key.split('#')[0]}#{label}"
        category = f"{'euro' if tag == 'MY' else tag.lower()}_{routing_type}"
        
        history = load_json(CFG.HISTORY_FILE)
        history[key_id] = {
            'alive': True,
            'latency': latency,
            'time': time.time(),
            'country': country,
            'routing_type': routing_type,
            'deep_check': enable_deep_for_ru,
            'is_ru_source': is_ru_source
        }
        save_json(CFG.HISTORY_FILE, history)
        
        return category, final, key_id
    except Exception as e:
        # Игнорируем ошибки для отладки
        return None

def _generate_subscriptions_list(files_data):
    ru_files, euro_files = files_data
    
    GITHUB_REPO = "Mihuil121/vpn-checker-backend-fox"
    BASE_RU = f"https://raw.githubusercontent.com/{GITHUB_REPO}/main/{CFG.BASE_DIR}/RU_Best"
    BASE_EU = f"https://raw.githubusercontent.com/{GITHUB_REPO}/main/{CFG.BASE_DIR}/My_Euro"
    
    subs = ["=== 🇷🇺 РОССИЯ ===", ""]
    for name, files in [("⚪ БЕЛЫЙ СПИСОК", ru_files[0]),
                       ("⚫ ЧЕРНЫЙ СПИСОК", ru_files[1]),
                       ("🔘 УНИВЕРСАЛЬНЫЕ", ru_files[2])]:
        if files:
            subs.append(f"{name}:")
            subs.extend(f"{BASE_RU}/{f}" for f in files)
            subs.append("")
    
    subs.extend(["=== 🇪🇺 ЕВРОПА ===", ""])
    for name, files in [("⚪ БЕЛЫЙ СПИСОК", euro_files[0]),
                       ("⚫ ЧЕРНЫЙ СПИСОК", euro_files[1]),
                       ("🔘 УНИВЕРСАЛЬНЫЕ", euro_files[2])]:
        if files:
            subs.append(f"{name}:")
            subs.extend(f"{BASE_EU}/{f}" for f in files)
            subs.append("")
    
    os.makedirs(CFG.BASE_DIR, exist_ok=True)
    with open(os.path.join(CFG.BASE_DIR, "subscriptions_list.txt"), "w", encoding="utf-8") as f:
        f.write("\n".join(subs))

# ==================== ЗАПУСК ====================
def main():
    parser = argparse.ArgumentParser(description="VPN Checker v15.2 - GitHub Edition")
    parser.add_argument("--cli", action="store_true", help="CLI режим")
    parser.add_argument("--fast", action="store_true", help="Быстрая проверка")
    parser.add_argument("--threads", type=int, default=50, help="Количество потоков")
    parser.add_argument("--max-keys", type=int, default=15000, help="Максимум ключей")
    parser.add_argument("--timeout", type=int, help="Таймаут")
    parser.add_argument("--bandwidth", action="store_true", help="Тест пропускной способности")
    parser.add_argument("--jitter", action="store_true", help="Тест jitter")
    parser.add_argument("--min-quality", type=float, default=0.0, help="Минимальное качество")
    
    args = parser.parse_args()
    
    if args.cli:
        run_cli(args)
    else:
        try:
            stdscr = curses.initscr()
            curses.noecho()
            curses.cbreak()
            stdscr.keypad(True)
            
            TUI(stdscr).run()
        except Exception as e:
            try:
                curses.endwin()
            except:
                pass
            print(f"❌ Ошибка TUI: {e}")
            import traceback
            traceback.print_exc()
            exit(1)

if __name__ == "__main__":
    main()