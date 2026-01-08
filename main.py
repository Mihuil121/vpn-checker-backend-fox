#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
VPN Checker v15.1 - Consolidated Edition with TUI
Гибрид v13.0 и v14.0 с оптимальными улучшениями + TUI интерфейс
"""

import os
import re
import socket
import ssl
import time
import json
import requests
import base64
import shutil
import hashlib
import statistics
import argparse
import curses
import signal
from dataclasses import dataclass, asdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from collections import defaultdict
from typing import Optional, Dict, List, Tuple

# ==================== КОНФИГУРАЦИЯ ====================
@dataclass
class Config:
    """Централизованная конфигурация"""
    BASE_DIR: str = "checked"
    FOLDER_RU: str = "checked/RU_Best"
    FOLDER_EURO: str = "checked/My_Euro"
    
    # Производительность
    TIMEOUT: int = 5
    THREADS: int = 50
    CACHE_HOURS: int = 12
    CHUNK_LIMIT: int = 1000
    MAX_KEYS: int = 15000
    RETRY_ATTEMPTS: int = 2
    
    # Включить продвинутые проверки (замедляют работу!)
    ENABLE_BANDWIDTH_TEST: bool = False  # Требует ~3 сек на ключ
    ENABLE_JITTER_TEST: bool = False     # Требует ~0.5 сек на ключ
    
    # Пороги качества
    MIN_QUALITY_SCORE: float = 30.0
    MAX_JITTER_MS: int = 50
    MIN_BANDWIDTH_MBPS: float = 1.0
    
    # Файлы
    HISTORY_FILE: str = "checked/history.json"
    ANALYTICS_FILE: str = "checked/analytics.json"
    BLACKLIST_FILE: str = "checked/blacklist.json"
    
    MY_CHANNEL: str = "@vlesstrojan"

CFG = Config()

# Источники (вынесены отдельно для удобства)
URLS_RU = [
    "https://raw.githubusercontent.com/zieng2/wl/main/vless.txt ",
    "https://raw.githubusercontent.com/LowiKLive/BypassWhitelistRu/refs/heads/main/WhiteList-Bypass_Ru.txt ",
    "https://raw.githubusercontent.com/zieng2/wl/main/vless_universal.txt ",
    "https://raw.githubusercontent.com/vsevjik/OBSpiskov/refs/heads/main/wwh ",
    "https://etoneya.a9fm.site/1 ",
    "https://raw.githubusercontent.com/Kirillo4ka/vpn-configs-for-russia/refs/heads/main/Vless-Rus-Mobile-White-List.txt ",
    "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/refs/heads/main/Vless-Reality-White-Lists-Rus-Mobile.txt ",
    "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/refs/heads/main/Vless-Reality-White-Lists-Rus-Cable.txt ",
    "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/refs/heads/main/BLACK_SS%2BAll_RUS.txt ",
    "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/refs/heads/main/BLACK_VLESS_RUS.txt "
]

URLS_MY = [
    "https://raw.githubusercontent.com/kort0881/vpn-vless-configs-russia/refs/heads/main/githubmirror/new/all_new.txt ",
    "https://raw.githubusercontent.com/crackbest/V2ray-Config/refs/heads/main/config.txt ",
    "https://raw.githubusercontent.com/miladtahanian/multi-proxy-config-fetcher/refs/heads/main/configs/proxy_configs.txt ",
    "https://raw.githubusercontent.com/SoliSpirit/v2ray-configs/refs/heads/main/Countries/Latvia.txt "
]

# Коды стран и маркеры
EURO_CODES = {"NL", "DE", "FI", "GB", "FR", "SE", "PL", "CZ", "AT", "CH", "IT", "ES", "NO", "DK", "BE", "IE", "LU", "EE", "LV", "LT", "RO", "BG", "HR", "SI", "SK", "HU", "PT", "GR", "CY", "MT"}
BAD_MARKERS = ["CN", "IR", "KR", "BR", "IN", "RELAY", "POOL", "🇨🇳", "🇮🇷", "🇰🇷", "TR", "SA", "AE"]
WHITE_MARKERS = ["white", "whitelist", "bypass", "россия", "russia", "mobile", "cable", "госуслуг", "government", "banking", "bank", "RU", "МТС", "Beeline"]
BLACK_MARKERS = ["black", "blacklist", "full", "global", "universal", "all", "vpn", "proxy", "tunnel", "freedom"]

# ==================== УТИЛИТЫ ====================
def load_json(path: str) -> dict:
    if os.path.exists(path):
        try:
            with open(path, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception as e:
            print(f"⚠️ Ошибка чтения {path}: {e}")
    return {}

def save_json(path: str, data: dict):
    try:
        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
    except Exception as e:
        print(f"⚠️ Ошибка записи {path}: {e}")

def get_hash(key: str) -> str:
    return hashlib.sha256(key.encode()).hexdigest()[:16]

def extract_ping(key_str: str) -> Optional[int]:
    try:
        label = key_str.split("#")[-1]
        if "ms" not in label:
            return None
        # Формат: 123ms_RU_W_... или 123ms_...
        ping_part = label.split("ms")[0].split("_")[-1]
        return int(ping_part)
    except:
        return None

from urllib.parse import unquote

# ==================== КЛАССЫ ДАННЫХ ====================
@dataclass
class KeyMetrics:
    latency: int
    bandwidth: Optional[float] = None
    jitter: Optional[int] = None
    uptime: Optional[float] = None
    last_check: float = 0
    check_count: int = 0

@dataclass
class KeyInfo:
    key: str
    key_id: str
    tag: str
    country: str
    routing_type: str
    metrics: KeyMetrics
    
    def quality_score(self) -> float:
        score = 100.0
        
        # Latency (50%)
        if self.metrics.latency > 500: score -= 50
        elif self.metrics.latency > 300: score -= 35
        elif self.metrics.latency > 200: score -= 20
        elif self.metrics.latency > 100: score -= 10
        
        # Jitter (20%)
        if self.metrics.jitter and self.metrics.jitter > 50:
            score -= 20
        elif self.metrics.jitter and self.metrics.jitter > 30:
            score -= 10
        
        # Bandwidth (20%)
        if self.metrics.bandwidth:
            if self.metrics.bandwidth < 1: score -= 20
            elif self.metrics.bandwidth < 5: score -= 10
        
        # Uptime (10%)
        if self.metrics.uptime is not None:
            score -= (100 - self.metrics.uptime) * 0.1
        
        return max(0, score)
    
    def get_emoji(self) -> str:
        q = self.quality_score()
        if q >= 80: return "⭐"
        if q >= 60: return "✅"
        if q >= 40: return "⚡"
        return "⚠️"

# ==================== КЛАССИФИКАТОР ====================
class SmartClassifier:
    """Улучшенная классификация с правилами и весами"""
    
    def __init__(self):
        self.weights = {
            'reality': 10, 'ws': -3, 'grpc': 2, 'tls': 5, 'port_443': 3,
            'white_words': 5, 'black_words': -8, 'path_obfuscation': -3
        }
    
    def predict(self, key: str) -> str:
        key_lower = key.lower()
        score = 0
        
        # Проверка комментария (высший приоритет)
        if "#" in key:
            comment = key.split("#")[-1].lower()
            if any(m in comment for m in WHITE_MARKERS): return 'white'
            if any(m in comment for m in BLACK_MARKERS): return 'black'
        
        # Технические признаки
        features = {
            'reality': 'security=reality' in key_lower,
            'ws': 'type=ws' in key_lower,
            'grpc': 'grpc' in key_lower,
            'tls': 'security=tls' in key_lower,
            'port_443': ':443' in key,
            'white_words': any(w in key_lower for w in WHITE_MARKERS),
            'black_words': any(w in key_lower for w in BLACK_MARKERS),
            'path_obfuscation': self._is_obfuscated_path(key_lower)
        }
        
        for name, present in features.items():
            score += self.weights.get(name, 0) * (1 if present else 0)
        
        if score > 10: return 'white'
        if score < -5: return 'black'
        return 'universal'
    
    def _is_obfuscated_path(self, key: str) -> bool:
        if 'path=' not in key: return False
        path = re.search(r'path=([^&\s]+)', key)
        if not path: return False
        path_val = unquote(path.group(1)).lower()
        return len(path_val) > 25 or any(c in path_val for c in ['?', '&', '%', '='])

# ==================== BLACKLIST ====================
class BlacklistManager:
    def __init__(self, file_path: str):
        self.file_path = file_path
        data = load_json(file_path)
        self.hosts = set(data.get('hosts', []))
        self.reasons = data.get('reasons', {})
    
    def add(self, host: str, reason: str):
        self.hosts.add(host)
        self.reasons[host] = {'reason': reason, 'added': time.time()}
        self.save()
    
    def is_blacklisted(self, host: str) -> bool:
        return host in self.hosts
    
    def save(self):
        save_json(self.file_path, {'hosts': list(self.hosts), 'reasons': self.reasons})

# ==================== АНАЛИТИКА ====================
class Analytics:
    def __init__(self, file_path: str):
        self.file_path = file_path
        self.data = load_json(file_path)
        self.session = {'start': time.time(), 'total': 0, 'success': 0}
    
    def record(self, key_id: str, success: bool, latency: Optional[int] = None):
        if key_id not in self.data:
            self.data[key_id] = {'created': time.time(), 'checks': []}
        
        self.data[key_id]['checks'].append({
            'time': time.time(),
            'success': success,
            'latency': latency
        })
        
        # Храним только последние 50 проверок
        self.data[key_id]['checks'] = self.data[key_id]['checks'][-50:]
        self.session['total'] += 1
        if success: self.session['success'] += 1
    
    def get_uptime(self, key_id: str) -> Optional[float]:
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
    """Все проверки соединений в одном месте"""
    
    @staticmethod
    def check_basic(host: str, port: int, is_tls: bool) -> Optional[int]:
        """Базовая проверка latency"""
        try:
            start = time.time()
            if is_tls:
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                with socket.create_connection((host, port), timeout=CFG.TIMEOUT) as sock:
                    with ctx.wrap_socket(sock, server_hostname=host):
                        pass
            else:
                with socket.create_connection((host, port), timeout=CFG.TIMEOUT):
                    pass
            return int((time.time() - start) * 1000)
        except:
            return None
    
    @staticmethod
    def check_jitter(host: str, port: int) -> Optional[int]:
        """Измерить jitter"""
        if not CFG.ENABLE_JITTER_TEST: return None
        
        latencies = []
        for _ in range(5):
            try:
                start = time.time()
                with socket.create_connection((host, port), timeout=2):
                    latencies.append(int((time.time() - start) * 1000))
                time.sleep(0.05)
            except:
                continue
        
        if len(latencies) >= 3:
            try: return int(statistics.stdev(latencies))
            except: pass
        return None
    
    @staticmethod
    def check_bandwidth(host: str, port: int) -> Optional[float]:
        """Измерить пропускную способность (упрощенно)"""
        if not CFG.ENABLE_BANDWIDTH_TEST: return None
        
        try:
            start = time.time()
            total_bytes = 0
            with socket.create_connection((host, port), timeout=CFG.TIMEOUT) as sock:
                sock.settimeout(0.5)
                sock.sendall(b"GET / HTTP/1.1\r\nHost: test\r\n\r\n")
                end_time = start + 2  # 2 секунды теста
                
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

# ==================== ПАРСИНГ ====================
def parse_key(key: str) -> Tuple[Optional[str], Optional[int], bool]:
    try:
        if "@" not in key or ":" not in key: return None, None, False
        
        part = key.split("@")[1].split("?")[0].split("#")[0]
        host, port_str = part.rsplit(":", 1)
        port = int(port_str.strip())
        
        if port <= 0 or port > 65535: return None, None, False
        
        is_tls = any(x in key.lower() for x in ['security=tls', 'security=reality']) or \
                 key.startswith(("trojan://", "vmess://"))
        
        return host.strip(), port, is_tls
    except:
        return None, None, False

def get_country(key: str, host: str) -> str:
    """Определить страну по TLD и коду"""
    host_lower = host.lower()
    key_upper = key.upper()
    
    tld_map = {'.ru': 'RU', '.de': 'DE', '.nl': 'NL', '.fr': 'FR', '.uk': 'GB', '.lv': 'LV', '.eu': 'EU'}
    for tld, code in tld_map.items():
        if host_lower.endswith(tld): return code
    
    for code in EURO_CODES:
        if code in key_upper: return code
    
    return "UNKNOWN"

def is_garbage(key: str) -> bool:
    upper = key.upper()
    return any(m in upper for m in BAD_MARKERS) or \
           any(x in key for x in [".ir", ".cn", "127.0.0.1", "localhost", "0.0.0.0"])

# ==================== ЗАГРУЗКА КЛЮЧЕЙ ====================
def fetch_keys(urls: List[str], tag: str) -> List[Tuple[str, str]]:
    out = []
    print(f"\n📥 Загрузка {tag}... ({len(urls)} источников)")
    
    session = requests.Session()
    session.headers.update({"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"})
    
    for url in urls:
        url = url.strip()
        if not url: continue
        
        print(f"  ➜ {url[:60]}...")
        try:
            resp = session.get(url, timeout=15)
            if resp.status_code != 200: continue
            
            content = resp.text
            lines = []
            if "://" not in content[:100]:
                try:
                    decoded = base64.b64decode(content + "==").decode('utf-8', errors='ignore')
                    lines = decoded.splitlines()
                except:
                    lines = content.splitlines()
            else:
                lines = content.splitlines()
            
            loaded = 0
            for line in lines:
                line = line.strip()
                if not line or len(line) > 2000: continue
                if line.startswith(("vless://", "vmess://", "trojan://", "ss://")):
                    if not is_garbage(line):
                        out.append((line, tag))
                        loaded += 1
            
            if loaded: print(f"    ✅ {loaded}")
        except Exception as e:
            print(f"    ❌ {e}")
    
    print(f"📊 {tag}: {len(out)} ключей")
    return out

# ==================== ФОРМАТИРОВАНИЕ И СОХРАНЕНИЕ ====================
def format_label(key_info: KeyInfo) -> str:
    """Создать читаемую метку"""
    parts = [
        f"{key_info.metrics.latency}ms",
        key_info.country,
        key_info.routing_type[0].upper()
    ]
    
    if key_info.metrics.bandwidth:
        parts.append(f"{key_info.metrics.bandwidth:.1f}Mb")
    
    if key_info.metrics.jitter:
        parts.append(f"J{key_info.metrics.jitter}")
    
    if key_info.metrics.uptime and key_info.metrics.uptime < 100:
        parts.append(f"UP{int(key_info.metrics.uptime)}")
    
    parts.append(key_info.get_emoji())
    parts.append(CFG.MY_CHANNEL)
    
    return "_".join(parts)

def save_chunked(keys_list: List[str], folder: str, base_name: str) -> List[str]:
    """Сохранить файлы по частям"""
    created_files = []
    valid_keys = [k.strip() for k in keys_list if k and isinstance(k, str) and k.strip()]
    
    if not valid_keys:
        fname = f"{base_name}.txt"
        with open(os.path.join(folder, fname), "w", encoding="utf-8") as f:
            f.write("")
        return [fname]
    
    chunks = [valid_keys[i:i + CFG.CHUNK_LIMIT] for i in range(0, len(valid_keys), CFG.CHUNK_LIMIT)]
    
    for i, chunk in enumerate(chunks, 1):
        fname = f"{base_name}.txt" if len(chunks) == 1 else f"{base_name}_part{i}.txt"
        with open(os.path.join(folder, fname), "w", encoding="utf-8") as f:
            f.write("\n".join(chunk))
        created_files.append(fname)
        print(f"  📄 {fname}: {len(chunk)} ключей")
    
    return created_files

# ==================== TUI (TEXT USER INTERFACE) ====================
class TUI:
    """Текстовый интерфейс для управления VPN Checker"""
    
    def __init__(self, stdscr):
        self.stdscr = stdscr
        self.height, self.width = stdscr.getmaxyx()
        self.current_row = 0
        self.menu_items = [
            "🚀 Быстрая проверка",
            "🔍 Полная проверка (с метриками)",
            "⚙️  Настройки",
            "🗑️  Очистить кэш",
            "📊 Статистика",
            "❌ Выход"
        ]
        self.settings = {
            "threads": CFG.THREADS,
            "max_keys": CFG.MAX_KEYS,
            "timeout": CFG.TIMEOUT,
            "enable_bandwidth": CFG.ENABLE_BANDWIDTH_TEST,
            "enable_jitter": CFG.ENABLE_JITTER_TEST,
            "min_quality": CFG.MIN_QUALITY_SCORE
        }
        signal.signal(signal.SIGINT, self.signal_handler)
    
    def signal_handler(self, signum, frame):
        """Обработка Ctrl+C"""
        self.cleanup()
        exit(0)
    
    def cleanup(self):
        """Очистка curses"""
        try:
            curses.nocbreak()
            self.stdscr.keypad(False)
            curses.echo()
            curses.endwin()
        except:
            pass
    
    def draw_menu(self):
        """Отрисовка главного меню"""
        self.stdscr.clear()
        self.height, self.width = self.stdscr.getmaxyx()
        
        # Заголовок
        title = " VPN Checker v15.1 - TUI Mode "
        self.stdscr.attron(curses.A_BOLD | curses.A_REVERSE)
        self.stdscr.addstr(0, (self.width - len(title)) // 2, title)
        self.stdscr.attroff(curses.A_BOLD | curses.A_REVERSE)
        
        # Информация
        info_y = 2
        self.stdscr.addstr(info_y, 2, f"📂 Директория: {CFG.BASE_DIR}", curses.A_DIM)
        self.stdscr.addstr(info_y + 1, 2, f"🔧 Потоков: {self.settings['threads']} | 🔑 Макс. ключей: {self.settings['max_keys']}", curses.A_DIM)
        self.stdscr.addstr(info_y + 2, 2, f"⏱️  Таймаут: {self.settings['timeout']}с | 📶 Метрики: {'✅' if self.settings['enable_bandwidth'] else '❌'} Bw {'✅' if self.settings['enable_jitter'] else '❌'} Jitter", curses.A_DIM)
        
        # Меню
        menu_y = info_y + 4
        for idx, item in enumerate(self.menu_items):
            x = (self.width - len(item)) // 2
            y = menu_y + idx * 2
            
            if idx == self.current_row:
                self.stdscr.attron(curses.A_REVERSE)
                self.stdscr.addstr(y, x, item)
                self.stdscr.attroff(curses.A_REVERSE)
            else:
                self.stdscr.addstr(y, x, item)
        
        # Подсказки
        hint_y = self.height - 3
        hint = "Используйте ↑↓ для навигации, Enter для выбора, q для выхода"
        self.stdscr.addstr(hint_y, (self.width - len(hint)) // 2, hint, curses.A_DIM)
        
        self.stdscr.refresh()
    
    def draw_settings(self):
        """Отрисовка меню настроек"""
        self.stdscr.clear()
        
        title = " ⚙️  НАСТРОЙКИ "
        self.stdscr.attron(curses.A_BOLD | curses.A_REVERSE)
        self.stdscr.addstr(0, (self.width - len(title)) // 2, title)
        self.stdscr.attroff(curses.A_BOLD | curses.A_REVERSE)
        
        items = [
            f"1. Потоки: {self.settings['threads']}",
            f"2. Макс. ключей: {self.settings['max_keys']}",
            f"3. Таймаут: {self.settings['timeout']}с",
            f"4. Тест пропускной способности: {'Вкл' if self.settings['enable_bandwidth'] else 'Выкл'}",
            f"5. Тест jitter: {'Вкл' if self.settings['enable_jitter'] else 'Выкл'}",
            f"6. Мин. качество: {self.settings['min_quality']}",
            "7. Сохранить и вернуться",
            "8. Вернуться без сохранения"
        ]
        
        for idx, item in enumerate(items):
            x = 4
            y = 3 + idx * 2
            
            if idx == self.current_row:
                self.stdscr.attron(curses.A_REVERSE)
                self.stdscr.addstr(y, x, item)
                self.stdscr.attroff(curses.A_REVERSE)
            else:
                self.stdscr.addstr(y, x, item)
        
        hint = "Используйте ↑↓ для навигации, Enter для редактирования"
        self.stdscr.addstr(self.height - 2, (self.width - len(hint)) // 2, hint, curses.A_DIM)
        
        self.stdscr.refresh()
    
    def edit_setting(self, key: str):
        """Редактирование параметра"""
        self.stdscr.clear()
        self.stdscr.addstr(2, 2, f"Редактирование {key}")
        self.stdscr.addstr(4, 2, f"Текущее значение: {self.settings[key]}")
        self.stdscr.addstr(6, 2, "Введите новое значение: ")
        
        curses.echo()
        curses.curs_set(1)
        try:
            value = self.stdscr.getstr(6, 28, 20).decode('utf-8')
            if key in ['threads', 'max_keys', 'timeout']:
                self.settings[key] = int(value)
            elif key in ['enable_bandwidth', 'enable_jitter']:
                self.settings[key] = value.lower() in ['y', 'yes', 'true', '1', 'on']
            elif key == 'min_quality':
                self.settings[key] = float(value)
        except:
            pass
        curses.noecho()
        curses.curs_set(0)
    
    def show_statistics(self):
        """Показать статистику"""
        self.stdscr.clear()
        
        title = " 📊 СТАТИСТИКА "
        self.stdscr.attron(curses.A_BOLD | curses.A_REVERSE)
        self.stdscr.addstr(0, (self.width - len(title)) // 2, title)
        self.stdscr.attroff(curses.A_BOLD | curses.A_REVERSE)
        
        y = 3
        try:
            # Статистика файлов
            if os.path.exists(CFG.BASE_DIR):
                total_files = sum(len(files) for _, _, files in os.walk(CFG.BASE_DIR))
                total_size = sum(os.path.getsize(os.path.join(dp, f)) for dp, _, files in os.walk(CFG.BASE_DIR) for f in files)
                
                self.stdscr.addstr(y, 4, f"📁 Файлов: {total_files}")
                self.stdscr.addstr(y + 1, 4, f"📊 Размер: {total_size / 1024 / 1024:.2f} MB")
            
            # История
            history = load_json(CFG.HISTORY_FILE)
            self.stdscr.addstr(y + 3, 4, f"🕒 Записей в истории: {len(history)}")
            
            # Blacklist
            blacklist = load_json(CFG.BLACKLIST_FILE)
            self.stdscr.addstr(y + 4, 4, f"⛔ Blacklist: {len(blacklist.get('hosts', []))} хостов")
            
            # Аналитика
            analytics = load_json(CFG.ANALYTICS_FILE)
            total_checks = sum(len(v.get('checks', [])) for v in analytics.values())
            self.stdscr.addstr(y + 5, 4, f"🔍 Всего проверок: {total_checks}")
            
        except Exception as e:
            self.stdscr.addstr(y, 4, f"❌ Ошибка загрузки статистики: {e}")
        
        self.stdscr.addstr(self.height - 2, 2, "Нажмите любую клавишу для возврата...", curses.A_DIM)
        self.stdscr.refresh()
        self.stdscr.getch()
    
    def clear_cache(self):
        """Очистка кэша"""
        self.stdscr.clear()
        self.stdscr.addstr(2, 2, "🗑️  ОЧИСТКА КЭША")
        
        try:
            files_cleared = 0
            if os.path.exists(CFG.HISTORY_FILE):
                os.remove(CFG.HISTORY_FILE)
                files_cleared += 1
            if os.path.exists(CFG.ANALYTICS_FILE):
                os.remove(CFG.ANALYTICS_FILE)
                files_cleared += 1
            if os.path.exists(CFG.BLACKLIST_FILE):
                os.remove(CFG.BLACKLIST_FILE)
                files_cleared += 1
            
            self.stdscr.addstr(4, 4, f"✅ Очищено файлов: {files_cleared}")
        except Exception as e:
            self.stdscr.addstr(4, 4, f"❌ Ошибка: {e}")
        
        self.stdscr.addstr(6, 2, "Нажмите любую клавишу...")
        self.stdscr.refresh()
        self.stdscr.getch()
    
    def draw_progress(self, progress: float, status: str):
        """Индикатор прогресса"""
        self.stdscr.clear()
        
        title = " ПРОВЕРКА В ПРОЦЕССЕ "
        self.stdscr.attron(curses.A_BOLD | curses.A_REVERSE)
        self.stdscr.addstr(0, (self.width - len(title)) // 2, title)
        self.stdscr.attroff(curses.A_BOLD | curses.A_REVERSE)
        
        # Прогресс-бар
        bar_width = self.width - 20
        bar_x = (self.width - bar_width) // 2
        bar_y = self.height // 2 - 2
        
        filled = int(bar_width * progress)
        bar = "█" * filled + "░" * (bar_width - filled)
        
        self.stdscr.addstr(bar_y, bar_x, f"[{bar}]")
        self.stdscr.addstr(bar_y + 1, bar_x + bar_width // 2 - 5, f"{progress * 100:.1f}%")
        
        # Статус
        self.stdscr.addstr(bar_y + 3, (self.width - len(status)) // 2, status)
        
        # Подсказка
        hint = "Нажмите Ctrl+C для отмены"
        self.stdscr.addstr(self.height - 2, (self.width - len(hint)) // 2, hint, curses.A_DIM)
        
        self.stdscr.refresh()
    
    def run_check(self, fast: bool = False):
        """Запуск проверки с индикатором прогресса"""
        try:
            # Подготовка
            for folder in [CFG.FOLDER_RU, CFG.FOLDER_EURO]:
                if os.path.exists(folder): shutil.rmtree(folder)
                os.makedirs(folder, exist_ok=True)
            
            # Загрузка источников
            self.draw_progress(0.1, "Загрузка источников...")
            tasks_ru = fetch_keys(URLS_RU, "RU")
            tasks_my = fetch_keys(URLS_MY, "MY")
            
            # Дедупликация
            unique = {get_hash(k.split("#")[0]): (k, t) for k, t in tasks_ru + tasks_my}
            all_items = list(unique.values())
            if len(all_items) > CFG.MAX_KEYS:
                all_items = all_items[:CFG.MAX_KEYS]
            
            # Кэш
            self.draw_progress(0.2, "Проверка кэша...")
            current_time = time.time()
            to_check = []
            cache_hits = 0
            results = {
                'ru_white': [], 'ru_black': [], 'ru_universal': [],
                'euro_white': [], 'euro_black': [], 'euro_universal': []
            }
            
            history = load_json(CFG.HISTORY_FILE)
            for key, tag in all_items:
                key_id = get_hash(key.split("#")[0])
                cached = history.get(key_id)
                
                if cached and (current_time - cached['time'] < CFG.CACHE_HOURS * 3600) and cached.get('alive'):
                    restoration_progress = 0.2 + (0.3 * cache_hits / len(all_items))
                    self.draw_progress(min(restoration_progress, 0.5), f"Восстановление из кэша: {cache_hits}/{len(all_items)}")
                    
                    metrics = KeyMetrics(latency=cached['latency'], last_check=cached['time'])
                    routing_type = cached.get('routing_type', 'universal')
                    country = cached.get('country', 'UNKNOWN')
                    key_info = KeyInfo(key, key_id, tag, country, routing_type, metrics)
                    label = format_label(key_info)
                    final = f"{key.split('#')[0]}#{label}"
                    
                    category_prefix = 'euro' if tag == 'MY' else tag.lower()
                    category = f"{category_prefix}_{routing_type}"
                    
                    if not (tag == "MY" and country == "RU"):
                        results[category].append(final)
                        cache_hits += 1
                else:
                    to_check.append((key, tag))
            
            # Проверка новых ключей
            if to_check:
                classifier = SmartClassifier()
                checker = ConnectionChecker()
                analytics = Analytics(CFG.ANALYTICS_FILE)
                blacklist = BlacklistManager(CFG.BLACKLIST_FILE)
                
                checked = 0
                with ThreadPoolExecutor(max_workers=CFG.THREADS) as executor:
                    futures = {executor.submit(check_single_key, item, classifier, checker, analytics, blacklist): item 
                              for item in to_check}
                    
                    for future in as_completed(futures):
                        checked += 1
                        progress = 0.5 + (checked / len(to_check)) * 0.5
                        self.draw_progress(progress, f"Проверка: {checked}/{len(to_check)}")
                        
                        try:
                            future.result(timeout=CFG.TIMEOUT + 3)
                        except:
                            pass
            
            # Сохранение
            self.draw_progress(0.95, "Сохранение результатов...")
            time.sleep(0.5)
            
            for cat in results:
                results[cat].sort(key=extract_ping)
            
            save_chunked(results['ru_white'], CFG.FOLDER_RU, "ru_white")
            save_chunked(results['ru_black'], CFG.FOLDER_RU, "ru_black")
            save_chunked(results['ru_universal'], CFG.FOLDER_RU, "ru_universal")
            save_chunked(results['euro_white'], CFG.FOLDER_EURO, "euro_white")
            save_chunked(results['euro_black'], CFG.FOLDER_EURO, "euro_black")
            save_chunked(results['euro_universal'], CFG.FOLDER_EURO, "euro_universal")
            
            # Подписки
            GITHUB_REPO = "Mihuil121/vpn-checker-backend-fox"
            BASE_RU = f"https://raw.githubusercontent.com/ {GITHUB_REPO}/main/{CFG.BASE_DIR}/RU_Best"
            BASE_EU = f"https://raw.githubusercontent.com/ {GITHUB_REPO}/main/{CFG.BASE_DIR}/My_Euro"
            
            subs = ["=== 🇷🇺 РОССИЯ ===", ""]
            for name, files in [("⚪ БЕЛЫЙ СПИСОК", results['ru_white']), 
                               ("⚫ ЧЕРНЫЙ СПИСОК", results['ru_black']), 
                               ("🔘 УНИВЕРСАЛЬНЫЕ", results['ru_universal'])]:
                if files:
                    subs.append(f"{name}:")
                    # Генерация файлов уже сделана, добавляем ссылки
                    base_name = "ru_" + name.split()[1].lower()
                    subs.extend(f"{BASE_RU}/{base_name}.txt")
                    subs.append("")
            
            subs.extend(["=== 🇪🇺 ЕВРОПА ===", ""])
            for name, files in [("⚪ БЕЛЫЙ СПИСОК", results['euro_white']),
                                ("⚫ ЧЕРНЫЙ СПИСОК", results['euro_black']),
                                ("🔘 УНИВЕРСАЛЬНЫЕ", results['euro_universal'])]:
                if files:
                    subs.append(f"{name}:")
                    base_name = "euro_" + name.split()[1].lower()
                    subs.extend(f"{BASE_EU}/{base_name}.txt")
                    subs.append("")
            
            os.makedirs(CFG.BASE_DIR, exist_ok=True)
            with open(os.path.join(CFG.BASE_DIR, "subscriptions_list.txt"), "w", encoding="utf-8") as f:
                f.write("\n".join(subs))
            
            self.draw_progress(1.0, "✅ Завершено!")
            time.sleep(1)
            
        except KeyboardInterrupt:
            raise
        except Exception as e:
            self.draw_progress(1.0, f"❌ Ошибка: {str(e)}")
            time.sleep(2)
            raise
    
    def run(self):
        """Главный цикл TUI"""
        # ИСПРАВЛЕНИЕ: Правильная инициализация цветов
        curses.curs_set(0)  # Скрыть курсор
        
        # Инициализация цветов
        if curses.has_colors():
            curses.start_color()  # <-- СНАЧАЛА это
            curses.use_default_colors()  # <-- ПОТОМ это
            curses.init_pair(1, curses.COLOR_CYAN, -1)
            curses.init_pair(2, curses.COLOR_GREEN, -1)
            curses.init_pair(3, curses.COLOR_YELLOW, -1)
            curses.init_pair(4, curses.COLOR_RED, -1)
        else:
            # Если цвета не поддерживаются
            try:
                curses.use_default_colors()
            except:
                pass
        
        while True:
            self.draw_menu()
            key = self.stdscr.getch()
            
            if key == curses.KEY_UP:
                self.current_row = max(0, self.current_row - 1)
            elif key == curses.KEY_DOWN:
                self.current_row = min(len(self.menu_items) - 1, self.current_row + 1)
            elif key == ord('\n') or key == curses.KEY_ENTER:
                # Запуск действия
                if self.current_row == 0:  # Быстрая проверка
                    CFG.ENABLE_BANDWIDTH_TEST = False
                    CFG.ENABLE_JITTER_TEST = False
                    CFG.THREADS = self.settings['threads']
                    CFG.MAX_KEYS = self.settings['max_keys']
                    CFG.TIMEOUT = self.settings['timeout']
                    self.run_check(fast=True)
                    self.stdscr.getch()
                elif self.current_row == 1:  # Полная проверка
                    CFG.ENABLE_BANDWIDTH_TEST = self.settings['enable_bandwidth']
                    CFG.ENABLE_JITTER_TEST = self.settings['enable_jitter']
                    CFG.THREADS = self.settings['threads']
                    CFG.MAX_KEYS = self.settings['max_keys']
                    CFG.TIMEOUT = self.settings['timeout']
                    CFG.MIN_QUALITY_SCORE = self.settings['min_quality']
                    self.run_check()
                    self.stdscr.getch()
                elif self.current_row == 2:  # Настройки
                    self.current_row = 0
                    self.show_settings()
                elif self.current_row == 3:  # Очистить кэш
                    self.clear_cache()
                elif self.current_row == 4:  # Статистика
                    self.show_statistics()
                elif self.current_row == 5:  # Выход
                    break
            elif key == ord('q'):
                break

# ==================== ОСНОВНАЯ ЛОГИКА ====================
def check_single_key(data: Tuple[str, str], 
                    classifier: SmartClassifier,
                    checker: ConnectionChecker,
                    analytics: Analytics,
                    blacklist: BlacklistManager) -> Optional[KeyInfo]:
    """Проверить один ключ"""
    key, tag = data
    
    # Парсинг
    host, port, is_tls = parse_key(key)
    if not host: return None
    
    # Blacklist
    if blacklist.is_blacklisted(host): return None
    
    key_id = get_hash(key.split("#")[0])
    
    # Базовая проверка с retry
    latency = None
    for _ in range(CFG.RETRY_ATTEMPTS):
        latency = checker.check_basic(host, port, is_tls)
        if latency: break
        time.sleep(0.1)
    
    if not latency:
        analytics.record(key_id, False)
        # Авто-blacklist при 5+ ошибках
        checks = analytics.data.get(key_id, {}).get('checks', [])
        if len(checks) >= 5 and sum(1 for c in checks[-5:] if not c['success']) >= 5:
            blacklist.add(host, "Auto: 5 failures")
        return None
    
    # Продвинутые метрики (по возможности)
    metrics = KeyMetrics(
        latency=latency,
        last_check=time.time()
    )
    
    if CFG.ENABLE_JITTER_TEST and latency < 200:
        metrics.jitter = checker.check_jitter(host, port)
    
    if CFG.ENABLE_BANDWIDTH_TEST and latency < 300:
        metrics.bandwidth = checker.check_bandwidth(host, port)
    
    # Uptime
    metrics.uptime = analytics.get_uptime(key_id)
    
    # Классификация
    routing_type = classifier.predict(key)
    country = get_country(key, host)
    
    # Создать KeyInfo
    key_info = KeyInfo(
        key=key,
        key_id=key_id,
        tag=tag,
        country=country,
        routing_type=routing_type,
        metrics=metrics
    )
    
    # Фильтр по качеству
    if key_info.quality_score() < CFG.MIN_QUALITY_SCORE:
        blacklist.add(host, f"Low quality: {key_info.quality_score():.1f}")
        analytics.record(key_id, False)
        return None
    
    analytics.record(key_id, True, latency)
    return key_info

def run_cli(args):
    """Запуск из командной строки"""
    try:
        main_logic(args)
    except KeyboardInterrupt:
        print("\n\n❌ Прервано пользователем")
        exit(1)
    except Exception as e:
        print(f"\n\n❌ Критическая ошибка: {e}")
        import traceback
        traceback.print_exc()
        exit(1)

def main_logic(args):
    """Основная логика без TUI"""
    if args.fast:
        CFG.ENABLE_BANDWIDTH_TEST = False
        CFG.ENABLE_JITTER_TEST = False
        print("⚡ Быстрый режим: продвинутые проверки отключены")
    
    CFG.THREADS = args.threads
    CFG.MAX_KEYS = args.max_keys
    
    # Заголовок
    print(f"\n{'='*70}")
    print(f"VPN Checker v15.0 | {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"Threads: {CFG.THREADS} | Timeout: {CFG.TIMEOUT}s | Max keys: {CFG.MAX_KEYS}")
    if CFG.ENABLE_BANDWIDTH_TEST or CFG.ENABLE_JITTER_TEST:
        print(f"Advanced checks: bandwidth={CFG.ENABLE_BANDWIDTH_TEST}, jitter={CFG.ENABLE_JITTER_TEST}")
    print(f"{'='*70}\n")
    
    # Очистка
    for folder in [CFG.FOLDER_RU, CFG.FOLDER_EURO]:
        if os.path.exists(folder): shutil.rmtree(folder)
        os.makedirs(folder, exist_ok=True)
    
    # Инициализация компонентов
    classifier = SmartClassifier()
    checker = ConnectionChecker()
    analytics = Analytics(CFG.ANALYTICS_FILE)
    blacklist = BlacklistManager(CFG.BLACKLIST_FILE)
    
    # История
    history = load_json(CFG.HISTORY_FILE)
    print(f"📂 История: {len(history)} записей")
    
    # Загрузка
    print(f"\n{'='*70}")
    print("ЗАГРУЗКА ИСТОЧНИКОВ")
    print(f"{'='*70}")
    tasks_ru = fetch_keys(URLS_RU, "RU")
    tasks_my = fetch_keys(URLS_MY, "MY")
    
    # Удаление дубликатов
    unique = {get_hash(k.split("#")[0]): (k, t) for k, t in tasks_ru + tasks_my}
    all_items = list(unique.values())
    print(f"\n📊 Уникальных ключей: {len(all_items)}")
    
    if len(all_items) > CFG.MAX_KEYS:
        all_items = all_items[:CFG.MAX_KEYS]
        print(f"⚠️  Ограничено до {CFG.MAX_KEYS}")
    
    # Кэш
    current_time = time.time()
    to_check = []
    results = {
        'ru_white': [], 'ru_black': [], 'ru_universal': [],
        'euro_white': [], 'euro_black': [], 'euro_universal': []
    }
    cache_hits = 0
    
    print(f"\n{'='*70}")
    print("ПРОВЕРКА КЭША")
    print(f"{'='*70}")
    
    for key, tag in all_items:
        key_id = get_hash(key.split("#")[0])
        cached = history.get(key_id)
        
        if cached and (current_time - cached['time'] < CFG.CACHE_HOURS * 3600) and cached.get('alive'):
            # Восстановить из кэша
            metrics = KeyMetrics(
                latency=cached['latency'],
                last_check=cached['time']
            )
            routing_type = cached.get('routing_type', 'universal')
            country = cached.get('country', 'UNKNOWN')
            
            key_info = KeyInfo(key, key_id, tag, country, routing_type, metrics)
            label = format_label(key_info)
            final = f"{key.split('#')[0]}#{label}"
            
            # ИСПРАВЛЕНИЕ: Используем 'euro' для тега 'MY'
            category_prefix = 'euro' if tag == 'MY' else tag.lower()
            category = f"{category_prefix}_{routing_type}"
            
            if tag == "MY" and country == "RU":
                pass  # Пропускаем RU из MY
            else:
                results[category].append(final)
                cache_hits += 1
        else:
            to_check.append((key, tag))
    
    print(f"✅ Из кэша: {cache_hits} | 🔍 Для проверки: {len(to_check)}")
    
    # Проверка новых
    if to_check:
        print(f"\n{'='*70}")
        print("ПРОВЕРКА В РЕАЛЬНОМ ВРЕМЕНИ")
        print(f"{'='*70}")
        
        checked = 0
        failed = 0
        stats = defaultdict(lambda: defaultdict(int))
        
        with ThreadPoolExecutor(max_workers=CFG.THREADS) as executor:
            futures = {executor.submit(check_single_key,
                                      item, classifier, checker, analytics, blacklist): item 
                      for item in to_check}
            
            for future in as_completed(futures):
                key, tag = futures[future]
                checked += 1
                
                try:
                    key_info = future.result(timeout=CFG.TIMEOUT + 3)
                    if not key_info:
                        failed += 1
                        continue
                    
                    # Сохранить в историю
                    history[key_info.key_id] = {
                        'alive': True,
                        'latency': key_info.metrics.latency,
                        'time': current_time,
                        'country': key_info.country,
                        'routing_type': key_info.routing_type
                    }
                    
                    # Форматировать
                    label = format_label(key_info)
                    final = f"{key_info.key.split('#')[0]}#{label}"
                    
                    # ИСПРАВЛЕНИЕ: Используем 'euro' для тега 'MY'
                    category_prefix = 'euro' if tag == 'MY' else tag.lower()
                    category = f"{category_prefix}_{key_info.routing_type}"
                    
                    if tag == "MY" and key_info.country == "RU":
                        pass
                    else:
                        results[category].append(final)
                        stats[tag][key_info.routing_type] += 1
                    
                except Exception:
                    failed += 1
                
                if checked % 50 == 0:
                    print(f"  📊 {checked}/{len(to_check)} | "
                          f"RU: W:{stats['RU']['white']} B:{stats['RU']['black']} U:{stats['RU']['universal']} | "
                          f"EU: W:{stats['MY']['white']} B:{stats['MY']['black']} U:{stats['MY']['universal']} | "
                          f"❌ {failed}")
        
        print(f"\n✅ Итого проверено: {checked}, нерабочих: {failed}")
    
    # Очистить старую историю
    history_cleaned = {k: v for k, v in history.items() if current_time - v['time'] < 86400 * 3}
    save_json(CFG.HISTORY_FILE, history_cleaned)
    blacklist.save()
    analytics.save()
    
    print(f"🧹 Очищено истории: {len(history)} → {len(history_cleaned)}")
    
    # Сортировка и сохранение
    print(f"\n{'='*70}")
    print("СОРТИРОВКА И СОХРАНЕНИЕ")
    print(f"{'='*70}")
    
    for cat in results:
        results[cat].sort(key=extract_ping)
    
    print(f"\n🇷🇺 РОССИЯ:")
    print(f"  ⚪ Белый список: {len(results['ru_white'])}")
    print(f"  ⚫ Черный список: {len(results['ru_black'])}")
    print(f"  🔘 Универсальные: {len(results['ru_universal'])}")
    
    print(f"\n🇪🇺 ЕВРОПА:")
    print(f"  ⚪ Белый список: {len(results['euro_white'])}")
    print(f"  ⚫ Черный список: {len(results['euro_black'])}")
    print(f"  🔘 Универсальные: {len(results['euro_universal'])}")
    
    # Сохранение
    print(f"\n📁 Сохранение файлов:")
    ru_white_files = save_chunked(results['ru_white'], CFG.FOLDER_RU, "ru_white")
    ru_black_files = save_chunked(results['ru_black'], CFG.FOLDER_RU, "ru_black")
    ru_uni_files = save_chunked(results['ru_universal'], CFG.FOLDER_RU, "ru_universal")
    euro_white_files = save_chunked(results['euro_white'], CFG.FOLDER_EURO, "euro_white")
    euro_black_files = save_chunked(results['euro_black'], CFG.FOLDER_EURO, "euro_black")
    euro_uni_files = save_chunked(results['euro_universal'], CFG.FOLDER_EURO, "euro_universal")
    
    # Подписки
    GITHUB_REPO = "Mihuil121/vpn-checker-backend-fox"
    BASE_RU = f"https://raw.githubusercontent.com/ {GITHUB_REPO}/main/{CFG.BASE_DIR}/RU_Best"
    BASE_EU = f"https://raw.githubusercontent.com/ {GITHUB_REPO}/main/{CFG.BASE_DIR}/My_Euro"
    
    subs = ["=== 🇷🇺 РОССИЯ ===", ""]
    
    for name, files in [("⚪ БЕЛЫЙ СПИСОК", ru_white_files), 
                        ("⚫ ЧЕРНЫЙ СПИСОК", ru_black_files), 
                        ("🔘 УНИВЕРСАЛЬНЫЕ", ru_uni_files)]:
        if files:
            subs.append(f"{name}:")
            subs.extend(f"{BASE_RU}/{f}" for f in files)
            subs.append("")
    
    subs.extend(["=== 🇪🇺 ЕВРОПА ===", ""])
    
    for name, files in [("⚪ БЕЛЫЙ СПИСОК", euro_white_files),
                        ("⚫ ЧЕРНЫЙ СПИСОК", euro_black_files),
                        ("🔘 УНИВЕРСАЛЬНЫЕ", euro_uni_files)]:
        if files:
            subs.append(f"{name}:")
            subs.extend(f"{BASE_EU}/{f}" for f in files)
            subs.append("")
    
    os.makedirs(CFG.BASE_DIR, exist_ok=True)
    with open(os.path.join(CFG.BASE_DIR, "subscriptions_list.txt"), "w", encoding="utf-8") as f:
        f.write("\n".join(subs))
    
    # Итог
    print(f"\n{'='*70}")
    print("✅ SUCCESS!")
    print(f"{'='*70}")
    print(f"🕒 Завершено: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"⏱️  Время: {int(time.time() - analytics.session['start'])} сек")
    print(f"📊 Сессия: {analytics.session['success']}/{analytics.session['total']} успешных")
    print("\n💡 Типы списков:")
    print("  ⚪ Белый - трафик идёт напрямую в РФ, VPN только для блокировок")
    print("  ⚫ Черный - весь трафик через VPN")
    print("  🔘 Универсальный - неопределён, проверьте вручную")
    print(f"\n📋 Подписки сохранены в: {CFG.BASE_DIR}/subscriptions_list.txt")

# ==================== ЗАПУСК ====================
if __name__ == "__main__":
    # Проверяем, есть ли аргументы командной строки
    parser = argparse.ArgumentParser(description="VPN Checker v15.1")
    parser.add_argument("--fast", action="store_true", help="Только быстрая проверка (без метрик)")
    parser.add_argument("--threads", type=int, default=50, help="Количество потоков")
    parser.add_argument("--max-keys", type=int, default=15000, help="Максимум ключей")
    parser.add_argument("--cli", action="store_true", help="Запустить в CLI режиме (без TUI)")
    args = parser.parse_args()
    
    if args.cli or len(os.sys.argv) > 1:
        # Запуск в CLI режиме
        run_cli(args)
    else:
        # Запуск TUI
        try:
            stdscr = curses.initscr()
            curses.noecho()  # Не показывать ввод клавиш
            curses.cbreak()  # Не требовать Enter для ввода
            stdscr.keypad(True)  # Обрабатывать специальные клавиши
            
            tui = TUI(stdscr)
            tui.run()
            
            tui.cleanup()
        except Exception as e:
            # Важно: всегда восстанавливать терминал
            try:
                curses.endwin()
            except:
                pass
            print(f"❌ Ошибка TUI: {e}")
            import traceback
            traceback.print_exc()
            exit(1)