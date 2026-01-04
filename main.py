#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
VPN Checker v13.0 - Smart Routing Edition
Ключевые улучшения:
- Автоматическое определение белых/черных списков
- Анализ конфигурации (routing rules, outbound domains)
- Умная классификация по параметрам
- Разделение на white/black/universal файлы
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
from urllib.parse import unquote, parse_qs, urlparse
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timedelta
from collections import defaultdict

# ------------------ Настройки ------------------
BASE_DIR = "checked"
FOLDER_RU = os.path.join(BASE_DIR, "RU_Best")
FOLDER_EURO = os.path.join(BASE_DIR, "My_Euro")

# Константы
TIMEOUT = 5
THREADS = 50
CACHE_HOURS = 12
CHUNK_LIMIT = 1000
MAX_KEYS_TO_CHECK = 15000
HISTORY_FILE = os.path.join(BASE_DIR, "history.json")
MY_CHANNEL = "@vlesstrojan"
RETRY_ATTEMPTS = 2

# Источники
URLS_RU = [
    "https://raw.githubusercontent.com/zieng2/wl/main/vless.txt",
    "https://raw.githubusercontent.com/LowiKLive/BypassWhitelistRu/refs/heads/main/WhiteList-Bypass_Ru.txt",
    "https://raw.githubusercontent.com/zieng2/wl/main/vless_universal.txt",
    "https://raw.githubusercontent.com/vsevjik/OBSpiskov/refs/heads/main/wwh",
    "https://etoneya.a9fm.site/1",
    "https://raw.githubusercontent.com/Kirillo4ka/vpn-configs-for-russia/refs/heads/main/Vless-Rus-Mobile-White-List.txt",
    "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/refs/heads/main/Vless-Reality-White-Lists-Rus-Mobile.txt",
    "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/refs/heads/main/Vless-Reality-White-Lists-Rus-Cable.txt",
    "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/refs/heads/main/BLACK_SS%2BAll_RUS.txt",
    "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/refs/heads/main/BLACK_VLESS_RUS.txt"
]

URLS_MY = [
    "https://raw.githubusercontent.com/kort0881/vpn-vless-configs-russia/refs/heads/main/githubmirror/new/all_new.txt",
    "https://raw.githubusercontent.com/crackbest/V2ray-Config/refs/heads/main/config.txt",
    "https://raw.githubusercontent.com/miladtahanian/multi-proxy-config-fetcher/refs/heads/main/configs/proxy_configs.txt",
    "https://raw.githubusercontent.com/SoliSpirit/v2ray-configs/refs/heads/main/Countries/Latvia.txt"
]

EURO_CODES = {
    "NL", "DE", "FI", "GB", "FR", "SE", "PL", "CZ", "AT", "CH", 
    "IT", "ES", "NO", "DK", "BE", "IE", "LU", "EE", "LV", "LT", 
    "RO", "BG", "HR", "SI", "SK", "HU", "PT", "GR", "CY", "MT"
}

BAD_MARKERS = ["CN", "IR", "KR", "BR", "IN", "RELAY", "POOL", "🇨🇳", "🇮🇷", "🇰🇷", "TR", "SA", "AE"]

# Маркеры для белых списков
WHITE_MARKERS = [
    "white", "whitelist", "bypass", "россия", "russia", "mobile", "cable",
    "госуслуг", "government", "banking", "bank", "RU", "МТС", "Beeline",
    "Megafon", "Tele2", "Rostelecom"
]

# Маркеры для черных списков
BLACK_MARKERS = [
    "black", "blacklist", "full", "global", "universal", "all", "vpn",
    "proxy", "tunnel", "freedom"
]

# ------------------ Классификация ключей ------------------
def detect_routing_type(key_str):
    """
    Определяет тип роутинга ключа
    Возвращает: 'white', 'black', или 'universal'
    """
    key_lower = key_str.lower()
    key_upper = key_str.upper()
    
    # 1. Проверка по имени/комментарию ключа
    if "#" in key_str:
        comment = key_str.split("#")[-1].lower()
        
        # Явные маркеры белого списка
        if any(marker in comment for marker in WHITE_MARKERS):
            return 'white'
        
        # Явные маркеры черного списка
        if any(marker in comment for marker in BLACK_MARKERS):
            return 'black'
    
    # 2. Анализ параметров конфигурации
    try:
        # Извлечение параметров из URL
        if "?" in key_str:
            params_part = key_str.split("?")[1].split("#")[0]
            params = {}
            for pair in params_part.split("&"):
                if "=" in pair:
                    k, v = pair.split("=", 1)
                    params[k.lower()] = unquote(v).lower()
            
            # Проверка routing правил
            if 'routing' in params or 'rule' in params:
                routing_value = params.get('routing', '') + params.get('rule', '')
                if any(w in routing_value for w in ['bypass', 'direct', 'domestic', 'local']):
                    return 'white'
            
            # Проверка режима сети
            mode = params.get('mode', params.get('network', ''))
            if 'split' in mode or 'bypass' in mode:
                return 'white'
            
            # Проверка outbound правил
            if 'outbound' in params:
                outbound = params['outbound']
                if any(w in outbound for w in ['direct', 'bypass', 'local']):
                    return 'white'
    
    except Exception:
        pass
    
    # 3. Анализ технических параметров
    # Reality часто используется для белых списков в России
    if 'security=reality' in key_lower:
        if 'ru' in key_lower or any(m in key_upper for m in ['RU', 'RUS', 'RUSSIA']):
            return 'white'
    
    # WebSocket с path часто для обхода блокировок (черный список)
    if 'type=ws' in key_lower or 'net=ws' in key_lower:
        if 'path=' in key_lower:
            path = re.search(r'path=([^&\s]+)', key_str)
            if path:
                path_value = unquote(path.group(1)).lower()
                # Обфусцированные пути обычно для полного VPN
                if len(path_value) > 20 or any(c in path_value for c in ['?', '&', '%']):
                    return 'black'
    
    # 4. По умолчанию - универсальный
    return 'universal'

def classify_key_advanced(key_str, source_tag):
    """
    Расширенная классификация с учетом источника
    """
    routing_type = detect_routing_type(key_str)
    
    # Переопределение на основе source_tag
    if source_tag == "RU":
        # Если явно черный список, оставляем
        if routing_type == 'black':
            return 'black'
        # Иначе по умолчанию белый для RU источников
        return 'white'
    
    return routing_type

# ------------------ Утилиты ------------------
def load_json(path):
    if os.path.exists(path):
        try:
            with open(path, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception as e:
            print(f"⚠️ Ошибка чтения {path}: {e}")
    return {}

def save_json(path, data):
    try:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
    except Exception as e:
        print(f"⚠️ Ошибка записи {path}: {e}")

# Предкомпилированные regex
RE_TLD_RU = re.compile(r'\.ru$', re.IGNORECASE)
RE_TLD_DE = re.compile(r'\.de$', re.IGNORECASE)
RE_TLD_NL = re.compile(r'\.nl$', re.IGNORECASE)
RE_TLD_UK = re.compile(r'\.(uk|co\.uk)$', re.IGNORECASE)
RE_TLD_FR = re.compile(r'\.fr$', re.IGNORECASE)
RE_TLD_LV = re.compile(r'\.lv$', re.IGNORECASE)
RE_TLD_EU = re.compile(r'\.eu$', re.IGNORECASE)

def get_country_fast(host, key_name):
    """Оптимизированное определение страны"""
    host_lower = host.lower()
    name_upper = key_name.upper()
    
    if RE_TLD_RU.search(host_lower): return "RU"
    if RE_TLD_DE.search(host_lower): return "DE"
    if RE_TLD_NL.search(host_lower): return "NL"
    if RE_TLD_UK.search(host_lower): return "GB"
    if RE_TLD_FR.search(host_lower): return "FR"
    if RE_TLD_LV.search(host_lower): return "LV"
    if RE_TLD_EU.search(host_lower): return "EU"
    
    for code in EURO_CODES:
        if code in name_upper:
            return code
    
    return "UNKNOWN"

def is_garbage(key_str):
    """Быстрая проверка на мусор"""
    upper = key_str.upper()
    return any(m in upper for m in BAD_MARKERS) or \
           any(x in key_str for x in [".ir", ".cn", "127.0.0.1", "localhost", "0.0.0.0"])

# ------------------ Загрузка ключей ------------------
def fetch_with_retry(session, url, retries=3):
    """HTTP запрос с retry"""
    for attempt in range(retries):
        try:
            resp = session.get(url, timeout=15)
            if resp.status_code == 200:
                return resp.text
            if resp.status_code in [403, 404]:
                return None
        except Exception as e:
            if attempt == retries - 1:
                print(f"    ❌ Ошибка после {retries} попыток: {e}")
    return None

def fetch_keys(urls, tag):
    """Загрузка и фильтрация ключей"""
    out = []
    print(f"\n📥 Загрузка {tag}... Источников: {len(urls)}")
    
    session = requests.Session()
    session.headers.update({
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
    })
    
    for url in urls:
        url = url.strip()
        if not url:
            continue
        
        print(f"  ➜ {url[:70]}...")
        content = fetch_with_retry(session, url)
        
        if not content:
            continue
        
        # Декодирование Base64
        lines = []
        if "://" not in content:
            try:
                decoded = base64.b64decode(content + "==").decode('utf-8', errors='ignore')
                lines = decoded.splitlines()
            except:
                lines = content.splitlines()
        else:
            lines = content.splitlines()
        
        # Обработка строк
        loaded = 0
        for line in lines:
            line = line.strip()
            if not line or len(line) > 2000:
                continue
            
            if line.startswith(("vless://", "vmess://", "trojan://", "ss://")):
                if is_garbage(line):
                    continue
                
                if tag == "RU" and any(m in line.upper() for m in ["CN", "IR"]):
                    continue
                
                out.append((line, tag))
                loaded += 1
        
        if loaded > 0:
            print(f"    ✅ Загружено: {loaded}")
    
    print(f"📊 {tag}: итого {len(out)} ключей")
    return out

# ------------------ Проверка соединения ------------------
def check_connection(host, port, is_tls):
    """Универсальная проверка TCP/TLS"""
    try:
        start = time.time()
        
        if is_tls:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            
            with socket.create_connection((host, port), timeout=TIMEOUT) as sock:
                with ctx.wrap_socket(sock, server_hostname=host):
                    pass
        else:
            with socket.create_connection((host, port), timeout=TIMEOUT) as sock:
                pass
        
        return int((time.time() - start) * 1000)
    except:
        return None

def parse_key(key):
    """Быстрый парсинг ключа"""
    try:
        if "@" not in key or ":" not in key:
            return None, None, None
        
        part = key.split("@")[1].split("?")[0].split("#")[0]
        host, port_str = part.rsplit(":", 1)
        port = int(port_str.strip())
        
        if port <= 0 or port > 65535:
            return None, None, None
        
        is_tls = any(x in key.lower() for x in ['security=tls', 'security=reality']) or \
                 key.startswith(("trojan://", "vmess://"))
        
        return host.strip(), port, is_tls
    except:
        return None, None, None

def check_single_key(data):
    """Проверка одного ключа"""
    key, tag = data
    
    host, port, is_tls = parse_key(key)
    if not host:
        return None, None, None, None
    
    country = get_country_fast(host, key)
    
    if tag == "MY" and country == "RU":
        return None, None, None, None
    
    # Определение типа роутинга
    routing_type = classify_key_advanced(key, tag)
    
    # Проверка с retry
    latency = None
    for attempt in range(RETRY_ATTEMPTS):
        latency = check_connection(host, port, is_tls)
        if latency is not None:
            break
        time.sleep(0.1)
    
    if latency is None:
        return None, None, None, None
    
    return latency, tag, country, routing_type

# ------------------ Утилиты сохранения ------------------
def extract_ping(key_str):
    """Извлечение пинга из метки"""
    try:
        label = key_str.split("#")[-1]
        if "ms_" not in label:
            return None
        ping_part = label.split("ms_")[0]
        return int(ping_part)
    except:
        return None

def save_chunked(keys_list, folder, base_name):
    """Сохранение с chunking"""
    created_files = []
    valid_keys = [k.strip() for k in keys_list if k and isinstance(k, str) and k.strip()]
    
    if not valid_keys:
        fname = f"{base_name}.txt"
        with open(os.path.join(folder, fname), "w", encoding="utf-8") as f:
            f.write("")
        return [fname]
    
    chunks = [valid_keys[i:i + CHUNK_LIMIT] for i in range(0, len(valid_keys), CHUNK_LIMIT)]
    
    for i, chunk in enumerate(chunks, 1):
        fname = f"{base_name}.txt" if len(chunks) == 1 else f"{base_name}_part{i}.txt"
        content = "\n".join(chunk)
        with open(os.path.join(folder, fname), "w", encoding="utf-8") as f:
            f.write(content)
        created_files.append(fname)
        print(f"  📄 {fname}: {len(chunk)} ключей")
    
    return created_files

# ------------------ Главная функция ------------------
def main():
    print(f"=== VPN Checker v13.0 (Smart Routing) ===")
    print(f"🚀 Запуск: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"⚙️  Настройки: Timeout={TIMEOUT}s | Threads={THREADS} | Retry={RETRY_ATTEMPTS}")
    print(f"🎯 Новое: Автоопределение белых/черных списков\n")
    
    # Очистка папок
    for folder in [FOLDER_RU, FOLDER_EURO]:
        if os.path.exists(folder):
            shutil.rmtree(folder)
        os.makedirs(folder, exist_ok=True)
    
    # Загрузка истории
    history = load_json(HISTORY_FILE)
    print(f"📂 История: {len(history)} записей")
    
    # Загрузка ключей
    print("\n" + "="*60)
    print("ЗАГРУЗКА ИСТОЧНИКОВ")
    print("="*60)
    tasks_ru = fetch_keys(URLS_RU, "RU")
    tasks_my = fetch_keys(URLS_MY, "MY")
    
    # Удаление дубликатов
    unique = {}
    for k, tag in tasks_ru + tasks_my:
        key_id = k.split("#")[0]
        unique[key_id] = (k, tag)
    
    all_items = list(unique.values())
    print(f"\n📊 Уникальных ключей: {len(all_items)}")
    
    if len(all_items) > MAX_KEYS_TO_CHECK:
        all_items = all_items[:MAX_KEYS_TO_CHECK]
        print(f"⚠️  Ограничено до {MAX_KEYS_TO_CHECK}")
    
    # Фильтрация по кэшу
    current_time = time.time()
    to_check = []
    
    # Раздельные результаты
    res_ru_white = []
    res_ru_black = []
    res_ru_universal = []
    res_euro_white = []
    res_euro_black = []
    res_euro_universal = []
    
    cache_hits = 0
    
    print("\n" + "="*60)
    print("ПРОВЕРКА КЭША")
    print("="*60)
    
    for key, tag in all_items:
        key_id = key.split("#")[0]
        cached = history.get(key_id)
        
        if cached and (current_time - cached['time'] < CACHE_HOURS * 3600) and cached.get('alive'):
            latency = cached['latency']
            country = cached.get('country', 'UNKNOWN')
            routing_type = cached.get('routing_type', 'universal')
            
            label = f"{latency}ms_{country}_{routing_type.upper()}_{MY_CHANNEL}"
            final = f"{key_id}#{label}"
            
            if tag == "RU":
                if routing_type == 'white':
                    res_ru_white.append(final)
                elif routing_type == 'black':
                    res_ru_black.append(final)
                else:
                    res_ru_universal.append(final)
            elif tag == "MY" and country != "RU":
                if routing_type == 'white':
                    res_euro_white.append(final)
                elif routing_type == 'black':
                    res_euro_black.append(final)
                else:
                    res_euro_universal.append(final)
            
            cache_hits += 1
        else:
            to_check.append((key, tag))
    
    print(f"✅ Из кэша: {cache_hits} | 🔍 Для проверки: {len(to_check)}")
    
    # Проверка новых ключей
    if to_check:
        print("\n" + "="*60)
        print("ПРОВЕРКА В РЕАЛЬНОМ ВРЕМЕНИ")
        print("="*60)
        
        checked = 0
        failed = 0
        stats = defaultdict(lambda: defaultdict(int))
        
        with ThreadPoolExecutor(max_workers=THREADS) as executor:
            futures = {executor.submit(check_single_key, item): item for item in to_check}
            
            for future in as_completed(futures):
                key, tag = futures[future]
                checked += 1
                
                try:
                    result = future.result(timeout=TIMEOUT + 2)
                    
                    if not result or result[0] is None:
                        failed += 1
                        continue
                    
                    latency, tag, country, routing_type = result
                    key_id = key.split("#")[0]
                    
                    # Сохранение в историю с типом роутинга
                    history[key_id] = {
                        'alive': True,
                        'latency': latency,
                        'time': current_time,
                        'country': country,
                        'routing_type': routing_type
                    }
                    
                    # Формирование строки с меткой типа
                    label = f"{latency}ms_{country}_{routing_type.upper()}_{MY_CHANNEL}"
                    final = f"{key_id}#{label}"
                    
                    if tag == "RU":
                        if routing_type == 'white':
                            res_ru_white.append(final)
                            stats['ru']['white'] += 1
                        elif routing_type == 'black':
                            res_ru_black.append(final)
                            stats['ru']['black'] += 1
                        else:
                            res_ru_universal.append(final)
                            stats['ru']['universal'] += 1
                    elif tag == "MY" and country != "RU":
                        if routing_type == 'white':
                            res_euro_white.append(final)
                            stats['euro']['white'] += 1
                        elif routing_type == 'black':
                            res_euro_black.append(final)
                            stats['euro']['black'] += 1
                        else:
                            res_euro_universal.append(final)
                            stats['euro']['universal'] += 1
                    
                except Exception:
                    failed += 1
                
                # Прогресс каждые 50 ключей
                if checked % 50 == 0:
                    print(f"  📊 {checked}/{len(to_check)} | "
                          f"RU: W:{stats['ru']['white']} B:{stats['ru']['black']} U:{stats['ru']['universal']} | "
                          f"EU: W:{stats['euro']['white']} B:{stats['euro']['black']} U:{stats['euro']['universal']} | "
                          f"❌ {failed}")
        
        print(f"\n✅ Итого проверено: {checked}, неработающих: {failed}")
    
    # Очистка истории
    history_cleaned = {
        k: v for k, v in history.items()
        if current_time - v['time'] < 259200
    }
    save_json(HISTORY_FILE, history_cleaned)
    print(f"\n🧹 Очищено истории: {len(history)} → {len(history_cleaned)}")
    
    # Сортировка
    print("\n" + "="*60)
    print("КЛАССИФИКАЦИЯ И СОРТИРОВКА")
    print("="*60)
    
    # Очистка и сортировка всех категорий
    def clean_and_sort(keys_list):
        clean = [k for k in keys_list if extract_ping(k) is not None]
        clean.sort(key=extract_ping)
        return clean
    
    res_ru_white = clean_and_sort(res_ru_white)
    res_ru_black = clean_and_sort(res_ru_black)
    res_ru_universal = clean_and_sort(res_ru_universal)
    res_euro_white = clean_and_sort(res_euro_white)
    res_euro_black = clean_and_sort(res_euro_black)
    res_euro_universal = clean_and_sort(res_euro_universal)
    
    print(f"🇷🇺 РОССИЯ:")
    print(f"  ⚪ Белый список (bypass): {len(res_ru_white)}")
    print(f"  ⚫ Черный список (full VPN): {len(res_ru_black)}")
    print(f"  🔘 Универсальные: {len(res_ru_universal)}")
    
    print(f"\n🇪🇺 ЕВРОПА:")
    print(f"  ⚪ Белый список: {len(res_euro_white)}")
    print(f"  ⚫ Черный список: {len(res_euro_black)}")
    print(f"  🔘 Универсальные: {len(res_euro_universal)}")
    
    # Сохранение файлов
    print("\n" + "="*60)
    print("СОХРАНЕНИЕ ФАЙЛОВ")
    print("="*60)
    
    print("\n🇷🇺 Россия:")
    ru_white_files = save_chunked(res_ru_white, FOLDER_RU, "ru_white")
    ru_black_files = save_chunked(res_ru_black, FOLDER_RU, "ru_black")
    ru_uni_files = save_chunked(res_ru_universal, FOLDER_RU, "ru_universal")
    
    print("\n🇪🇺 Европа:")
    euro_white_files = save_chunked(res_euro_white, FOLDER_EURO, "euro_white")
    euro_black_files = save_chunked(res_euro_black, FOLDER_EURO, "euro_black")
    euro_uni_files = save_chunked(res_euro_universal, FOLDER_EURO, "euro_universal")
    
    # Генерация подписок
    GITHUB_USER_REPO = "Mihuil121/vpn-checker-backend-fox"
    BRANCH = "main"
    
    BASE_RU = f"https://raw.githubusercontent.com/{GITHUB_USER_REPO}/{BRANCH}/{BASE_DIR}/RU_Best"
    BASE_EU = f"https://raw.githubusercontent.com/{GITHUB_USER_REPO}/{BRANCH}/{BASE_DIR}/My_Euro"
    
    subs = ["=== 🇷🇺 РОССИЯ ===", ""]
    
    if ru_white_files:
        subs.append("⚪ БЕЛЫЙ СПИСОК (Госуслуги, банки, РФ сайты):")
        for f in ru_white_files:
            subs.append(f"{BASE_RU}/{f}")
        subs.append("")
    
    if ru_black_files:
        subs.append("⚫ ЧЕРНЫЙ СПИСОК (Полный VPN):")
        for f in ru_black_files:
            subs.append(f"{BASE_RU}/{f}")
        subs.append("")
    
    if ru_uni_files:
        subs.append("🔘 УНИВЕРСАЛЬНЫЕ:")
        for f in ru_uni_files:
            subs.append(f"{BASE_RU}/{f}")
    
    subs.extend(["", "=== 🇪🇺 ЕВРОПА ===", ""])
    
    if euro_white_files:
        subs.append("⚪ БЕЛЫЙ СПИСОК:")
        for f in euro_white_files:
            subs.append(f"{BASE_EU}/{f}")
        subs.append("")
    
    if euro_black_files:
        subs.append("⚫ ЧЕРНЫЙ СПИСОК:")
        for f in euro_black_files:
            subs.append(f"{BASE_EU}/{f}")
        subs.append("")
    
    if euro_uni_files:
        subs.append("🔘 УНИВЕРСАЛЬНЫЕ:")
        for f in euro_uni_files:
            subs.append(f"{BASE_EU}/{f}")
    
    with open(os.path.join(BASE_DIR, "subscriptions_list.txt"), "w", encoding="utf-8") as f:
        f.write("\n".join(subs))
    
    print("\n" + "="*60)
    print("✅ SUCCESS: ВСЕ СПИСКИ ОБНОВЛЕНЫ С КЛАССИФИКАЦИЕЙ")
    print("="*60)
    print(f"🕒 Завершено: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("\n💡 Подсказка:")
    print("  ⚪ БЕЛЫЙ - только заблокированные в РФ сайты идут через VPN")
    print("  ⚫ ЧЕРНЫЙ - весь трафик через VPN")
    print("  🔘 УНИВЕРСАЛЬНЫЙ - неопределенный тип, используйте на свое усмотрение")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n⚠️ Прервано (Ctrl+C)")
        exit(1)
    except Exception as e:
        print(f"\n\n❌ КРИТИЧЕСКАЯ ОШИБКА: {e}")
        import traceback
        traceback.print_exc()
        exit(1)