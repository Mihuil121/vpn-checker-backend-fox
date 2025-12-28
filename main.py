import os
import re
import html
import socket
import ssl
import time
import requests
import base64
import websocket
from datetime import datetime
from urllib.parse import quote, unquote

# ------------------ Настройки ------------------
NEW_KEYS_FOLDER = "checked"
os.makedirs(NEW_KEYS_FOLDER, exist_ok=True)

TIMEOUT = 2   # Таймаут проверки (сек)
RETRIES = 1   # Попыток на ключ

timestamp = datetime.now().strftime("%Y%m%d_%H%M")
LIVE_KEYS_FILE = os.path.join(NEW_KEYS_FOLDER, "live_keys.txt")
LOG_FILE = os.path.join(NEW_KEYS_FOLDER, "log.txt")

MY_CHANNEL = "@vlesstrojan" 

# Полный список источников (Ваши + Ryzgames)
URLS = [
    "https://github.com/sakha1370/OpenRay/raw/refs/heads/main/output/all_valid_proxies.txt",
    "https://raw.githubusercontent.com/sevcator/5ubscrpt10n/main/protocols/vl.txt",
    "https://raw.githubusercontent.com/yitong2333/proxy-minging/refs/heads/main/v2ray.txt",
    "https://raw.githubusercontent.com/acymz/AutoVPN/refs/heads/main/data/V2.txt",
    "https://raw.githubusercontent.com/miladtahanian/V2RayCFGDumper/refs/heads/main/config.txt",
    "https://raw.githubusercontent.com/roosterkid/openproxylist/main/V2RAY_RAW.txt",
    "https://github.com/Epodonios/v2ray-configs/raw/main/Splitted-By-Protocol/trojan.txt",
    "https://raw.githubusercontent.com/YasserDivaR/pr0xy/refs/heads/main/ShadowSocks2021.txt",
    "https://raw.githubusercontent.com/mohamadfg-dev/telegram-v2ray-configs-collector/refs/heads/main/category/vless.txt",
    "https://raw.githubusercontent.com/mheidari98/.proxy/refs/heads/main/vless",
    "https://raw.githubusercontent.com/youfoundamin/V2rayCollector/main/mixed_iran.txt",
    "https://raw.githubusercontent.com/mheidari98/.proxy/refs/heads/main/all",
    "https://github.com/Kwinshadow/TelegramV2rayCollector/raw/refs/heads/main/sublinks/mix.txt",
    "https://github.com/LalatinaHub/Mineral/raw/refs/heads/master/result/nodes",
    "https://raw.githubusercontent.com/miladtahanian/multi-proxy-config-fetcher/refs/heads/main/configs/proxy_configs.txt",
    "https://raw.githubusercontent.com/Pawdroid/Free-servers/refs/heads/main/sub",
    "https://github.com/MhdiTaheri/V2rayCollector_Py/raw/refs/heads/main/sub/Mix/mix.txt",
    "https://github.com/Epodonios/v2ray-configs/raw/main/Splitted-By-Protocol/vmess.txt",
    "https://github.com/MhdiTaheri/V2rayCollector/raw/refs/heads/main/sub/mix",
    "https://raw.githubusercontent.com/mehran1404/Sub_Link/refs/heads/main/V2RAY-Sub.txt",
    "https://raw.githubusercontent.com/shabane/kamaji/master/hub/merged.txt",
    "https://raw.githubusercontent.com/wuqb2i4f/xray-config-toolkit/main/output/base64/mix-uri",
    "https://raw.githubusercontent.com/AzadNetCH/Clash/refs/heads/main/AzadNet.txt",
    "https://raw.githubusercontent.com/STR97/STRUGOV/refs/heads/main/STR.BYPASS",
    "https://raw.githubusercontent.com/V2RayRoot/V2RayConfig/refs/heads/main/Config/vless.txt",
    "https://raw.githubusercontent.com/lagzian/SS-Collector/main/mix_clash.yaml",
    "https://raw.githubusercontent.com/Argh94/V2RayAutoConfig/refs/heads/main/configs/Vless.txt",
    "https://raw.githubusercontent.com/Argh94/V2RayAutoConfig/refs/heads/main/configs/Hysteria2.txt",
    "https://raw.githubusercontent.com/mahdibland/V2RayAggregator/master/sub/sub_list.json",
    "https://raw.githubusercontent.com/NiREvil/vless/main/sub/SSTime",
    "https://raw.githubusercontent.com/ndsphonemy/proxy-sub/main/speed.txt",
    "https://raw.githubusercontent.com/Mahdi0024/ProxyCollector/master/sub/proxies.txt",
    "https://raw.githubusercontent.com/Mosifree/-FREE2CONFIG/refs/heads/main/Reality",
    "https://raw.githubusercontent.com/MrMohebi/xray-proxy-grabber-telegram/master/collected-proxies/row-url/all.txt",
    "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/refs/heads/main/Vless-Reality-White-Lists-Rus-Mobile.txt",
    "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/refs/heads/main/Vless-Reality-White-Lists-Rus-Cable.txt",
    "https://raw.githubusercontent.com/RYZgames31/UWB/refs/heads/main/wcfg",
    "https://raw.githubusercontent.com/AvenCores/goida-vpn-configs/refs/heads/main/githubmirror/26.txt",
    "https://raw.githubusercontent.com/zieng2/wl/main/vless.txt",
    "https://raw.githubusercontent.com/LowiKLive/BypassWhitelistRu/refs/heads/main/WhiteList-Bypass_Ru.txt",
    "https://raw.githubusercontent.com/zieng2/wl/main/vless_universal.txt",
    "https://raw.githubusercontent.com/vsevjik/OBSpiskov/refs/heads/main/wwh",
    "https://jsnegsukavsos.hb.ru-msk.vkcloud-storage.ru/love",
    "https://etoneya.a9fm.site/1",
    "https://s3c3.001.gpucloud.ru/vahe4xkwi/cjdr"
]

# ------------------ Функции ------------------

def decode_base64_safe(data):
    """Безопасная декодировка Base64 (с паддингом и без)"""
    try:
        # Добавляем паддинг если нужно
        padding = len(data) % 4
        if padding:
            data += '=' * (4 - padding)
        return base64.b64decode(data).decode('utf-8', errors='ignore')
    except:
        return None

def fetch_and_load_keys(urls):
    all_keys = []
    print(f"Загрузка с {len(urls)} источников...")
    
    for url in urls:
        try:
            resp = requests.get(url, timeout=10)
            if resp.status_code != 200:
                print(f"[ERROR] {url} -> {resp.status_code}")
                continue
                
            content = resp.text.strip()
            
            # Проверка на Base64 (если нет явных протоколов)
            if "vmess://" not in content and "vless://" not in content and "://" not in content:
                decoded = decode_base64_safe(content)
                if decoded:
                    lines = decoded.splitlines()
                else:
                    lines = content.splitlines()
            else:
                lines = content.splitlines()

            count = 0
            for line in lines:
                line = line.strip()
                if line.startswith(("vless://", "vmess://", "trojan://", "ss://")):
                    all_keys.append(line)
                    count += 1
            print(f"[OK] {url} -> найдено {count}")
            
        except Exception as e:
            print(f"[FAIL] {url} -> {e}")
            
    return list(set(all_keys)) # Сразу удаляем дубликаты

def extract_host_port(key):
    try:
        if "@" in key and ":" in key:
            after_at = key.split("@")[1]
            main_part = re.split(r'[?#]', after_at)[0]
            if ":" in main_part:
                host, port = main_part.split(":")
                return host, int(port)
    except: return None, None
    return None, None

def classify_latency(latency_ms: int) -> str:
    if latency_ms < 300: return "fast"
    if latency_ms < 1000: return "normal"
    return "slow"

def measure_latency(key, host, port, timeout=TIMEOUT):
    """
    Гибридная проверка: WebSocket для Cloudflare/CDN, TCP для остальных.
    """
    is_tls = 'security=tls' in key or 'security=reality' in key or 'trojan://' in key or 'vmess://' in key
    is_ws = 'type=ws' in key or 'net=ws' in key
    
    path = "/"
    path_match = re.search(r'path=([^&]+)', key)
    if path_match: path = unquote(path_match.group(1))

    protocol = "wss" if is_tls else "ws"
    
    # 1. Если это WebSocket (VLESS/VMess WS)
    if is_ws:
        try:
            start = time.time()
            ws_url = f"{protocol}://{host}:{port}{path}"
            # Важно: отключаем проверку сертификата, чтобы не падать на self-signed
            ws = websocket.create_connection(ws_url, timeout=timeout, sslopt={"cert_reqs": ssl.CERT_NONE})
            ws.close()
            return int((time.time() - start) * 1000)
        except: return None

    # 2. Если это просто TLS (Reality / Trojan / VLESS TCP)
    if not is_ws and is_tls:
        try:
            start = time.time()
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            with socket.create_connection((host, port), timeout=timeout) as sock:
                with context.wrap_socket(sock, server_hostname=host):
                    pass
            return int((time.time() - start) * 1000)
        except: return None

    # 3. Обычный TCP
    try:
        start = time.time()
        with socket.create_connection((host, port), timeout=timeout):
            pass
        return int((time.time() - start) * 1000)
    except: return None

def add_comment(key, latency, quality):
    if "#" in key: base, _ = key.split("#", 1)
    else: base = key
    tag = f"{quality}_{latency}ms_{MY_CHANNEL}".replace(" ", "_")
    return f"{base}#{tag}"

# ------------------ Main Process ------------------
if __name__ == "__main__":
    print("=== START CHECKER ===")
    
    # 1. Загрузка
    all_keys = fetch_and_load_keys(URLS)
    print(f"Всего уникальных ключей для проверки: {len(all_keys)}")

    # 2. Проверка
    valid_count = 0
    
    with open(LIVE_KEYS_FILE, "w", encoding="utf-8") as f_out:
        for i, key in enumerate(all_keys):
            key = html.unescape(key).strip()
            host, port = extract_host_port(key)
            
            if not host: continue

            # Вывод прогресса каждые 100 ключей
            if i % 100 == 0: print(f"Checked {i}/{len(all_keys)}...")

            latency = measure_latency(key, host, port)
            
            if latency is not None:
                qual = classify_latency(latency)
                final_key = add_comment(key, latency, qual)
                f_out.write(final_key + "\n")
                valid_count += 1

    print(f"=== DONE. Valid keys: {valid_count} ===")
    print(f"Saved to: {LIVE_KEYS_FILE}")


