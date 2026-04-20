#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
VPN Checker v4.0 - УМНАЯ ПРОВЕРКА ПО ПОДПИСКАМ

Алгоритм:
- Сначала загружаем ВСЕ подписки и считаем ключи
- Сортируем по убыванию размера (сначала большие)
- Каждая подписка проверяется своим пулом:
    workers = min(кол-во_ключей, MAX_WORKERS_PER_SUB)
  т.е. маленькая подписка (3 ключа) → 3 потока, мгновенно
       большая (31285 ключей) → MAX_WORKERS_PER_SUB потоков
- Глобальный семафор не даёт суммарно запустить > MAX_TOTAL_WORKERS Xray
- Подробный прогресс: [Подписка 3/47] [Ключ 150/985]
"""

import os
import json
import time
import random
import subprocess
import tempfile
import requests
import socket
import re
import hashlib
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Optional, Tuple, Dict
from dataclasses import dataclass
import signal
import threading
import argparse
from urllib.parse import urlparse, parse_qs, unquote
import base64
import ipaddress

# ==================== КОНФИГУРАЦИЯ ====================
COUNTRY_FLAGS = {
    "RU": "🇷🇺", "DE": "🇩🇪", "NL": "🇳🇱", "US": "🇺🇸", "GB": "🇬🇧",
    "FR": "🇫🇷", "PL": "🇵🇱", "UA": "🇺🇦", "KZ": "🇰🇿", "TR": "🇹🇷",
    "FI": "🇫🇮", "SE": "🇸🇪", "LT": "🇱🇹", "LV": "🇱🇻", "EE": "🇪🇪",
    "RO": "🇷🇴", "HU": "🇭🇺", "CZ": "🇨🇿", "AT": "🇦🇹", "CH": "🇨🇭",
    "IT": "🇮🇹", "ES": "🇪🇸", "SG": "🇸🇬", "JP": "🇯🇵", "HK": "🇭🇰",
    "CA": "🇨🇦", "AU": "🇦🇺", "AE": "🇦🇪", "GE": "🇬🇪", "AM": "🇦🇲",
    "BY": "🇧🇾", "MD": "🇲🇩", "IR": "🇮🇷", "IN": "🇮🇳", "CN": "🇨🇳",
    "KR": "🇰🇷", "BR": "🇧🇷", "ID": "🇮🇩", "VN": "🇻🇳", "TH": "🇹🇭",
    "MY": "🇲🇾", "PH": "🇵🇭", "BG": "🇧🇬", "GR": "🇬🇷",
    "PT": "🇵🇹", "IE": "🇮🇪", "NO": "🇳🇴", "DK": "🇩🇰", "BE": "🇧🇪",
    "LU": "🇱🇺", "SK": "🇸🇰", "SI": "🇸🇮", "HR": "🇭🇷", "RS": "🇷🇸",
    "AL": "🇦🇱", "MK": "🇲🇰", "MT": "🇲🇹", "CY": "🇨🇾", "IS": "🇮🇸",
    "AZ": "🇦🇿", "UZ": "🇺🇿", "TM": "🇹🇲", "KG": "🇰🇬", "TJ": "🇹🇯",
    "MX": "🇲🇽", "AR": "🇦🇷", "CL": "🇨🇱", "CO": "🇨🇴", "PE": "🇵🇪",
    "ZA": "🇿🇦", "EG": "🇪🇬", "NG": "🇳🇬", "KE": "🇰🇪", "IL": "🇮🇱",
    "SA": "🇸🇦", "QA": "🇶🇦", "KW": "🇰🇼", "BH": "🇧🇭", "OM": "🇴🇲",
    "PK": "🇵🇰", "BD": "🇧🇩", "LK": "🇱🇰", "NP": "🇳🇵", "MM": "🇲🇲",
    "KH": "🇰🇭", "LA": "🇱🇦", "MN": "🇲🇳", "TW": "🇹🇼", "NZ": "🇳🇿",
}

TLD_COUNTRY_MAP = {
    ".ru": "RU", ".рф": "RU", ".de": "DE", ".nl": "NL", ".fr": "FR",
    ".uk": "GB", ".com": "US", ".org": "US", ".net": "US", ".edu": "US",
    ".pl": "PL", ".ua": "UA", ".kz": "KZ", ".tr": "TR", ".fi": "FI",
    ".se": "SE", ".lt": "LT", ".lv": "LV", ".ee": "EE", ".ro": "RO",
    ".hu": "HU", ".cz": "CZ", ".at": "AT", ".ch": "CH", ".it": "IT",
    ".es": "ES", ".sg": "SG", ".jp": "JP", ".hk": "HK", ".ca": "CA",
    ".au": "AU", ".ae": "AE", ".ge": "GE", ".am": "AM", ".by": "BY",
    ".md": "MD", ".ir": "IR", ".in": "IN", ".cn": "CN", ".kr": "KR",
    ".br": "BR", ".id": "ID", ".vn": "VN", ".th": "TH", ".my": "MY",
    ".ph": "PH", ".bg": "BG", ".gr": "GR", ".pt": "PT", ".ie": "IE",
    ".no": "NO", ".dk": "DK", ".be": "BE", ".lu": "LU", ".sk": "SK",
    ".si": "SI", ".hr": "HR", ".rs": "RS", ".al": "AL", ".mk": "MK",
    ".mt": "MT", ".cy": "CY", ".is": "IS", ".az": "AZ", ".uz": "UZ",
    ".tm": "TM", ".kg": "KG", ".tj": "TJ", ".mx": "MX", ".ar": "AR",
    ".cl": "CL", ".co": "CO", ".pe": "PE", ".za": "ZA", ".eg": "EG",
    ".ng": "NG", ".ke": "KE", ".il": "IL", ".sa": "SA", ".qa": "QA",
    ".kw": "KW", ".bh": "BH", ".om": "OM", ".pk": "PK", ".bd": "BD",
    ".lk": "LK", ".np": "NP", ".mm": "MM", ".kh": "KH", ".la": "LA",
    ".mn": "MN", ".tw": "TW", ".nz": "NZ",
}

IP_COUNTRY_RANGES = {
    "RU": ["5.", "31.", "37.", "46.", "62.", "77.", "78.", "79.", "80.", "81.", "82.", "83.",
           "84.", "85.", "87.", "88.", "89.", "90.", "91.", "92.", "93.", "94.", "95.", "109.",
           "141.", "178.", "185.", "188.", "194.", "195.", "212.", "213.", "217."],
    "US": ["8.", "13.", "17.", "23.", "24.", "32.", "34.", "35.", "40.", "44.", "45.", "50.",
           "52.", "54.", "63.", "64.", "65.", "66.", "67.", "68.", "69.", "70.", "71.", "72.",
           "73.", "74.", "75.", "76.", "96.", "97.", "98.", "99.", "100.", "104.", "107.",
           "108.", "128.", "129.", "130.", "131.", "132.", "134.", "135.", "136.", "137.",
           "138.", "139.", "140.", "142.", "143.", "144.", "146.", "147.", "148.", "149.",
           "150.", "151.", "152.", "155.", "156.", "157.", "158.", "159.", "160.", "161.",
           "162.", "163.", "164.", "165.", "166.", "167.", "168.", "169.", "170.", "172.",
           "173.", "174.", "184.", "185.", "192.", "198.", "199.", "204.", "205.", "206.",
           "207.", "208.", "209.", "216."],
    "DE": ["46.", "51.", "52.", "53.", "77.", "78.", "79.", "80.", "81.", "82.", "83.", "84.",
           "85.", "87.", "88.", "89.", "91.", "93.", "94.", "95.", "109.", "134.", "135.",
           "136.", "137.", "138.", "139.", "141.", "144.", "145.", "151.", "159.", "176.",
           "177.", "178.", "185.", "188.", "193.", "194.", "195.", "212.", "213.", "217."],
    "NL": ["5.", "31.", "37.", "45.", "46.", "62.", "77.", "78.", "79.", "80.", "81.", "82.",
           "83.", "84.", "85.", "87.", "88.", "89.", "91.", "93.", "94.", "95.", "109.",
           "130.", "131.", "145.", "176.", "177.", "178.", "185.", "188.", "193.", "194.",
           "195.", "212.", "213."],
    "GB": ["2.", "5.", "31.", "37.", "45.", "46.", "51.", "52.", "62.", "77.", "78.", "79.",
           "80.", "81.", "82.", "83.", "84.", "85.", "87.", "88.", "89.", "91.", "93.",
           "94.", "95.", "109.", "130.", "141.", "158.", "176.", "177.", "178.", "185.",
           "188.", "193.", "194.", "195.", "212.", "213."],
    "FR": ["5.", "31.", "37.", "45.", "46.", "51.", "52.", "62.", "77.", "78.", "79.", "80.",
           "81.", "82.", "83.", "84.", "85.", "87.", "88.", "89.", "91.", "93.", "94.",
           "95.", "109.", "141.", "151.", "159.", "176.", "177.", "178.", "185.", "188.",
           "193.", "194.", "195.", "212.", "213."],
    "CN": ["14.", "27.", "36.", "39.", "42.", "49.", "58.", "59.", "60.", "61.", "101.",
           "103.", "106.", "110.", "111.", "112.", "113.", "114.", "115.", "116.", "117.",
           "118.", "119.", "120.", "121.", "122.", "123.", "124.", "125.", "126.", "128.",
           "218.", "219.", "220.", "221.", "222.", "223."],
}


@dataclass
class Config:
    XRAY_PATH: str = "/home/misha121/vpn-checker-backend-fox/Xray-linux-64/xray"

    CHECKED_DIR: str = "checked"
    RU_DIR:      str = "checked/RU_Best"
    EURO_DIR:    str = "checked/My_Euro"

    SOCKS_PORT_START: int = 20000
    SOCKS_PORT_RANGE: int = 10000   # порты 20000-29999

    XRAY_STARTUP_WAIT:  float = 0.5
    CONNECTION_TIMEOUT: int   = 4
    REQUEST_TIMEOUT:    int   = 8
    TOTAL_TIMEOUT:      int   = 25

    MAX_WORKERS_PER_SUB: int = 80
    MAX_TOTAL_WORKERS:   int = 80
    MAX_KEYS:            int = 999999

    RUSSIAN_TEST_SITES: List[str] = None
    FOREIGN_TEST_SITES: List[str] = None
    SOURCES:            List[str] = None

    def __post_init__(self):
        if self.RUSSIAN_TEST_SITES is None:
            self.RUSSIAN_TEST_SITES = [
                "https://vk.com",
                "https://yandex.ru",
                "https://mail.ru",
            ]
        if self.FOREIGN_TEST_SITES is None:
            self.FOREIGN_TEST_SITES = [
                "https://www.instagram.com",
                "https://www.facebook.com",
                "https://www.twitter.com",
            ]
        if self.SOURCES is None:
            # ===== ВСТАВЬ СВОИ ССЫЛКИ СЮДА =====
            self.SOURCES = [
                "https://raw.githubusercontent.com/zieng2/wl/main/vless.txt",
                "https://gitverse.ru/api/repos/RUVIPIEN/russian-white-bolt/raw/branch/master/VPNMIRRORS/nekobox/Alley_Config_1_d0212d.txt",
                "https://raw.githubusercontent.com/Vovo4ka000/V4kVPN/main/v4kVPN.txt",
                "https://gitverse.ru/api/repos/RUVIPIEN/russian-white-bolt/raw/branch/master/VPNMIRRORS/nekobox/Alley_Config_2_862576.txt",
                "https://gitverse.ru/api/repos/RUVIPIEN/russian-white-bolt/raw/branch/master/VPNMIRRORS/nekobox/ByWarm_Merged_b37672.txt",
                "https://gitverse.ru/api/repos/RUVIPIEN/russian-white-bolt/raw/branch/master/VPNMIRRORS/nekobox/ByWarm_Selected_6ac883.txt",
                "https://gitverse.ru/api/repos/RUVIPIEN/russian-white-bolt/raw/branch/master/VPNMIRRORS/nekobox/ByWarm_WL_db4c3f.txt",
                "https://gitverse.ru/api/repos/RUVIPIEN/russian-white-bolt/raw/branch/master/VPNMIRRORS/nekobox/ByeWhiteLists_2_fda813.txt",
                "https://gitverse.ru/api/repos/RUVIPIEN/russian-white-bolt/raw/branch/master/VPNMIRRORS/v2ray/Bypass_Config_7_d33b54.txt",
                "https://gitverse.ru/api/repos/RUVIPIEN/russian-white-bolt/raw/branch/master/VPNMIRRORS/happ/SER38_Happ_Sub1_ddd131.txt",
                "https://wlrus.lol/confs/selected.txt",
                "https://raw.githubusercontent.com/Ilyacom4ik/free-v2ray-2026/refs/heads/main/subscriptions/FreeCFGHub1.txt",
                "https://raw.githubusercontent.com/HikaruApps/WhiteLattice/refs/heads/main/subscriptions/config.txt",
                "https://storage.yandexcloud.net/wall-breaker-c0de-a666/config.txt",
                "https://gitverse.ru/api/repos/bywarm/rser/raw/branch/master/selected.txt",
                "https://wlrus.lol/confs/merged.txt",
                "https://gitverse.ru/api/repos/bywarm/rser/raw/branch/master/merged.txt",
                "https://raw.githubusercontent.com/F0rc3Run/F0rc3Run/main/splitted-by-protocol/vless.txt",
                "https://v2.alicivil.workers.dev/",
                "https://raw.githubusercontent.com/mshojaei77/v2rayAuto/refs/heads/main/telegram/popular_channels_1",
                "https://raw.githubusercontent.com/10ium/ScrapeAndCategorize/refs/heads/main/output_configs/Hysteria2.txt",
                "https://raw.githubusercontent.com/MatinGhanbari/v2ray-configs/main/subscriptions/v2ray/subs/sub1.txt",
                "https://raw.githubusercontent.com/barry-far/V2ray-config/main/Splitted-By-Protocol/vless.txt",
                "https://raw.githubusercontent.com/ksenkovsolo/HardVPN-bypass-WhiteLists-/refs/heads/main/vpn-lte/WHITELIST-ALL.txt",
                "https://raw.githubusercontent.com/AvenCores/goida-vpn-configs/refs/heads/main/githubmirror/1.txt ",
                "https://raw.githubusercontent.com/Firmfox/Proxify/refs/heads/main/v2ray_configs/mixed/subscription-1.txt",
                "https://raw.githubusercontent.com/Danialsamadi/v2go/refs/heads/main/AllConfigsSub.txt",
                "https://raw.githubusercontent.com/ksenkovsolo/HardVPN-bypass-WhiteLists-/refs/heads/main/vpn-lte/subscriptions/1sub.txt",
                "https://raw.githubusercontent.com/ksenkovsolo/HardVPN-bypass-WhiteLists-/refs/heads/main/vpn-lte/good_keys.txt",
                "https://raw.githubusercontent.com/ksenkovsolo/HardVPN-bypass-WhiteLists-/refs/heads/main/vpn-lte/best_keys.txt",
                "https://raw.githubusercontent.com/ksenkovsolo/HardVPN-bypass-WhiteLists-/refs/heads/main/vpn-lte/subscriptions/2sub.txt",
                "https://mifa.world/vless",
                "https://raw.githubusercontent.com/Firmfox/Proxify/refs/heads/main/v2ray_configs/mixed/subscription-2.txt",
                "https://gitflic.ru/project/sigil/my-new-cool-project/blob/raw?file=whitelist",
                "https://cloud.sayori.cc/https://raw.githubusercontent.com/mbelspb-gif/ffsfsfssdf/refs/heads/main/TG-swordware",
                "https://raw.githubusercontent.com/mbelspb-gif/ffsfsfssdf/refs/heads/main/TG-swordware",
                "https://raw.githubusercontent.com/kort0881/sbornik-vless/refs/heads/main/subs/ss_001.txt",
                "https://raw.githubusercontent.com/kort0881/sbornik-vless/refs/heads/main/subs/tuic_001.txt",   
                "https://raw.githubusercontent.com/kort0881/sbornik-vless/refs/heads/main/subs/ss_002.txt",
                "https://raw.githubusercontent.com/kort0881/sbornik-vless/refs/heads/main/subs/hysteria2_001.txt",
                "https://raw.githubusercontent.com/kort0881/sbornik-vless/refs/heads/main/subs/vless_001.txt",
                "https://raw.githubusercontent.com/kort0881/sbornik-vless/refs/heads/main/subs/vless_002.txt",
                "https://raw.githubusercontent.com/kort0881/sbornik-vless/refs/heads/main/subs/vless_003.txt",
                "https://raw.githubusercontent.com/kort0881/sbornik-vless/refs/heads/main/subs/vless_004.txt",
                "https://raw.githubusercontent.com/kort0881/sbornik-vless/refs/heads/main/subs/vless_005.txt",
                "https://raw.githubusercontent.com/kort0881/sbornik-vless/refs/heads/main/subs/vless_006.txt",
                "https://raw.githubusercontent.com/kort0881/sbornik-vless/refs/heads/main/subs/vless_007.txt",
                "https://raw.githubusercontent.com/kort0881/sbornik-vless/refs/heads/main/subs/vless_008.txt",
                "https://raw.githubusercontent.com/kort0881/sbornik-vless/refs/heads/main/subs/vless_009.txt",
                "https://raw.githubusercontent.com/kort0881/sbornik-vless/refs/heads/main/subs/vless_010.txt",
                "https://raw.githubusercontent.com/kort0881/sbornik-vless/refs/heads/main/subs/vless_011.txt",
                "https://raw.githubusercontent.com/kort0881/sbornik-vless/refs/heads/main/subs/vless_012.txt",
                "https://raw.githubusercontent.com/kort0881/sbornik-vless/refs/heads/main/subs/vmess_001.txt",
                "https://raw.githubusercontent.com/kort0881/sbornik-vless/refs/heads/main/subs/vmess_002.txt",
                "https://raw.githubusercontent.com/kort0881/sbornik-vless/refs/heads/main/subs/vmess_003.txt",
                "https://raw.githubusercontent.com/kort0881/sbornik-vless/refs/heads/main/subs/vmess_004.txt",
                "https://raw.githubusercontent.com/kort0881/sbornik-vless/refs/heads/main/subs/vmess_005.txt",
                "https://raw.githubusercontent.com/kort0881/sbornik-vless/refs/heads/main/subs/vmess_006.txt",
                "https://raw.githubusercontent.com/kort0881/sbornik-vless/refs/heads/main/subs/vmess_007.txt",
                "https://raw.githubusercontent.com/kort0881/sbornik-vless/refs/heads/main/subs/vmess_008.txt",
                "https://raw.githubusercontent.com/kort0881/sbornik-vless/refs/heads/main/subs/trojan_001.txt",
                "https://raw.githubusercontent.com/ssavnayt/AWCFG-CONFIG-LIST/refs/heads/main/Configs-all-country.txt",
                "https://raw.githubusercontent.com/ssavnayt/AWCFG-CONFIG-LIST/refs/heads/main/Configs-AUTO.txt",
                "https://raw.githubusercontent.com/V2RayRoot/V2Root-ConfigPilot/refs/heads/main/output/BestConfigs.txt",
                "https://raw.githubusercontent.com/sakha1370/OpenRay/refs/heads/main/output/all_valid_proxies.txt",
                "https://raw.githubusercontent.com/whoahaow/rjsxrd/refs/heads/main/githubmirror/default/1.txt",
                "https://raw.githubusercontent.com/whoahaow/rjsxrd/refs/heads/main/githubmirror/bypass-unsecure/bypass-unsecure-1.txt",
                "https://raw.githubusercontent.com/whoahaow/rjsxrd/refs/heads/main/githubmirror/bypass-unsecure/bypass-unsecure-2.txt",
                "https://raw.githubusercontent.com/whoahaow/rjsxrd/refs/heads/main/githubmirror/bypass-unsecure/bypass-unsecure-3.txt",
                "https://raw.githubusercontent.com/whoahaow/rjsxrd/refs/heads/main/githubmirror/bypass-unsecure/bypass-unsecure-4.txt",
                "https://raw.githubusercontent.com/whoahaow/rjsxrd/refs/heads/main/githubmirror/bypass-unsecure/bypass-unsecure-5.txt",
                "https://raw.githubusercontent.com/whoahaow/rjsxrd/refs/heads/main/githubmirror/bypass-unsecure/bypass-unsecure-6.txt",
                "https://raw.githubusercontent.com/whoahaow/rjsxrd/refs/heads/main/githubmirror/bypass-unsecure/bypass-unsecure-7.txt",
                "https://raw.githubusercontent.com/whoahaow/rjsxrd/refs/heads/main/githubmirror/bypass-unsecure/bypass-unsecure-8.txt",
                "https://raw.githubusercontent.com/whoahaow/rjsxrd/refs/heads/main/githubmirror/bypass-unsecure/bypass-unsecure-9.txt",
                "https://raw.githubusercontent.com/whoahaow/rjsxrd/refs/heads/main/githubmirror/bypass-unsecure/bypass-unsecure-10.txt",
                "https://raw.githubusercontent.com/whoahaow/rjsxrd/refs/heads/main/githubmirror/bypass-unsecure/bypass-unsecure-11.txt",
                "https://raw.githubusercontent.com/whoahaow/rjsxrd/refs/heads/main/githubmirror/bypass-unsecure/bypass-unsecure-12.txt",
                "https://raw.githubusercontent.com/whoahaow/rjsxrd/refs/heads/main/githubmirror/bypass-unsecure/bypass-unsecure-13.txt",
                "https://raw.githubusercontent.com/whoahaow/rjsxrd/refs/heads/main/githubmirror/bypass-unsecure/bypass-unsecure-14.txt",
                "https://raw.githubusercontent.com/whoahaow/rjsxrd/refs/heads/main/githubmirror/bypass-unsecure/bypass-unsecure-15.txt",
                "https://raw.githubusercontent.com/whoahaow/rjsxrd/refs/heads/main/githubmirror/bypass-unsecure/bypass-unsecure-16.txt",
                "https://raw.githubusercontent.com/whoahaow/rjsxrd/refs/heads/main/githubmirror/bypass-unsecure/bypass-unsecure-all.txt",
                "https://airlinkvpn.github.io/1.txt",
                "https://gist.githubusercontent.com/cvedcvpn/e7221e7f54944f2611c3c0460f3afd30/raw/90bbd746ef545e49ef7e408969c031ae211fdc03/CVEDCVPN",
                "https://raw.githubusercontent.com/Kirillo4ka/eavevpn-configs/refs/heads/main/BLACK_SS%2BAll_RUS.txt",
                "https://raw.githubusercontent.com/Kirillo4ka/eavevpn-configs/refs/heads/main/Vless-Reality-White-Lists-Rus-Mobile-2.txt",
                "https://raw.githubusercontent.com/Kirillo4ka/eavevpn-configs/refs/heads/main/Vless-Reality-White-Lists-Rus-Mobile.txt",
                "https://raw.githubusercontent.com/Kirillo4ka/eavevpn-configs/refs/heads/main/WHITE-CIDR-RU-checked.txt",
                "https://raw.githubusercontent.com/Kirillo4ka/eavevpn-configs/refs/heads/main/WHITE-SNI-RU-all.txt",
                "https://raw.githubusercontent.com/Kirillo4ka/eavevpn-configs/refs/heads/main/BLACK_VLESS_RUS.txt",
                 "https://raw.githubusercontent.com/Kirillo4ka/eavevpn-configs/refs/heads/main/BLACK_VLESS_RUS_mobile.txt",
                 "https://gistpad.com/raw/lumar-vpn-all-tg-reverse-engineer-s-basement",
                 "https://raw.githubusercontent.com/StealthNetVPN/StealthNet/refs/heads/main/StealthNetVPN",
                 "https://raw.githubusercontent.com/mmaksim9191/my-vpn-configs/refs/heads/main/configs/mobile-whitelist-1.txt",
                 "https://raw.githubusercontent.com/mmaksim9191/my-vpn-configs/refs/heads/main/configs/white-cidr-checked.txt",
                 "https://raw.githubusercontent.com/EtoNeYaProject/etoneyaproject.github.io/refs/heads/main/1",
                 "https://gitverse.ru/api/repos/bywarm/rser/raw/branch/master/selected.txt",
                 "https://rostunnel.vercel.app/mega.txt",
                 "https://raw.githubusercontent.com/tankist939-afk/Obhod-WL/refs/heads/main/Obhod%20WL",
                 "https://raw.githubusercontent.com/LimeHi/LimeVPNGenerator/main/Keys.txt",
                 "https://gist.githubusercontent.com/sevushyamamoto-stack/9341be7a058e132154d407d082a60fb1/raw/mysub.txt",
                 "https://raw.githubusercontent.com/ByeWhiteLists/ByeWhiteLists2/refs/heads/main/ByeWhiteLists2.txt",
                 "https://raw.githubusercontent.com/Rayan-Config/C-Sub/refs/heads/main/configs/proxy.txt",
                 "https://raw.githubusercontent.com/prominbro/KfWL/refs/heads/main/KfWL.txt",
                 "https://raw.githubusercontent.com/prominbro/KfWL/refs/heads/main/KfWLcheck.txt",
                 "https://raw.githubusercontent.com/amindzlvess-boop/SlashVPN/refs/heads/main/vpn.txt",
                 "https://raw.githubusercontent.com/EtoNeYaProject/etoneyaproject.github.io/refs/heads/main/gemini",
                 "https://raw.githubusercontent.com/EtoNeYaProject/etoneyaproject.github.io/refs/heads/main/youtube",
                 "https://raw.githubusercontent.com/EtoNeYaProject/etoneyaproject.github.io/refs/heads/main/ytm",
                 "https://raw.githubusercontent.com/EtoNeYaProject/etoneyaproject.github.io/refs/heads/main/other",
                 "https://raw.githubusercontent.com/hamedcode/port-based-v2ray-configs/main/sub/port_2053.txt",
                 "https://raw.githubusercontent.com/hamedcode/port-based-v2ray-configs/main/sub/port_8880.txt",
                 "https://raw.githubusercontent.com/hamedcode/port-based-v2ray-configs/main/sub/port_8443.txt",
                 "https://raw.githubusercontent.com/hamedcode/port-based-v2ray-configs/main/detailed/vless/80.txt",
                 "https://raw.githubusercontent.com/hamedcode/port-based-v2ray-configs/main/detailed/vless/2096.txt",
                 "https://raw.githubusercontent.com/hamedcode/port-based-v2ray-configs/main/sub/vless.txt",
                 "https://raw.githubusercontent.com/sevcator/5ubscrpt10n/main/protocols/vl.txt",
                 "https://raw.githubusercontent.com/sevcator/5ubscrpt10n/main/mini/m1n1-5ub-1.txt",
                 "https://raw.githubusercontent.com/sevcator/5ubscrpt10n/main/mini/m1n1-5ub-2.txt",
                 "https://raw.githubusercontent.com/sevcator/5ubscrpt10n/main/mini/m1n1-5ub-3.txt",
                 "https://raw.githubusercontent.com/sevcator/5ubscrpt10n/main/mini/m1n1-5ub-4.txt",
                 "https://raw.githubusercontent.com/sevcator/5ubscrpt10n/main/mini/m1n1-5ub-5.txt",
                 "https://raw.githubusercontent.com/sevcator/5ubscrpt10n/main/mini/m1n1-5ub-6.txt",
                 "https://raw.githubusercontent.com/sevcator/5ubscrpt10n/main/mini/m1n1-5ub-7.txt",
                 "https://raw.githubusercontent.com/sevcator/5ubscrpt10n/main/mini/m1n1-5ub-8.txt",
                 "https://raw.githubusercontent.com/sevcator/5ubscrpt10n/main/mini/m1n1-5ub-9.txt",
                 "https://raw.githubusercontent.com/sevcator/5ubscrpt10n/main/mini/m1n1-5ub-10.txt",
                 "https://raw.githubusercontent.com/sevcator/5ubscrpt10n/main/mini/m1n1-5ub-11.txt",
                 "https://raw.githubusercontent.com/sevcator/5ubscrpt10n/main/mini/m1n1-5ub-12.txt",
                 "https://raw.githubusercontent.com/sevcator/5ubscrpt10n/main/mini/m1n1-5ub-13.txt",
                 "https://raw.githubusercontent.com/sevcator/5ubscrpt10n/main/mini/m1n1-5ub-14.txt",
                 "https://raw.githubusercontent.com/sevcator/5ubscrpt10n/main/mini/m1n1-5ub-15.txt",
                 "https://raw.githubusercontent.com/sevcator/5ubscrpt10n/main/mini/m1n1-5ub-16.txt",
                 "https://raw.githubusercontent.com/sevcator/5ubscrpt10n/main/mini/m1n1-5ub-17.txt",
                 "https://raw.githubusercontent.com/sevcator/5ubscrpt10n/main/mini/m1n1-5ub-18.txt",
                 "https://raw.githubusercontent.com/sevcator/5ubscrpt10n/main/mini/m1n1-5ub-19.txt",
                 "https://raw.githubusercontent.com/sevcator/5ubscrpt10n/main/mini/m1n1-5ub-20.txt",
                 "https://raw.githubusercontent.com/sevcator/5ubscrpt10n/main/mini/m1n1-5ub-21.txt",
                 "https://raw.githubusercontent.com/sevcator/5ubscrpt10n/main/mini/m1n1-5ub-22.txt",
                 "https://raw.githubusercontent.com/sevcator/5ubscrpt10n/main/mini/m1n1-5ub-23.txt",
                 "https://raw.githubusercontent.com/sevcator/5ubscrpt10n/main/mini/m1n1-5ub-24.txt",
                 "https://raw.githubusercontent.com/sevcator/5ubscrpt10n/main/mini/m1n1-5ub-25.txt",
                 "https://raw.githubusercontent.com/sevcator/5ubscrpt10n/main/mini/m1n1-5ub-26.txt",
                 "https://raw.githubusercontent.com/sevcator/5ubscrpt10n/main/mini/m1n1-5ub-27.txt",
                 "https://raw.githubusercontent.com/sevcator/5ubscrpt10n/main/mini/m1n1-5ub-28.txt",
                 "https://raw.githubusercontent.com/sevcator/5ubscrpt10n/main/mini/m1n1-5ub-29.txt",
                 "https://raw.githubusercontent.com/sevcator/5ubscrpt10n/main/mini/m1n1-5ub-30.txt",
                 "https://raw.githubusercontent.com/sevcator/5ubscrpt10n/main/mini/m1n1-5ub-31.txt",
                 "https://raw.githubusercontent.com/sevcator/5ubscrpt10n/main/mini/m1n1-5ub-32.txt",
                 "https://raw.githubusercontent.com/sevcator/5ubscrpt10n/main/mini/m1n1-5ub-33.txt",
                 "https://raw.githubusercontent.com/sevcator/5ubscrpt10n/main/mini/m1n1-5ub-34.txt",
                 "https://raw.githubusercontent.com/sevcator/5ubscrpt10n/main/mini/m1n1-5ub-35.txt",
                 "https://raw.githubusercontent.com/sevcator/5ubscrpt10n/main/mini/m1n1-5ub-36.txt",
                 "https://subrostunnel.vercel.app/gen.txt",
                 "https://wlrus.lol/confs/blackl.txt",
                 "https://raw.githubusercontent.com/ALIILAPRO/v2rayNG-Config/main/server.txt",
                 "https://raw.githubusercontent.com/AB-84-AB/Free-Shadowsocks/refs/heads/main/Telegram-id-AB_841",
                 "https://raw.githubusercontent.com/47AgEnT-47/vpn-configs/refs/heads/main/configs.txt",
                 "https://gitverse.ru/api/repos/cid-uskoritel/cid-white/raw/branch/master/whitelist.txt",
                 "https://github.com/FLEXIY0/matryoshka-vpn/raw/main/configs/russia_whitelist.txt",
                 "https://raw.githubusercontent.com/Maskkost93/kizyak-vpn-4.0/refs/heads/main/kizyakbeta6.txt",
                 "https://raw.githubusercontent.com/Maskkost93/kizyak-vpn-4.0/refs/heads/main/kizyakbeta6BL.txt",
                "https://raw.githubusercontent.com/AvenCores/goida-vpn-configs/refs/heads/main/githubmirror/4.txt",
                "https://raw.githubusercontent.com/AvenCores/goida-vpn-configs/refs/heads/main/githubmirror/5.txt",
                "https://raw.githubusercontent.com/AvenCores/goida-vpn-configs/refs/heads/main/githubmirror/6.txt",
                "https://raw.githubusercontent.com/AvenCores/goida-vpn-configs/refs/heads/main/githubmirror/7.txt",
                "https://raw.githubusercontent.com/AvenCores/goida-vpn-configs/refs/heads/main/githubmirror/8.txt",
                "https://raw.githubusercontent.com/AvenCores/goida-vpn-configs/refs/heads/main/githubmirror/9.txt",
                "https://raw.githubusercontent.com/AvenCores/goida-vpn-configs/refs/heads/main/githubmirror/10.txt",
                "https://raw.githubusercontent.com/AvenCores/goida-vpn-configs/refs/heads/main/githubmirror/11.txt",
                "https://raw.githubusercontent.com/AvenCores/goida-vpn-configs/refs/heads/main/githubmirror/12.txt",
                "https://raw.githubusercontent.com/AvenCores/goida-vpn-configs/refs/heads/main/githubmirror/13.txt",
                "https://raw.githubusercontent.com/AvenCores/goida-vpn-configs/refs/heads/main/githubmirror/14.txt",
                "https://raw.githubusercontent.com/AvenCores/goida-vpn-configs/refs/heads/main/githubmirror/15.txt",
                "https://raw.githubusercontent.com/AvenCores/goida-vpn-configs/refs/heads/main/githubmirror/16.txt",
                "https://raw.githubusercontent.com/AvenCores/goida-vpn-configs/refs/heads/main/githubmirror/17.txt",
                "https://raw.githubusercontent.com/AvenCores/goida-vpn-configs/refs/heads/main/githubmirror/18.txt",
                "https://raw.githubusercontent.com/AvenCores/goida-vpn-configs/refs/heads/main/githubmirror/19.txt",
                "https://raw.githubusercontent.com/AvenCores/goida-vpn-configs/refs/heads/main/githubmirror/20.txt",
                "https://raw.githubusercontent.com/AvenCores/goida-vpn-configs/refs/heads/main/githubmirror/21.txt",
                "https://raw.githubusercontent.com/AvenCores/goida-vpn-configs/refs/heads/main/githubmirror/22.txt",
                "https://raw.githubusercontent.com/AvenCores/goida-vpn-configs/refs/heads/main/githubmirror/23.txt",
                "https://raw.githubusercontent.com/AvenCores/goida-vpn-configs/refs/heads/main/githubmirror/24.txt",
                "https://raw.githubusercontent.com/AvenCores/goida-vpn-configs/refs/heads/main/githubmirror/25.txt",
                "https://raw.githubusercontent.com/AvenCores/goida-vpn-configs/refs/heads/main/githubmirror/26.txt",
                "https://raw.githubusercontent.com/LowiKLive/BypassWhitelistRu/refs/heads/main/WhiteList-Bypass_Ru.txt",
                "https://raw.githubusercontent.com/zieng2/wl/main/vless_universal.txt",
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
                "https://raw.githubusercontent.com/VPN-cat/VPN/refs/heads/main/configs/VPN-cat",
                "https://raw.githubusercontent.com/VPN-cat/VPN/refs/heads/main/configs/VPN-cat-top-25",
                "https://raw.githubusercontent.com/VPN-cat/VPN/refs/heads/main/configs/VPN-cat-top-100",
                "https://raw.githubusercontent.com/zieng2/wl/main/vless_lite.txt",
                "https://raw.githubusercontent.com/SilentGhostCodes/WhiteListVpn/refs/heads/main/BlackList.txt",
                "https://raw.githubusercontent.com/Farid-Karimi/Config-Collector/main/trojan_iran.txt",
                "https://raw.githubusercontent.com/Epodonios/v2ray-configs/refs/heads/main/Sub44.txt",
                "https://raw.githubusercontent.com/Epodonios/v2ray-configs/refs/heads/main/Sub45.txt",
                "https://raw.githubusercontent.com/Epodonios/v2ray-configs/refs/heads/main/Sub46.txt",
                "https://raw.githubusercontent.com/Epodonios/v2ray-configs/refs/heads/main/Sub47.txt",
                "https://raw.githubusercontent.com/Epodonios/v2ray-configs/refs/heads/main/Sub48.txt",
                "https://raw.githubusercontent.com/Epodonios/v2ray-configs/refs/heads/main/Sub49.txt",
                "https://raw.githubusercontent.com/Epodonios/v2ray-configs/refs/heads/main/Sub50.txt",
                "https://raw.githubusercontent.com/Epodonios/v2ray-configs/refs/heads/main/Sub51.txt",
                "https://raw.githubusercontent.com/Epodonios/v2ray-configs/refs/heads/main/Sub52.txt",
                "https://raw.githubusercontent.com/Epodonios/v2ray-configs/refs/heads/main/Sub53.txt",
                "https://raw.githubusercontent.com/AvenCores/goida-vpn-configs/refs/heads/main/githubmirror/3.txt"
                "https://raw.githubusercontent.com/parvinxs/Submahsanetxsparvin/refs/heads/main/Sub.mahsa.xsparvin",
                "https://cdn.jsdelivr.net/gh/xiaoji235/airport-free/v2ray.txt",
                "https://raw.githubusercontent.com/vsevjik/OBSpiskov/refs/heads/main/wwh",
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
                "https://raw.githubusercontent.com/whoahaow/rjsxrd/refs/heads/main/githubmirror/bypass/bypass-1.txt",
                "https://raw.githubusercontent.com/whoahaow/rjsxrd/refs/heads/main/githubmirror/bypass/bypass-2.txt",
                "https://raw.githubusercontent.com/whoahaow/rjsxrd/refs/heads/main/githubmirror/bypass/bypass-3.txt",
                "https://raw.githubusercontent.com/whoahaow/rjsxrd/refs/heads/main/githubmirror/bypass/bypass-4.txt",
                "https://raw.githubusercontent.com/whoahaow/rjsxrd/refs/heads/main/githubmirror/bypass/bypass-5.txt",
                "https://raw.githubusercontent.com/whoahaow/rjsxrd/refs/heads/main/githubmirror/bypass/bypass-6.txt",
            ]


CFG = Config()

# Глобальный семафор — ограничивает суммарное кол-во Xray
_global_semaphore: threading.Semaphore = None

# Реальный IP машины (устанавливается один раз при старте)
_real_ip: Optional[str] = None

# Атомарный счётчик портов без коллизий
_port_counter = 0
_port_lock = threading.Lock()


def alloc_port() -> int:
    global _port_counter
    with _port_lock:
        port = CFG.SOCKS_PORT_START + (_port_counter % CFG.SOCKS_PORT_RANGE)
        _port_counter += 1
    return port


# ==================== XRAY ====================
class XrayManager:
    def __init__(self, config_path: str, port: int):
        self.config_path = config_path
        self.port = port
        self.process = None

    def start(self) -> bool:
        try:
            if not os.path.exists(CFG.XRAY_PATH):
                return False
            self.process = subprocess.Popen(
                [CFG.XRAY_PATH, "run", "-config", self.config_path],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                preexec_fn=os.setsid,
            )
            time.sleep(CFG.XRAY_STARTUP_WAIT)
            return self.process.poll() is None
        except:
            return False

    def stop(self):
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


# ==================== ПАРСЕРЫ ====================
def create_xray_config(key: str, port: int) -> Optional[dict]:
    config = {
        "log": {"loglevel": "none"},
        "inbounds": [{"port": port, "protocol": "socks",
                      "settings": {"auth": "noauth", "udp": True}}],
        "outbounds": [{"protocol": "freedom", "settings": {}}],
    }
    try:
        if   key.startswith("vless://"):     outbound = _parse_vless(key)
        elif key.startswith("vmess://"):     outbound = _parse_vmess(key)
        elif key.startswith("trojan://"):    outbound = _parse_trojan(key)
        elif key.startswith("ss://"):        outbound = _parse_ss(key)
        elif key.startswith("hysteria2://"): outbound = _parse_hy2(key)
        else: return None
        if outbound:
            config["outbounds"].insert(0, outbound)
            return config
    except:
        pass
    return None


def _parse_vless(key: str) -> Optional[dict]:
    key = key.replace("vless://", "")
    if "@" not in key: return None
    uuid, rest = key.split("@", 1)
    server_port, _, tail = rest.partition("?")
    params, _, _ = tail.partition("#")
    if ":" not in server_port: return None
    server, port = server_port.rsplit(":", 1)
    q = parse_qs(params)
    ob = {
        "protocol": "vless",
        "settings": {"vnext": [{"address": server, "port": int(port),
                                 "users": [{"id": uuid, "encryption": "none"}]}]},
        "streamSettings": {"network": q.get("type", ["tcp"])[0]},
    }
    sec = q.get("security", ["none"])[0]
    ob["streamSettings"]["security"] = sec
    if sec in ("tls", "reality"):
        ts = {}
        if "sni" in q: ts["serverName"] = q["sni"][0]
        if sec == "reality":
            ts["show"] = False
            for k2, qk in [("publicKey","pbk"),("shortId","sid"),("fingerprint","fp")]:
                if qk in q: ts[k2] = q[qk][0]
            if "spx" in q: ts["spiderX"] = unquote(q["spx"][0])
            ob["streamSettings"]["realitySettings"] = ts
        else:
            ob["streamSettings"]["tlsSettings"] = ts
    net = ob["streamSettings"]["network"]
    if net == "ws":
        ws = {}
        if "path" in q: ws["path"] = unquote(q["path"][0])
        if "host" in q: ws["headers"] = {"Host": q["host"][0]}
        ob["streamSettings"]["wsSettings"] = ws
    elif net == "grpc":
        grpc = {}
        if "serviceName" in q: grpc["serviceName"] = q["serviceName"][0]
        ob["streamSettings"]["grpcSettings"] = grpc
    if "flow" in q:
        ob["settings"]["vnext"][0]["users"][0]["flow"] = q["flow"][0]
    return ob


def _parse_vmess(key: str) -> Optional[dict]:
    raw = key.replace("vmess://", "")
    raw += "=" * (4 - len(raw) % 4)
    try: v = json.loads(base64.b64decode(raw).decode("utf-8"))
    except: return None
    ob = {
        "protocol": "vmess",
        "settings": {"vnext": [{"address": v.get("add",""), "port": int(v.get("port",443)),
                                 "users": [{"id": v.get("id",""), "alterId": int(v.get("aid",0)),
                                            "security": v.get("scy","auto")}]}]},
        "streamSettings": {"network": v.get("net","tcp")},
    }
    if v.get("tls") == "tls":
        ob["streamSettings"]["security"] = "tls"
        ts = {}
        if v.get("sni"): ts["serverName"] = v["sni"]
        ob["streamSettings"]["tlsSettings"] = ts
    if ob["streamSettings"]["network"] == "ws":
        ws = {}
        if v.get("path"): ws["path"] = v["path"]
        if v.get("host"): ws["headers"] = {"Host": v["host"]}
        ob["streamSettings"]["wsSettings"] = ws
    return ob


def _parse_trojan(key: str) -> Optional[dict]:
    key = key.replace("trojan://", "")
    if "@" not in key: return None
    pwd, rest = key.split("@", 1)
    sp, _, tail = rest.partition("?")
    params, _, _ = tail.partition("#")
    if ":" not in sp: return None
    server, port = sp.rsplit(":", 1)
    q = parse_qs(params)
    ob = {
        "protocol": "trojan",
        "settings": {"servers": [{"address": server, "port": int(port), "password": pwd}]},
        "streamSettings": {"network": q.get("type",["tcp"])[0], "security": "tls"},
    }
    ts = {}
    if "sni" in q: ts["serverName"] = q["sni"][0]
    ob["streamSettings"]["tlsSettings"] = ts
    return ob


def _parse_ss(key: str) -> Optional[dict]:
    key = key.replace("ss://", "")
    try:
        if "@" in key:
            enc, sp = key.split("@", 1)
            enc += "=" * (4 - len(enc) % 4)
            method, pwd = base64.b64decode(enc).decode("utf-8").split(":", 1)
        else:
            key += "=" * (4 - len(key) % 4)
            dec = base64.b64decode(key).decode("utf-8")
            if "@" not in dec: return None
            mp, sp = dec.split("@", 1)
            method, pwd = mp.split(":", 1)
        sp = sp.split("#")[0]
        server, port = sp.rsplit(":", 1)
        return {"protocol": "shadowsocks",
                "settings": {"servers": [{"address": server, "port": int(port),
                                          "method": method, "password": pwd}]}}
    except: return None


def _parse_hy2(key: str) -> Optional[dict]:
    key = key.replace("hysteria2://", "")
    if "@" not in key: return None
    auth, rest = key.split("@", 1)
    sp, _, tail = rest.partition("?")
    params, _, _ = tail.partition("#")
    if ":" not in sp: return None
    server, port = sp.rsplit(":", 1)
    q = parse_qs(params)
    user, pwd = auth.split(":", 1) if ":" in auth else ("", auth)
    ob = {"protocol": "hysteria2",
          "settings": {"servers": [{"address": server, "port": int(port), "password": pwd}]}}
    s = ob["settings"]["servers"][0]
    if user: s["auth_str"] = user
    if q.get("insecure",["0"])[0] == "1": s["insecure"] = True
    if "sni" in q: s["sni"] = q["sni"][0]
    return ob


# ==================== SOCKS / CURL ====================
def check_socks_port(port: int, timeout: int = 3) -> bool:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        ok = s.connect_ex(("127.0.0.1", port)) == 0
        s.close()
        return ok
    except:
        return False


def curl_check(port: int, url: str) -> Tuple[bool, float]:
    try:
        t0 = time.time()
        r = subprocess.run(
            ["curl", "-x", f"socks5h://127.0.0.1:{port}",
             "-m", str(CFG.REQUEST_TIMEOUT),
             "--connect-timeout", str(CFG.CONNECTION_TIMEOUT),
             "-s", "-o", "/dev/null", "-w", "%{http_code}",
             url],
            capture_output=True, timeout=CFG.REQUEST_TIMEOUT + 2,
        )
        elapsed = time.time() - t0
        code = r.stdout.decode().strip()
        return code in ("200","204","301","302"), elapsed
    except:
        return False, float(CFG.REQUEST_TIMEOUT)


def get_real_ip() -> Optional[str]:
    """Получить реальный IP машины (без прокси). Вызывается один раз при старте."""
    services = [
        "https://api.ipify.org",
        "https://ifconfig.me/ip",
        "https://api4.my-ip.io/ip",
        "https://ipv4.icanhazip.com",
    ]
    for url in services:
        try:
            r = requests.get(url, timeout=5)
            if r.status_code == 200:
                ip = r.text.strip()
                if ip and len(ip) < 50 and "." in ip:
                    return ip
        except:
            continue
    return None


# Запасные сервисы для проверки IP (если один заблокирует при массовых запросах)
IP_CHECK_URLS = [
    "https://ipinfo.io/ip",
    "https://api.ipify.org",
    "https://ifconfig.me/ip",
]


def get_proxy_ip(port: int) -> Optional[str]:
    """Получить IP через прокси (socks5h). Пробует сервисы по очереди, останавливается на первом успешном.
    Валидирует ответ — настоящий IP короткий и содержит точки, не HTML-страница ошибки."""
    for url in IP_CHECK_URLS:
        try:
            r = subprocess.run(
                ["curl", "-x", f"socks5h://127.0.0.1:{port}",
                 "-m", "4", "--connect-timeout", "4",
                 "-s", url],
                capture_output=True, timeout=6,
            )
            ip = r.stdout.decode().strip()
            if ip and len(ip) < 50 and "." in ip:
                return ip
        except:
            continue
    return None


# ==================== БЕЗОПАСНОСТЬ ====================
def quick_security_check(key: str) -> Tuple[bool, str]:
    for p in ("exec=","command=","shell=","javascript:","eval("):
        if p in key.lower():
            return False, f"вредоносный параметр: {p}"
    if key.startswith("vmess://") and "scy=none" in key.lower():
        return False, "VMess без шифрования"
    return True, "OK"


# ==================== ОПРЕДЕЛЕНИЕ ТИПА КЛЮЧА ====================
def _is_ru_cidr(ip: str) -> bool:
    return any(ip.startswith(p) for p in (
        "5.","31.","37.","46.","62.","77.","78.","79.","80.","81.","82.","83.",
        "84.","85.","87.","88.","89.","90.","91.","92.","93.","94.","95.","109.",
        "141.","178.","185.","188.","194.","195.","212.","213.","217.",
    ))


def _is_ru_domain(d: str) -> bool:
    d = d.lower()
    return any(k in d for k in (".ru",".рф","vk.com","yandex","mail.ru","gosuslugi",
                                 "sberbank","tinkoff","vtb","ozon","wildberries"))


def _has_white_marker(key: str) -> bool:
    kl = key.lower()
    return any(m in kl for m in ("white","whitelist","bypass","обход","белый",
                                   "россия","russia","mobile","cable","ru-"))


def determine_key_type(key: str, port: int) -> Tuple[str, str]:
    """
    Определяет тип ключа (white/universal/none).

    Логика:
    1. Проверка что SOCKS-порт открыт
    2. Тест зарубежных заблокированных сайтов — если отвечают, туннель реальный
    3. Тест российских сайтов — если отвечают, проверяем IP (трафик идёт через прокси?)
    4. Если IP совпадает с реальным → "none" (трафик мимо прокси)
    5. Если ничего не отвечает → "none"
    """
    if not check_socks_port(port):
        return "none", "порт не открыт"

    # ── Тест зарубежных заблокированных сайтов ──
    # Они заблокированы в РФ без VPN — если открылись, туннель 100% работает
    for site in CFG.FOREIGN_TEST_SITES:
        ok, t = curl_check(port, site)
        if ok:
            return "universal", f"Зарубеж OK ({t:.1f}s)"

    # ── Тест российских сайтов ──
    # Они доступны без VPN, поэтому проверяем IP — реально ли трафик через прокси
    for site in CFG.RUSSIAN_TEST_SITES:
        ok, t = curl_check(port, site)
        if ok:
            global _real_ip
            if _real_ip:
                proxy_ip = get_proxy_ip(port)
                if proxy_ip and proxy_ip == _real_ip:
                    return "none", f"IP не изменился — трафик мимо прокси"
            return "white", f"только РФ ({t:.1f}s)"

    return "none", "ничего не отвечает"


# ==================== ПРОВЕРКА ОДНОГО КЛЮЧА ====================
def check_single_key(key: str, port: int) -> Tuple[bool, str, Optional[str], str, str, str]:
    ok, msg = quick_security_check(key)
    if not ok:
        return False, "Безопасность", None, "none", msg, ""

    config = create_xray_config(key, port)
    if not config:
        return False, "Ошибка парсинга", None, "none", "", ""

    with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
        json.dump(config, f)
        cfg_path = f.name

    xray = XrayManager(cfg_path, port)
    try:
        if not xray.start():
            return False, "Xray не запустился", None, "none", "", ""
        ktype, details = determine_key_type(key, port)
        if ktype == "none":
            return False, "Не работает", None, "none", details, ""
        label = "Белый список" if ktype == "white" else "Универсальный"
        country_code, country_flag = get_country_with_flag(key)
        return True, label, key, ktype, details, country_flag
    except Exception as e:
        return False, "Ошибка", None, "none", str(e)[:40], ""
    finally:
        xray.stop()
        try: os.unlink(cfg_path)
        except: pass


# ==================== ЗАГРУЗКА ПОДПИСКИ ====================
PREFIXES = ("vless://","vmess://","trojan://","ss://","hysteria2://")


def fetch_keys(url: str) -> List[str]:
    try:
        parsed = urlparse(url)
        if parsed.netloc == "translate.yandex.ru":
            orig = parse_qs(parsed.query).get("url",[None])[0]
            if orig: url = unquote(orig)

        headers = {"User-Agent": "Mozilla/5.0 (X11; Linux x86_64) Chrome/123",
                   "Accept": "text/plain,*/*"}
        for attempt in range(3):
            try:
                resp = requests.get(url, timeout=45, headers=headers, allow_redirects=True)
                resp.raise_for_status()
                break
            except:
                if attempt == 2: return []
                time.sleep(1)

        content = resp.text.strip()
        if not any(content.startswith(p) for p in PREFIXES):
            try:
                content += "=" * (4 - len(content) % 4)
                content = base64.b64decode(content).decode("utf-8")
            except: pass

        return [l.strip() for l in content.replace("\r\n","\n").replace("\r","\n").split("\n")
                if l.strip() and any(l.strip().startswith(p) for p in PREFIXES)]
    except:
        return []


# ==================== ОПРЕДЕЛЕНИЕ СТРАНЫ ====================
_ip_country_cache: Dict[str, str] = {}
_host_ip_cache:    Dict[str, str] = {}
_country_cache:    Dict[str, str] = {}

COUNTRY_NAMES_RU = {
    "RU":"Россия","NL":"Нидерланды","DE":"Германия","US":"США","GB":"Великобритания",
    "FR":"Франция","PL":"Польша","UA":"Украина","KZ":"Казахстан","TR":"Турция",
    "FI":"Финляндия","SE":"Швеция","LT":"Литва","LV":"Латвия","EE":"Эстония",
    "RO":"Румыния","HU":"Венгрия","CZ":"Чехия","AT":"Австрия","CH":"Швейцария",
    "IT":"Италия","ES":"Испания","SG":"Сингапур","JP":"Япония","HK":"Гонконг",
    "CA":"Канада","AU":"Австралия","AE":"ОАЭ","GE":"Грузия","AM":"Армения",
    "BY":"Беларусь","MD":"Молдова","IR":"Иран","IN":"Индия",
}


def extract_host_from_key(key: str) -> Optional[str]:
    try:
        host = ""
        for proto in ("vless://","trojan://","hysteria2://","vmess://","ss://"):
            if key.startswith(proto):
                if proto == "vmess://":
                    raw = key.replace("vmess://","")
                    raw += "=" * (4 - len(raw) % 4)
                    host = json.loads(base64.b64decode(raw).decode("utf-8")).get("add","")
                else:
                    rest = key.replace(proto,"").split("@",1)
                    part = rest[-1] if len(rest)>1 else rest[0]
                    host = part.split("?")[0].split("#")[0]
                    if ":" in host:
                        host = host.rsplit(":",1)[0]
                    if host.startswith("[") and "]" in host:
                        host = host[1:host.index("]")]
                break
        return host.strip() if host else None
    except:
        return None


def get_country_by_tld(host: str) -> Optional[str]:
    host_lower = host.lower()
    for tld, country in TLD_COUNTRY_MAP.items():
        if host_lower.endswith(tld):
            return country
    return None


def get_country_code(host: str) -> Optional[str]:
    if not host:
        return None

    if host in _host_ip_cache:
        ip = _host_ip_cache[host]
        if ip in _ip_country_cache:
            return _ip_country_cache[ip]

    try:
        ipaddress.ip_address(host)
        ip = host
    except ValueError:
        try:
            ip = socket.gethostbyname(host)
            _host_ip_cache[host] = ip
        except:
            return get_country_by_tld(host)

    if ip in _ip_country_cache:
        return _ip_country_cache[ip]

    for country, ranges in IP_COUNTRY_RANGES.items():
        if any(ip.startswith(prefix) for prefix in ranges):
            _ip_country_cache[ip] = country
            return country

    try:
        resp = requests.get(f"https://ipinfo.io/{ip}/json", timeout=3)
        if resp.status_code == 200:
            data = resp.json()
            country = data.get("country","").upper()
            if country and len(country) == 2:
                _ip_country_cache[ip] = country
                return country
    except:
        pass

    return None


def get_country_with_flag(key: str) -> Tuple[str, str]:
    host = extract_host_from_key(key)
    if not host:
        return ("", "UNKNOWN")

    country_code = get_country_code(host)

    if country_code:
        flag = COUNTRY_FLAGS.get(country_code, "")
        return (country_code, f"{flag}{country_code}")

    country_code = get_country_by_tld(host)
    if country_code:
        flag = COUNTRY_FLAGS.get(country_code, "")
        return (country_code, f"{flag}{country_code}")

    return ("", "UNKNOWN")


def get_country(key: str) -> str:
    try:
        host = extract_host_from_key(key)
        if not host: return ""
        if host in _country_cache: return _country_cache[host]
        ip = host
        if not re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", host):
            ip = socket.gethostbyname(host)
        resp = requests.get(f"https://ipinfo.io/{ip}/json", timeout=5)
        code = resp.json().get("country","").upper()
        name = COUNTRY_NAMES_RU.get(code, code)
        _country_cache[host] = name
        return name
    except:
        return ""


# ==================== ИМЕНОВАНИЕ ====================
_country_flags_cache: Dict[str, str] = {}


def rename_key(key: str, country_flag: str = "") -> str:
    base = key.split("#",1)[0].rstrip("#")
    if country_flag:
        label = f"Шкатулка запретов — {country_flag}"
    else:
        country = get_country(key)
        label = f"Шкатулка запретов — {country}" if country else "Шкатулка запретов"
    return f"{base}#{label}"


# ==================== ЯДРО: ПРОВЕРКА ПОДПИСКИ ====================
def check_subscription(
    sub_index: int,
    total_subs: int,
    url: str,
    keys: List[str],
    global_white: List[str],
    global_universal: List[str],
    stats: dict,
    stop_event: threading.Event,
) -> None:
    n = len(keys)
    workers = min(n, CFG.MAX_WORKERS_PER_SUB)
    short_url = url.rstrip("/").split("/")[-1][:45] or url[:45]

    print(f"\n{'─'*70}")
    print(f"📦 [{sub_index}/{total_subs}] {short_url}")
    print(f"   Ключей: {n} | Потоков: {workers}")

    sub_white = sub_universal = sub_failed = 0
    t0 = time.time()

    def _worker(key: str):
        if stop_event.is_set():
            return False, "Остановлено", None, "none", "", ""
        _global_semaphore.acquire()
        try:
            port = alloc_port()
            time.sleep(random.uniform(0, 0.03))
            return check_single_key(key, port)
        finally:
            _global_semaphore.release()

    with ThreadPoolExecutor(max_workers=workers) as ex:
        futures = {ex.submit(_worker, k): k for k in keys}
        checked = 0
        try:
            for fut in as_completed(futures):
                if stop_event.is_set():
                    break
                checked += 1
                try:
                    success, reason, wkey, ktype, details, country_flag = fut.result(timeout=CFG.TOTAL_TIMEOUT)
                except Exception:
                    sub_failed += 1
                    continue

                if success and wkey:
                    elapsed = time.time() - t0
                    speed = checked / elapsed * 60 if elapsed else 0
                    if country_flag and wkey:
                        _country_flags_cache[wkey] = country_flag
                    if ktype == "white":
                        global_white.append(wkey)
                        sub_white += 1
                        country_info = f" {country_flag}" if country_flag else ""
                        print(f"  🏳️  [{checked}/{n}]{country_info} {details}  "
                              f"(всего белых: {len(global_white)}, {speed:.0f}/мин)")
                    else:
                        global_universal.append(wkey)
                        sub_universal += 1
                        country_info = f" {country_flag}" if country_flag else ""
                        print(f"  🌍 [{checked}/{n}]{country_info} {details}  "
                              f"(всего универс: {len(global_universal)}, {speed:.0f}/мин)")
                else:
                    sub_failed += 1
        except KeyboardInterrupt:
            stop_event.set()
            for f in futures: f.cancel()

    elapsed = time.time() - t0
    speed = n / elapsed * 60 if elapsed else 0
    stats["total"]     += n
    stats["white"]     += sub_white
    stats["universal"] += sub_universal
    stats["failed"]    += sub_failed

    found = sub_white + sub_universal
    print(f"   ✅ Итог: {found}/{n} рабочих  "
          f"(🏳️ {sub_white} белых, 🌍 {sub_universal} универс) | "
          f"{speed:.0f} ключ/мин | {elapsed:.1f}s")


# ==================== СОХРАНЕНИЕ ====================
def save_keys(white_keys: List[str], universal_keys: List[str]):
    print(f"\n{'='*70}\nСОХРАНЕНИЕ\n{'='*70}")
    os.makedirs(CFG.RU_DIR,   exist_ok=True)
    os.makedirs(CFG.EURO_DIR, exist_ok=True)

    print("🔍 Добавляем флаги стран...")
    white_renamed = []
    for k in white_keys:
        flag = _country_flags_cache.get(k, "")
        white_renamed.append(rename_key(k, flag))

    universal_renamed = []
    for k in universal_keys:
        flag = _country_flags_cache.get(k, "")
        universal_renamed.append(rename_key(k, flag))

    if white_keys:
        p = os.path.join(CFG.RU_DIR, "ru_white.txt")
        with open(p, "w", encoding="utf-8") as f: f.write("\n".join(white_renamed))
        print(f"🏳️  {p}  ({len(white_keys)} ключей)")

    if universal_keys:
        p = os.path.join(CFG.EURO_DIR, "euro_universal.txt")
        with open(p, "w", encoding="utf-8") as f: f.write("\n".join(universal_renamed))
        print(f"🌍 {p}  ({len(universal_keys)} ключей)")

        p = os.path.join(CFG.EURO_DIR, "euro_black.txt")
        with open(p, "w", encoding="utf-8") as f: f.write("")

    subs = os.path.join(CFG.CHECKED_DIR, "subscriptions_list.txt")
    with open(subs, "w", encoding="utf-8") as f:
        f.write("=== 🇷🇺 РОССИЯ ===\n\n⚪ БЕЛЫЙ СПИСОК:\n"
                "https://raw.githubusercontent.com/Mihuil121/vpn-checker-backend-fox/main/checked/RU_Best/ru_white.txt\n\n"
                "=== 🇪🇺 ЕВРОПА ===\n\n⚫ ЧЕРНЫЙ СПИСОК:\n"
                "https://raw.githubusercontent.com/Mihuil121/vpn-checker-backend-fox/main/checked/My_Euro/euro_black.txt\n\n"
                "🔘 УНИВЕРСАЛЬНЫЕ:\n"
                "https://raw.githubusercontent.com/Mihuil121/vpn-checker-backend-fox/main/checked/My_Euro/euro_universal.txt\n")
    print(f"📋 {subs}")


# ==================== CLI ====================
def parse_args():
    p = argparse.ArgumentParser(
        description="VPN Checker v4.0 — умная проверка по подпискам",
        epilog="""
Примеры:
  python main_fast.py                              # все источники
  python main_fast.py --workers-per-sub 200        # больше потоков на подписку
  python main_fast.py --total-workers 400          # больше Xray одновременно
  python main_fast.py --sources URL1 URL2          # только эти подписки
"""
    )
    p.add_argument("--sources", nargs="*", default=None, metavar="URL")
    p.add_argument("--max-keys", type=int, default=None, metavar="N")
    p.add_argument("--workers-per-sub", type=int, default=None, metavar="N",
                   help=f"Макс потоков на одну подписку (по умолч. {CFG.MAX_WORKERS_PER_SUB})")
    p.add_argument("--total-workers", type=int, default=None, metavar="N",
                   help=f"Глобальный лимит Xray-процессов (по умолч. {CFG.MAX_TOTAL_WORKERS})")
    return p.parse_args()


# ==================== MAIN ====================
def main():
    global _global_semaphore
    args = parse_args()

    sources  = args.sources or CFG.SOURCES
    max_keys = args.max_keys or CFG.MAX_KEYS
    if args.workers_per_sub: CFG.MAX_WORKERS_PER_SUB = args.workers_per_sub
    if args.total_workers:   CFG.MAX_TOTAL_WORKERS   = args.total_workers

    _global_semaphore = threading.Semaphore(CFG.MAX_TOTAL_WORKERS)

    print(f"\n{'='*70}")
    print(" VPN Checker v4.0 — УМНАЯ ПРОВЕРКА ПО ПОДПИСКАМ")
    print(f"{'='*70}")
    print(f"  Потоков на подписку: до {CFG.MAX_WORKERS_PER_SUB}")
    print(f"  Глобальный лимит Xray: {CFG.MAX_TOTAL_WORKERS}")
    print(f"  Startup: {CFG.XRAY_STARTUP_WAIT}s | Timeout: {CFG.REQUEST_TIMEOUT}s")

    # Получаем реальный IP машины один раз при старте
    global _real_ip
    _real_ip = "109.110.91.167"
    print(f"  🌐 Реальный IP: {_real_ip}")

    if not os.path.exists(CFG.XRAY_PATH):
        print(f"\n❌ Xray не найден: {CFG.XRAY_PATH}")
        return

    if not sources:
        print("\n❌ Нет источников. Добавь ссылки в CFG.SOURCES или передай через --sources")
        return

    # ── ШАГ 1: Анализ всех подписок ─────────────────────────────────────
    print(f"\n{'='*70}")
    print(f"📊 АНАЛИЗ ПОДПИСОК  ({len(sources)} источников)")
    print(f"{'='*70}")

    sub_data: List[Tuple[str, List[str]]] = []
    seen:     set = set()
    total_keys = 0

    for url in sources:
        raw_keys = fetch_keys(url)
        uniq = []
        for k in raw_keys:
            if k not in seen:
                seen.add(k)
                uniq.append(k)
        if total_keys + len(uniq) > max_keys:
            uniq = uniq[:max_keys - total_keys]

        short = url.rstrip("/").split("/")[-1][:45] or url[:45]
        if uniq:
            sub_data.append((url, uniq))
            total_keys += len(uniq)
            w = min(len(uniq), CFG.MAX_WORKERS_PER_SUB)
            print(f"  ✅ {len(uniq):>6} ключей → {w:>3} потоков  {short}")
        else:
            print(f"  ❌      0                    {short}")

        if total_keys >= max_keys:
            break

    # Сортируем: сначала большие подписки
    sub_data.sort(key=lambda x: len(x[1]), reverse=True)

    print(f"\n  📦 Подписок: {len(sub_data)}")
    print(f"  🔑 Уникальных ключей: {total_keys}")
    print(f"\n  Топ-5 по размеру:")
    for url, keys in sub_data[:5]:
        short = url.rstrip("/").split("/")[-1][:50]
        print(f"    {len(keys):>6} ключей  {short}")

    # ── ШАГ 2: Проверка ─────────────────────────────────────────────────
    print(f"\n{'='*70}")
    print("🚀 НАЧИНАЕМ ПРОВЕРКУ")
    print(f"{'='*70}")

    white_keys:     List[str] = []
    universal_keys: List[str] = []
    stats      = {"total": 0, "white": 0, "universal": 0, "failed": 0}
    stop_event = threading.Event()
    t_global   = time.time()

    try:
        for i, (url, keys) in enumerate(sub_data, 1):
            if stop_event.is_set():
                break
            check_subscription(i, len(sub_data), url, keys,
                                white_keys, universal_keys, stats, stop_event)
            elapsed = time.time() - t_global
            speed = stats["total"] / elapsed * 60 if elapsed else 0
            print(f"   📈 Общий итог: 🏳️ {stats['white']} | 🌍 {stats['universal']} | "
                  f"{speed:.0f} ключ/мин | осталось подписок: {len(sub_data)-i}")

    except KeyboardInterrupt:
        print("\n\n⚠️  Ctrl+C — сохраняю...")
        stop_event.set()

    # ── ШАГ 3: Финал ────────────────────────────────────────────────────
    elapsed = time.time() - t_global
    print(f"\n{'='*70}")
    print("📊 ФИНАЛЬНЫЙ РЕЗУЛЬТАТ")
    print(f"{'='*70}")
    print(f"  🏳️  Белый список:  {stats['white']}")
    print(f"  🌍 Универсальные: {stats['universal']}")
    print(f"  ❌ Не работают:   {stats['failed']}")
    print(f"  ⏱️  Время:         {elapsed/60:.1f} мин")
    spd = stats['total'] / elapsed * 60 if elapsed else 0
    print(f"  ⚡ Скорость:       {spd:.0f} ключ/мин")
    print(f"{'='*70}")

    if white_keys or universal_keys:
        save_keys(white_keys, universal_keys)
    else:
        print("\n⚠️  Рабочих ключей не найдено")

    print("\n✅ ГОТОВО!\n")


if __name__ == "__main__":
    main()
