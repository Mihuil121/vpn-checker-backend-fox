#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
VPN Checker v4.0 - УМНАЯ ПРОВЕРКА ПО ПОДПИСКАМ

Новый алгоритм:
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
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Optional, Tuple, Dict
from dataclasses import dataclass
import signal
import threading
import argparse
from urllib.parse import urlparse, parse_qs, unquote
import base64

# ==================== КОНФИГУРАЦИЯ ====================
@dataclass
class Config:
    XRAY_PATH: str = "/home/misha/vpn-checker-backend-fox/Xray-linux-64/xray"

    CHECKED_DIR: str = "checked"
    RU_DIR:      str = "checked/RU_Best"
    EURO_DIR:    str = "checked/My_Euro"

    SOCKS_PORT_START: int = 20000
    SOCKS_PORT_RANGE: int = 10000   # порты 20000-29999

    XRAY_STARTUP_WAIT:  float = 1.0
    CONNECTION_TIMEOUT: int   = 5   # было 3 — многие не успевали подключиться
    REQUEST_TIMEOUT:    int   = 10  # было 6 — зарубеж часто таймаутил
    TOTAL_TIMEOUT:      int   = 35  # было 20

    # Макс потоков на одну подписку
    # Маленькая (< 50) → все ключи сразу; большая → не больше этого
    MAX_WORKERS_PER_SUB: int = 150

    # Жёсткий глобальный лимит одновременных Xray-процессов (RAM-защита)
    MAX_TOTAL_WORKERS: int = 300

    MAX_KEYS: int = 999999

    RUSSIAN_TEST_SITES: List[str] = None
    FOREIGN_TEST_SITES: List[str] = None
    SOURCES: List[str] = None

    def __post_init__(self):
        if self.RUSSIAN_TEST_SITES is None:
            self.RUSSIAN_TEST_SITES = [
                "https://vk.com",
                "https://yandex.ru",
                "https://mail.ru",
            ]
        if self.FOREIGN_TEST_SITES is None:
            self.FOREIGN_TEST_SITES = [
                "https://www.google.com",
                "https://www.youtube.com",
                "https://www.facebook.com",
            ]
        if self.SOURCES is None:
            self.SOURCES = [
                 "https://raw.githubusercontent.com/zieng2/wl/main/vless.txt",
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
                "https://raw.githubusercontent.com/zieng2/wl/main/vless_lite.txt#%D0%90%D0%B2%D1%82%D0%BE%D0%BE%D0%B1%D0%BD%D0%BE%D0%B2%D0%BB%D1%8F%D0%B5%D0%BC%D1%8B%D0%B9",
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

# ==================== БЕЗОПАСНОСТЬ ====================
def quick_security_check(key: str) -> Tuple[bool, str]:
    for p in ("exec=","command=","shell=","javascript:","eval("):
        if p in key.lower():
            return False, f"вредоносный параметр: {p}"
    if key.startswith("vmess://") and "scy=none" in key.lower():
        return False, "VMess без шифрования"
    return True, "OK"

# ==================== ТИП КЛЮЧА ====================
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
    if not check_socks_port(port):
        return "none", "порт не открыт"

    # Быстрые эвристики по содержимому ключа
    try:
        if "?" in key:
            q = parse_qs(key.split("?")[1].split("#")[0])
            sni = q.get("sni",[None])[0]
            if sni and _is_ru_domain(sni):
                ok, t = curl_check(port, CFG.RUSSIAN_TEST_SITES[0])
                if ok: return "white", f"SNI={sni} ({t:.1f}s)"
    except: pass

    try:
        if "@" in key:
            host = key.split("@")[1].split(":")[0].split("?")[0]
            if _is_ru_cidr(host):
                ok, t = curl_check(port, CFG.RUSSIAN_TEST_SITES[0])
                if ok: return "white", f"РФ IP {host} ({t:.1f}s)"
    except: pass

    if _has_white_marker(key):
        ok, t = curl_check(port, CFG.RUSSIAN_TEST_SITES[0])
        if ok: return "white", f"маркер РФ ({t:.1f}s)"

    # Полный тест РФ
    ru_ok, ru_t = False, 0.0
    for site in CFG.RUSSIAN_TEST_SITES:
        ok, t = curl_check(port, site)
        if ok:
            ru_ok, ru_t = True, t
            break
    if not ru_ok:
        return "none", "РФ недоступен"

    # Тест зарубеж
    for site in CFG.FOREIGN_TEST_SITES:
        ok, t = curl_check(port, site)
        if ok:
            return "universal", f"РФ+Зарубеж ({ru_t:.1f}s + {t:.1f}s)"

    return "white", f"только РФ ({ru_t:.1f}s)"

# ==================== ПРОВЕРКА ОДНОГО КЛЮЧА ====================
def check_single_key(key: str, port: int) -> Tuple[bool, str, Optional[str], str, str]:
    ok, msg = quick_security_check(key)
    if not ok:
        return False, "Безопасность", None, "none", msg

    config = create_xray_config(key, port)
    if not config:
        return False, "Ошибка парсинга", None, "none", ""

    with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
        json.dump(config, f)
        cfg_path = f.name

    xray = XrayManager(cfg_path, port)
    try:
        if not xray.start():
            return False, "Xray не запустился", None, "none", ""
        ktype, details = determine_key_type(key, port)
        if ktype == "none":
            return False, "Не работает", None, "none", details
        label = "Белый список" if ktype == "white" else "Универсальный"
        return True, label, key, ktype, details
    except Exception as e:
        return False, "Ошибка", None, "none", str(e)[:40]
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

# ==================== ИМЕНОВАНИЕ ====================
COUNTRY_NAMES_RU = {
    "RU":"Россия","NL":"Нидерланды","DE":"Германия","US":"США","GB":"Великобритания",
    "FR":"Франция","PL":"Польша","UA":"Украина","KZ":"Казахстан","TR":"Турция",
    "FI":"Финляндия","SE":"Швеция","LT":"Литва","LV":"Латвия","EE":"Эстония",
    "RO":"Румыния","HU":"Венгрия","CZ":"Чехия","AT":"Австрия","CH":"Швейцария",
    "IT":"Италия","ES":"Испания","SG":"Сингапур","JP":"Япония","HK":"Гонконг",
    "CA":"Канада","AU":"Австралия","AE":"ОАЭ","GE":"Грузия","AM":"Армения",
    "BY":"Беларусь","MD":"Молдова","IR":"Иран","IN":"Индия",
}
_country_cache: Dict[str, str] = {}

def get_country(key: str) -> str:
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
                    if ":" in host: host = host.rsplit(":",1)[0]
                break
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

def rename_key(key: str) -> str:
    base = key.split("#",1)[0].rstrip("#")
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
    # Пул = min(ключей, MAX_WORKERS_PER_SUB)
    # Маленькие подписки (3 ключа) → 3 потока → проверяются мгновенно
    workers = min(n, CFG.MAX_WORKERS_PER_SUB)
    short_url = url.rstrip("/").split("/")[-1][:45] or url[:45]

    print(f"\n{'─'*70}")
    print(f"📦 [{sub_index}/{total_subs}] {short_url}")
    print(f"   Ключей: {n} | Потоков: {workers}")

    sub_white = sub_universal = sub_failed = 0
    t0 = time.time()

    def _worker(key: str):
        if stop_event.is_set():
            return False, "Остановлено", None, "none", ""
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
                    success, reason, wkey, ktype, details = fut.result(timeout=CFG.TOTAL_TIMEOUT)
                except Exception:
                    sub_failed += 1
                    continue

                if success and wkey:
                    elapsed = time.time() - t0
                    speed = checked / elapsed * 60 if elapsed else 0
                    if ktype == "white":
                        global_white.append(wkey)
                        sub_white += 1
                        print(f"  🏳️  [{checked}/{n}] {details}  "
                              f"(всего белых: {len(global_white)}, {speed:.0f}/мин)")
                    else:
                        global_universal.append(wkey)
                        sub_universal += 1
                        print(f"  🌍 [{checked}/{n}] {details}  "
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
    os.makedirs(CFG.RU_DIR, exist_ok=True)
    os.makedirs(CFG.EURO_DIR, exist_ok=True)

    print("🔍 Определяем страны...")
    white_renamed     = [rename_key(k) for k in white_keys]
    universal_renamed = [rename_key(k) for k in universal_keys]

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

    sources   = args.sources or CFG.SOURCES
    max_keys  = args.max_keys or CFG.MAX_KEYS
    if args.workers_per_sub: CFG.MAX_WORKERS_PER_SUB = args.workers_per_sub
    if args.total_workers:   CFG.MAX_TOTAL_WORKERS   = args.total_workers

    _global_semaphore = threading.Semaphore(CFG.MAX_TOTAL_WORKERS)

    print(f"\n{'='*70}")
    print(" VPN Checker v4.0 — УМНАЯ ПРОВЕРКА ПО ПОДПИСКАМ")
    print(f"{'='*70}")
    print(f"  Потоков на подписку: до {CFG.MAX_WORKERS_PER_SUB}")
    print(f"  Глобальный лимит Xray: {CFG.MAX_TOTAL_WORKERS}")
    print(f"  Startup: {CFG.XRAY_STARTUP_WAIT}s | Timeout: {CFG.REQUEST_TIMEOUT}s")

    if not os.path.exists(CFG.XRAY_PATH):
        print(f"\n❌ Xray не найден: {CFG.XRAY_PATH}")
        return

    # ── ШАГ 1: Анализ всех подписок ─────────────────────────────────────
    print(f"\n{'='*70}")
    print(f"📊 АНАЛИЗ ПОДПИСОК  ({len(sources)} источников)")
    print(f"{'='*70}")

    sub_data: List[Tuple[str, List[str]]] = []
    seen: set = set()
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

    # Сортируем: сначала большие подписки → максимальная загрузка CPU
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
    stats = {"total": 0, "white": 0, "universal": 0, "failed": 0}
    stop_event = threading.Event()
    t_global = time.time()

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
