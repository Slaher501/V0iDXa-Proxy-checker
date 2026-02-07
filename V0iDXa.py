import re
import requests
import threading
import signal
import sys
import os
import random
import warnings
import time
import json
import sqlite3
import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
from colorama import Fore, Style, init
from datetime import datetime
from requests.packages.urllib3.exceptions import InsecureRequestWarning

# Initialize
init(autoreset=True)
warnings.simplefilter('ignore', InsecureRequestWarning)
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

# Globals
print_lock = threading.Lock()
stats = {
    "total": 0,
    "checked": 0,
    "socks5": 0,
    "socks4": 0,
    "http": 0,
    "dead": 0,
    "residential": 0,
    "datacenter": 0,
    "elite": 0,
    "anonymous": 0,
    "transparent": 0,
    "google_passed": 0,
    "ultra_fast": 0,
    "fast": 0,
    "medium": 0,
    "slow": 0,
    "blacklisted": 0,
    "ssl_supported": 0
}
stop_progress = False
proxy_cache = {}
working_proxies = []
PROXY_RE = re.compile(r'\d+\.\d+\.\d+\.\d+:\d+')
TIMEOUT = 2.5

USER_AGENTS = [
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
    'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0',
]

TEST_URLS = [
    "http://azenv.net/",
    "http://httpbin.org/ip",
    "http://ip-api.com/json",
]

BLACKLIST_CHECKERS = [
    "https://check.getipintel.net/check.php?ip={ip}",
    "http://multirbl.valli.org/lookup/{ip}.html",
]


def signal_handler(sig, frame):
    """Handle Ctrl+C interrupt"""
    global stop_progress
    stop_progress = True
    print(f"\n\n{Style.BRIGHT}{Fore.YELLOW}[!] Stopping...")
    print(f"{Fore.GREEN}[✓] Saved successfully!\n")
    sys.exit(0)


signal.signal(signal.SIGINT, signal_handler)


def clear_screen():
    """Clear terminal screen"""
    os.system('cls' if os.name == 'nt' else 'clear')


def get_existing_files():
    """Get list of existing proxy files"""
    return [f for f in os.listdir('.') if f.endswith('.txt') and os.path.isfile(f)]


def select_or_create_file():
    """Select existing file or create new one"""
    existing_files = get_existing_files()
    print(f"\n{Style.BRIGHT}{Fore.CYAN}{'=' * 70}")
    print(f"{Fore.YELLOW}                     FILE SELECTION")
    print(f"{Fore.CYAN}{'=' * 70}\n")

    if existing_files:
        print(f"{Fore.GREEN}Existing files:\n")
        for i, file in enumerate(existing_files, 1):
            print(f"  {Fore.WHITE}[{i}] {file.ljust(30)} {Fore.CYAN}({os.path.getsize(file) / 1024:.2f} KB)")
        print(f"\n  {Fore.YELLOW}[0] Create new file")

        try:
            choice = input(f"\n{Style.BRIGHT}{Fore.YELLOW}Select [0-{len(existing_files)}]: ").strip()
            if choice == "0" or choice == "":
                filename = input(f"{Fore.YELLOW}Filename (without .txt): ").strip()
                if not filename:
                    filename = f"proxies_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
                if not filename.endswith('.txt'):
                    filename += '.txt'
                return filename
            else:
                idx = int(choice) - 1
                if 0 <= idx < len(existing_files):
                    return existing_files[idx]
        except:
            pass
    else:
        filename = input(f"{Style.BRIGHT}{Fore.YELLOW}New filename (without .txt): ").strip()
        if not filename:
            filename = f"proxies_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        if not filename.endswith('.txt'):
            filename += '.txt'
        return filename

    return f"proxies_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"


# ==================== DATABASE FUNCTIONS ====================

def init_database():
    """Initialize SQLite database"""
    conn = sqlite3.connect('proxies.db')
    c = conn.cursor()

    c.execute('''
              CREATE TABLE IF NOT EXISTS proxies
              (
                  id
                  INTEGER
                  PRIMARY
                  KEY
                  AUTOINCREMENT,
                  ip
                  TEXT
                  NOT
                  NULL,
                  port
                  INTEGER
                  NOT
                  NULL,
                  protocol
                  TEXT
                  NOT
                  NULL,
                  country
                  TEXT,
                  country_code
                  TEXT,
                  city
                  TEXT,
                  isp
                  TEXT,
                  asn
                  TEXT,
                  type
                  TEXT,
                  speed_ms
                  INTEGER,
                  download_speed
                  REAL,
                  upload_speed
                  REAL,
                  speed_category
                  TEXT,
                  anonymity
                  TEXT,
                  google_test
                  TEXT,
                  ssl_support
                  TEXT,
                  blacklisted
                  INTEGER,
                  open_ports
                  TEXT,
                  first_seen
                  TIMESTAMP,
                  last_checked
                  TIMESTAMP,
                  status
                  TEXT,
                  UNIQUE
              (
                  ip,
                  port,
                  protocol
              )
                  )
              ''')

    c.execute('''
              CREATE TABLE IF NOT EXISTS scan_history
              (
                  id
                  INTEGER
                  PRIMARY
                  KEY
                  AUTOINCREMENT,
                  scan_date
                  TIMESTAMP,
                  total_checked
                  INTEGER,
                  total_live
                  INTEGER,
                  success_rate
                  REAL,
                  duration_seconds
                  INTEGER
              )
              ''')

    conn.commit()
    conn.close()
    print(f"{Fore.GREEN}[✓] Database initialized")


def save_to_database(proxy_info):
    """Save proxy to database"""
    try:
        conn = sqlite3.connect('proxies.db')
        c = conn.cursor()

        now = datetime.now().isoformat()

        c.execute('''
            INSERT OR REPLACE INTO proxies 
            (ip, port, protocol, country, country_code, city, isp, asn, type, 
             speed_ms, download_speed, upload_speed, speed_category, anonymity, 
             google_test, ssl_support, blacklisted, open_ports, 
             first_seen, last_checked, status)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            proxy_info.get('ip'),
            proxy_info.get('port'),
            proxy_info.get('protocol'),
            proxy_info.get('country', 'Unknown'),
            proxy_info.get('country_code', 'XX'),
            proxy_info.get('city', 'Unknown'),
            proxy_info.get('isp', 'Unknown'),
            proxy_info.get('asn', 'AS0'),
            proxy_info.get('type', 'DC'),
            proxy_info.get('speed_ms', 9999),
            proxy_info.get('download_speed', 0.0),
            proxy_info.get('upload_speed', 0.0),
            proxy_info.get('speed_category', 'UNKNOWN'),
            proxy_info.get('anonymity', 'UNKNOWN'),
            proxy_info.get('google_test', 'UNKNOWN'),
            proxy_info.get('ssl_support', 'UNKNOWN'),
            proxy_info.get('blacklisted', 0),
            proxy_info.get('open_ports', ''),
            now,
            now,
            'LIVE'
        ))

        conn.commit()
        conn.close()

    except Exception as e:
        pass


def save_scan_history(total_checked, total_live, duration):
    """Save scan history"""
    try:
        conn = sqlite3.connect('proxies.db')
        c = conn.cursor()

        success_rate = (total_live / total_checked * 100) if total_checked > 0 else 0

        c.execute('''
                  INSERT INTO scan_history (scan_date, total_checked, total_live, success_rate, duration_seconds)
                  VALUES (?, ?, ?, ?, ?)
                  ''', (datetime.now().isoformat(), total_checked, total_live, success_rate, duration))

        conn.commit()
        conn.close()
    except:
        pass


# ==================== ADVANCED TESTING FUNCTIONS ====================

def benchmark_speed(proxy, proto):
    """
    Benchmark download/upload speed
    Returns: dict with speeds and category
    """
    try:
        px = {"http": f"{proto}://{proxy}", "https": f"{proto}://{proxy}"}

        # Download test (1MB file)
        download_url = "http://speedtest.ftp.otenet.gr/files/test1Mb.db"
        start = time.time()
        r = requests.get(download_url, proxies=px, timeout=15, stream=True, verify=False)

        download_size = 0
        for chunk in r.iter_content(chunk_size=8192):
            download_size += len(chunk)
            if download_size > 1048576:  # 1MB
                break

        download_time = time.time() - start

        if download_time > 0:
            # Speed in Mbps
            download_speed = (download_size * 8) / (download_time * 1000000)

            # Categorize speed
            if download_speed > 10:
                category = "ULTRA"
            elif download_speed > 5:
                category = "FAST"
            elif download_speed > 1:
                category = "MEDIUM"
            else:
                category = "SLOW"

            return {
                'download_speed': round(download_speed, 2),
                'upload_speed': 0.0,  # Upload test can be added
                'category': category
            }
    except:
        pass

    return {
        'download_speed': 0.0,
        'upload_speed': 0.0,
        'category': 'UNKNOWN'
    }


def scan_open_ports(ip, common_ports=[21, 22, 23, 80, 443, 3128, 8080, 8888]):
    """
    Scan common ports
    Returns: list of open ports
    """
    open_ports = []

    for port in common_ports:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            result = sock.connect_ex((ip, port))
            if result == 0:
                open_ports.append(port)
            sock.close()
        except:
            continue

    return open_ports


def check_ssl_support(proxy, proto):
    """
    Check SSL/TLS support
    Returns: SSL version or NONE
    """
    try:
        px = {"http": f"{proto}://{proxy}", "https": f"{proto}://{proxy}"}

        r = requests.get(
            "https://www.howsmyssl.com/a/check",
            proxies=px,
            timeout=8,
            verify=False
        )

        if r.status_code == 200:
            data = r.json()
            tls_version = data.get('tls_version', 'UNKNOWN')
            return tls_version
    except:
        pass

    return "NONE"


def check_blacklist(ip):
    """
    Check if IP is blacklisted
    Returns: True if blacklisted, False otherwise
    """
    try:
        # Check with getipintel
        r = requests.get(
            f"https://check.getipintel.net/check.php?ip={ip}&contact=admin@example.com",
            timeout=5
        )

        if r.status_code == 200:
            score = float(r.text.strip())
            # Score > 0.95 = likely bad
            if score > 0.95:
                return True
    except:
        pass

    return False


def test_concurrent_connections(proxy, proto, num_connections=5):
    """
    Test if proxy supports multiple concurrent connections
    Returns: number of successful connections
    """
    successful = 0

    def single_connection():
        try:
            px = {"http": f"{proto}://{proxy}", "https": f"{proto}://{proxy}"}
            r = requests.get(
                random.choice(TEST_URLS),
                proxies=px,
                timeout=5,
                verify=False
            )
            return r.status_code == 200
        except:
            return False

    with ThreadPoolExecutor(max_workers=num_connections) as executor:
        futures = [executor.submit(single_connection) for _ in range(num_connections)]
        for future in as_completed(futures):
            if future.result():
                successful += 1

    return successful


def check_webrtc_leak(proxy, proto):
    """
    Check for WebRTC leak (basic check)
    Returns: LEAK or SECURE
    """
    try:
        px = {"http": f"{proto}://{proxy}", "https": f"{proto}://{proxy}"}

        # Use browserleaks API
        r = requests.get(
            "https://browserleaks.com/json/ip",
            proxies=px,
            timeout=8,
            verify=False
        )

        if r.status_code == 200:
            data = r.json()
            # Check if real IP is leaked in WebRTC
            if data.get('webrtc_ip'):
                return "LEAK"
            return "SECURE"
    except:
        pass

    return "UNKNOWN"


def check_anonymity_level(proxy, proto):
    """Check proxy anonymity level"""
    try:
        px = {"http": f"{proto}://{proxy}", "https": f"{proto}://{proxy}"}

        r = requests.get(
            "http://httpbin.org/headers",
            proxies=px,
            timeout=5,
            headers={'User-Agent': random.choice(USER_AGENTS)}
        )

        if r.status_code == 200:
            headers = r.json().get('headers', {})

            proxy_headers = [
                'X-Forwarded-For',
                'X-Real-Ip',
                'Via',
                'X-Proxy-Id',
                'Forwarded',
                'Client-Ip',
            ]

            detected_count = sum(1 for h in proxy_headers if h in headers)

            if detected_count == 0:
                return "ELITE"
            elif detected_count <= 2:
                return "ANON"
            else:
                return "TRANS"

    except:
        pass

    return "UNKNOWN"


def test_google_access(proxy, proto):
    """Test Google access"""
    try:
        px = {"http": f"{proto}://{proxy}", "https": f"{proto}://{proxy}"}

        r = requests.get(
            "https://www.google.com/search?q=test",
            proxies=px,
            timeout=8,
            headers={
                'User-Agent': random.choice(USER_AGENTS),
                'Accept-Language': 'en-US,en;q=0.9',
            },
            verify=False,
            allow_redirects=True
        )

        response_lower = r.text.lower()

        if 'captcha' in response_lower or '/sorry/' in r.url:
            return "CAPTCHA"
        elif r.status_code == 200 and ('search' in response_lower or 'results' in response_lower):
            return "PASS"
        elif r.status_code in [403, 429]:
            return "BLOCKED"

    except:
        pass

    return "FAIL"


def get_proxy_intelligence(ip, proto, port):
    """Get proxy geolocation and ISP info"""
    if ip in proxy_cache:
        return proxy_cache[ip]

    try:
        start_time = time.time()

        r = requests.get(
            f"http://ip-api.com/json/{ip}?fields=66846719",
            timeout=3,
            headers={'User-Agent': random.choice(USER_AGENTS)}
        )
        response_time = int((time.time() - start_time) * 1000)

        if r.status_code == 200:
            data = r.json()
            info = {
                'ip': ip,
                'port': port,
                'protocol': proto,
                'country': data.get('country', 'Unknown'),
                'country_code': data.get('countryCode', 'XX'),
                'city': data.get('city', 'Unknown'),
                'isp': data.get('isp', 'Unknown')[:30],
                'asn': data.get('as', 'Unknown').split()[0] if data.get('as') else 'AS0',
                'org': data.get('org', 'Unknown')[:25],
                'type': 'RES' if not data.get('hosting', True) else 'DC',
                'speed_ms': response_time,
                'latitude': data.get('lat', 0.0),
                'longitude': data.get('lon', 0.0),
            }
            proxy_cache[ip] = info
            return info
    except:
        pass

    return {
        'ip': ip,
        'port': port,
        'protocol': proto,
        'country': 'Unknown',
        'country_code': 'XX',
        'city': 'Unknown',
        'isp': 'Unknown',
        'asn': 'AS0',
        'type': 'DC',
        'speed_ms': 9999,
        'latitude': 0.0,
        'longitude': 0.0,
    }


# ==================== SCRAPING FUNCTIONS ====================

def auto_discover_proxy_sources():
    """Auto-discover new sources from GitHub"""
    print(f"{Fore.CYAN}[*] Discovering new sources from GitHub...")

    new_sources = []
    search_queries = [
        "proxy list raw",
        "socks5 list txt",
        "free proxies github"
    ]

    for query in search_queries:
        try:
            r = requests.get(
                f"https://api.github.com/search/code?q={query}+extension:txt",
                headers={'User-Agent': random.choice(USER_AGENTS)},
                timeout=10
            )

            if r.status_code == 200:
                results = r.json().get('items', [])

                for item in results[:5]:
                    raw_url = item.get('html_url', '').replace(
                        'github.com',
                        'raw.githubusercontent.com'
                    ).replace('/blob/', '/')

                    if raw_url and raw_url not in new_sources:
                        new_sources.append(raw_url)

        except:
            continue

    if new_sources:
        print(f"{Fore.GREEN}[✓] Discovered {len(new_sources)} new sources!")
    else:
        print(f"{Fore.YELLOW}[!] No new sources found")

    return new_sources


def scrape_with_rotation(url):
    """Scrape using working proxy rotation"""
    if not working_proxies:
        try:
            return requests.get(url, timeout=10, headers={'User-Agent': random.choice(USER_AGENTS)}, verify=False).text
        except:
            return ""

    proxy = random.choice(working_proxies)
    px = {"http": proxy, "https": proxy}

    try:
        r = requests.get(url, proxies=px, timeout=10, verify=False, headers={'User-Agent': random.choice(USER_AGENTS)})
        return r.text
    except:
        try:
            return requests.get(url, timeout=10, verify=False).text
        except:
            return ""


def scrape_proxies(limit, use_auto_discover=False, use_rotation=False):
    """Scrape proxies from sources"""
    sources = [
        "https://api.proxyscrape.com/v2/?request=displayproxies&protocol=all",
        "https://api.proxyscrape.com/v2/?request=displayproxies&protocol=socks5",
        "https://api.proxyscrape.com/v2/?request=displayproxies&protocol=socks4",
        "https://api.proxyscrape.com/v2/?request=displayproxies&protocol=http",
        "https://www.proxy-list.download/api/v1/get?type=socks5",
        "https://www.proxy-list.download/api/v1/get?type=socks4",
        "https://www.proxy-list.download/api/v1/get?type=http",
        "https://api.openproxylist.xyz/socks5.txt",
        "https://api.openproxylist.xyz/socks4.txt",
        "https://api.openproxylist.xyz/http.txt",
        "https://raw.githubusercontent.com/TheSpeedX/SOCKS-List/master/socks5.txt",
        "https://raw.githubusercontent.com/TheSpeedX/SOCKS-List/master/socks4.txt",
        "https://raw.githubusercontent.com/TheSpeedX/SOCKS-List/master/http.txt",
        "https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/socks5.txt",
        "https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/socks4.txt",
        "https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/http.txt",
        "https://raw.githubusercontent.com/jetkai/proxy-list/main/online-proxies/txt/proxies-socks5.txt",
        "https://raw.githubusercontent.com/jetkai/proxy-list/main/online-proxies/txt/proxies-socks4.txt",
        "https://raw.githubusercontent.com/jetkai/proxy-list/main/online-proxies/txt/proxies-http.txt",
        "https://raw.githubusercontent.com/mmpx12/proxy-list/master/socks5.txt",
        "https://raw.githubusercontent.com/mmpx12/proxy-list/master/http.txt",
        "https://raw.githubusercontent.com/hookzof/socks5_list/master/proxy.txt",
        "https://raw.githubusercontent.com/Zaeem20/FREE_PROXIES_LIST/master/socks5.txt",
        "https://raw.githubusercontent.com/Zaeem20/FREE_PROXIES_LIST/master/http.txt",
        "https://raw.githubusercontent.com/roosterkid/openproxylist/main/SOCKS5_RAW.txt",
        "https://raw.githubusercontent.com/sunny9577/proxy-scraper/master/proxies.txt",
        "https://raw.githubusercontent.com/vakhov/fresh-proxy-list/master/socks5.txt",
        "https://raw.githubusercontent.com/vakhov/fresh-proxy-list/master/http.txt",
    ]

    if use_auto_discover:
        new_sources = auto_discover_proxy_sources()
        sources.extend(new_sources)

    all_proxies = []
    print(f"{Style.BRIGHT}{Fore.CYAN}[*] Scraping from {len(sources)} sources...")

    def fetch(url):
        try:
            if use_rotation:
                text = scrape_with_rotation(url)
            else:
                r = requests.get(url, timeout=10, headers={'User-Agent': random.choice(USER_AGENTS)}, verify=False)
                text = r.text if r.status_code == 200 else ""

            return PROXY_RE.findall(text) if text else []
        except:
            return []

    with ThreadPoolExecutor(max_workers=30) as executor:
        futures = [executor.submit(fetch, url) for url in sources]
        for f in as_completed(futures):
            found = f.result()
            if found:
                all_proxies.extend(found)
                sys.stdout.write(f"{Fore.GREEN}█")
            else:
                sys.stdout.write(f"{Fore.RED}░")
            sys.stdout.flush()

    final = list(set(all_proxies))[:limit]
    print(f"\n\n{Fore.GREEN}[✓] Collected {len(final)} unique proxies\n")
    return final


# ==================== PROXY CHECKING ====================

def filter_dead_proxies(filename):
    """Re-check and remove dead proxies"""
    print(f"\n{Fore.CYAN}[*] Starting post-check validation...")
    if not os.path.exists(filename):
        return

    with open(filename, "r", encoding='utf-8') as f:
        proxies = [line.strip() for line in f if line.strip()]

    if not proxies:
        return

    print(f"{Fore.YELLOW}[*] Re-checking {len(proxies)} proxies...")
    live_list = []

    def re_check(p_line):
        try:
            if "://" in p_line:
                parts = p_line.split("://")
                proto = parts[0].split()[0] if " " in parts[0] else parts[0]
                addr = parts[1].split()[0] if " " in parts[1] else parts[1].split("|")[0].strip()
            else:
                parts = p_line.split()
                proto, addr = parts[0], f"{parts[1]}:{parts[2]}"

            px = {"http": f"{proto}://{addr}", "https": f"{proto}://{addr}"}
            r = requests.get(random.choice(TEST_URLS), proxies=px, timeout=TIMEOUT, verify=False)
            return p_line if r.status_code == 200 else None
        except:
            return None

    with ThreadPoolExecutor(max_workers=100) as executor:
        futures = [executor.submit(re_check, p) for p in proxies]
        for future in as_completed(futures):
            res = future.result()
            if res:
                live_list.append(res)

    with open(filename, "w", encoding='utf-8') as f:
        for p in live_list:
            f.write(p + "\n")

    print(f"{Fore.GREEN}[✓] Cleanup done! {len(live_list)} proxies remain active.")


def check_proxy_advanced(proxy, output_file, existing_set, proxychains_format,
                         enable_intelligence=True, enable_anonymity=False,
                         enable_google_test=False, enable_database=False,
                         enable_speed_test=False, enable_port_scan=False,
                         enable_ssl_check=False, enable_blacklist_check=False):
    """Advanced proxy checking with all features"""
    global working_proxies

    ip, port = proxy.split(":")
    protocols = ["socks5", "socks4", "http"]
    found_live = False

    for proto in protocols:
        try:
            px = {"http": f"{proto}://{proxy}", "https": f"{proto}://{proxy}"}
            start = time.time()
            r = requests.get(
                random.choice(TEST_URLS),
                proxies=px,
                timeout=TIMEOUT,
                headers={'User-Agent': random.choice(USER_AGENTS)},
                verify=False
            )
            response_time = int((time.time() - start) * 1000)

            if r.status_code == 200:
                intel = {'ip': ip, 'port': port, 'protocol': proto, 'speed_ms': response_time}

                # Get intelligence
                if enable_intelligence:
                    intel = get_proxy_intelligence(ip, proto, port)

                    with print_lock:
                        if intel['type'] == 'RES':
                            stats['residential'] += 1
                        else:
                            stats['datacenter'] += 1

                # Check anonymity
                if enable_anonymity:
                    anonymity = check_anonymity_level(proxy, proto)
                    intel['anonymity'] = anonymity

                    with print_lock:
                        if anonymity == "ELITE":
                            stats['elite'] += 1
                        elif anonymity == "ANON":
                            stats['anonymous'] += 1
                        elif anonymity == "TRANS":
                            stats['transparent'] += 1
                else:
                    intel['anonymity'] = 'UNKNOWN'

                # Test Google
                if enable_google_test:
                    google = test_google_access(proxy, proto)
                    intel['google_test'] = google

                    if google == "PASS":
                        with print_lock:
                            stats['google_passed'] += 1
                else:
                    intel['google_test'] = 'UNKNOWN'

                # Speed benchmark
                if enable_speed_test:
                    speed_data = benchmark_speed(proxy, proto)
                    intel.update(speed_data)

                    with print_lock:
                        category = speed_data.get('category', 'UNKNOWN')
                        if category == 'ULTRA':
                            stats['ultra_fast'] += 1
                        elif category == 'FAST':
                            stats['fast'] += 1
                        elif category == 'MEDIUM':
                            stats['medium'] += 1
                        elif category == 'SLOW':
                            stats['slow'] += 1
                else:
                    intel['download_speed'] = 0.0
                    intel['upload_speed'] = 0.0
                    intel['category'] = 'UNKNOWN'

                # Port scan
                if enable_port_scan:
                    open_ports = scan_open_ports(ip)
                    intel['open_ports'] = ','.join(map(str, open_ports))
                else:
                    intel['open_ports'] = ''

                # SSL check
                if enable_ssl_check:
                    ssl = check_ssl_support(proxy, proto)
                    intel['ssl_support'] = ssl

                    if ssl != 'NONE':
                        with print_lock:
                            stats['ssl_supported'] += 1
                else:
                    intel['ssl_support'] = 'UNKNOWN'

                # Blacklist check
                if enable_blacklist_check:
                    is_blacklisted = check_blacklist(ip)
                    intel['blacklisted'] = 1 if is_blacklisted else 0

                    if is_blacklisted:
                        with print_lock:
                            stats['blacklisted'] += 1
                else:
                    intel['blacklisted'] = 0

                # Save to database
                if enable_database:
                    save_to_database(intel)

                # Format output
                if proxychains_format:
                    line = f"{proto} {ip} {port}"
                    json_file = output_file.replace('.txt', '_intel.json')
                    try:
                        with open(json_file, 'a', encoding='utf-8') as jf:
                            json.dump(intel, jf, ensure_ascii=False)
                            jf.write('\n')
                    except:
                        pass
                else:
                    line = f"{proto}://{ip}:{port}"
                    if enable_intelligence:
                        line += f" | {intel.get('country_code', 'XX')} | {intel.get('isp', 'Unknown')[:15]} | {intel.get('type', 'DC')} | {intel.get('speed_ms', 9999)}ms"
                    if enable_anonymity:
                        line += f" | {intel.get('anonymity', 'UNK')}"
                    if enable_google_test:
                        line += f" | G:{intel.get('google_test', 'UNK')}"
                    if enable_speed_test:
                        line += f" | {intel.get('download_speed', 0.0)}Mbps | {intel.get('category', 'UNK')}"
                    if enable_ssl_check:
                        line += f" | SSL:{intel.get('ssl_support', 'UNK')}"
                    if enable_blacklist_check and intel.get('blacklisted'):
                        line += f" | {Fore.RED}BLACKLISTED{Fore.RESET}"

                # Print
                color = {
                    'socks5': Fore.MAGENTA,
                    'socks4': Fore.BLUE,
                    'http': Fore.GREEN
                }.get(proto, Fore.WHITE)

                with print_lock:
                    if line not in existing_set:
                        stats[proto] += 1
                        sys.stdout.write('\r' + ' ' * 200 + '\r')

                        output_str = f"{color}[✓] {proto.upper().ljust(6)} {Fore.WHITE}| {ip.ljust(15)}:{port.ljust(5)}"

                        if enable_intelligence:
                            type_color = Fore.CYAN if intel.get('type') == 'RES' else Fore.YELLOW
                            output_str += f" | {Fore.CYAN}{intel.get('country_code', 'XX')} | {type_color}{intel.get('type', 'DC')}"

                        if enable_anonymity:
                            anon_color = {
                                'ELITE': Fore.GREEN,
                                'ANON': Fore.YELLOW,
                                'TRANS': Fore.RED
                            }.get(intel.get('anonymity'), Fore.WHITE)
                            output_str += f" | {anon_color}{intel.get('anonymity', 'UNK')}"

                        if enable_google_test:
                            google_color = Fore.GREEN if intel.get('google_test') == 'PASS' else Fore.RED
                            output_str += f" | G:{google_color}{intel.get('google_test', 'UNK')}{Fore.RESET}"

                        if enable_speed_test:
                            speed_color = {
                                'ULTRA': Fore.GREEN,
                                'FAST': Fore.CYAN,
                                'MEDIUM': Fore.YELLOW,
                                'SLOW': Fore.RED
                            }.get(intel.get('category'), Fore.WHITE)
                            output_str += f" | {speed_color}{intel.get('category', 'UNK')}{Fore.RESET}"

                        print(output_str)

                        with open(output_file, "a", encoding='utf-8') as f:
                            f.write(line + "\n")
                        existing_set.add(line)

                        # Add to rotation pool
                        working_proxies.append(f"{proto}://{ip}:{port}")
                        if len(working_proxies) > 50:
                            working_proxies.pop(0)

                found_live = True
                break
        except:
            continue

    with print_lock:
        stats["checked"] += 1
        if not found_live:
            stats["dead"] += 1


def print_progress_bar_enhanced():
    """Enhanced progress bar"""
    global stop_progress
    start_time = time.time()

    while not stop_progress and stats["checked"] < stats["total"]:
        percent = int((stats['checked'] / stats['total']) * 100) if stats['total'] > 0 else 0
        bar = '█' * int(40 * percent / 100) + '░' * (40 - int(40 * percent / 100))

        elapsed = time.time() - start_time
        if stats['checked'] > 0:
            avg_time = elapsed / stats['checked']
            remaining = (stats['total'] - stats['checked']) * avg_time
            eta = f"{int(remaining // 60)}m {int(remaining % 60)}s"
        else:
            eta = "calculating..."

        line = (
            f"\r{Style.BRIGHT}{Fore.CYAN}[{bar}] {percent}% | "
            f"{Fore.WHITE}Checked: {stats['checked']}/{stats['total']} | "
            f"{Fore.MAGENTA}S5:{stats['socks5']} {Fore.BLUE}S4:{stats['socks4']} {Fore.GREEN}H:{stats['http']} | "
            f"{Fore.RED}Dead:{stats['dead']} | "
            f"{Fore.WHITE}ETA: {eta}     "
        )
        sys.stdout.write(line)
        sys.stdout.flush()
        time.sleep(0.2)


# ==================== EXPORT & UTILITIES ====================

def export_to_geojson(filename):
    """Export proxies to GeoJSON for mapping"""
    try:
        conn = sqlite3.connect('proxies.db')
        c = conn.cursor()

        c.execute(
            "SELECT ip, port, protocol, country, latitude, longitude, type, anonymity FROM proxies WHERE status='LIVE'")
        proxies = c.fetchall()
        conn.close()

        geojson = {
            "type": "FeatureCollection",
            "features": []
        }

        for proxy in proxies:
            if proxy[4] and proxy[5]:  # lat, lon
                feature = {
                    "type": "Feature",
                    "geometry": {
                        "type": "Point",
                        "coordinates": [proxy[5], proxy[4]]  # lon, lat
                    },
                    "properties": {
                        "ip": proxy[0],
                        "port": proxy[1],
                        "protocol": proxy[2],
                        "country": proxy[3],
                        "type": proxy[6],
                        "anonymity": proxy[7]
                    }
                }
                geojson["features"].append(feature)

        output_file = filename.replace('.txt', '_map.geojson')
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(geojson, f, indent=2)

        print(f"{Fore.GREEN}[✓] GeoJSON exported to: {output_file}")
        print(f"{Fore.CYAN}[i] View at: https://geojson.io")

    except Exception as e:
        print(f"{Fore.RED}[!] Export failed: {e}")


def filter_by_country(filename):
    """Filter proxies by country"""
    print(f"\n{Fore.CYAN}[*] Filter by Country")
    country_code = input(f"{Fore.YELLOW}Enter country code (US, UK, SA, etc.): ").strip().upper()

    if not os.path.exists(filename):
        print(f"{Fore.RED}[!] File not found!")
        return

    filtered = []
    with open(filename, 'r', encoding='utf-8') as f:
        for line in f:
            if country_code in line:
                filtered.append(line.strip())

    if filtered:
        output = f"{country_code}_proxies.txt"
        with open(output, 'w', encoding='utf-8') as f:
            for proxy in filtered:
                f.write(proxy + '\n')
        print(f"{Fore.GREEN}[✓] Saved {len(filtered)} proxies to {output}")
    else:
        print(f"{Fore.RED}[!] No proxies found for {country_code}")


def export_proxies(filename):
    """Export to different formats"""
    print(f"\n{Fore.CYAN}[*] Export Options:")
    print(f"  [1] Keep current format")
    print(f"  [2] Export to JSON")
    print(f"  [3] Export to CSV")
    print(f"  [4] Export to GeoJSON (map)")
    print(f"  [5] Export all formats")

    choice = input(f"{Fore.YELLOW}Select: ").strip()

    if not os.path.exists(filename):
        print(f"{Fore.RED}[!] File not found!")
        return

    with open(filename, 'r', encoding='utf-8') as f:
        proxies = [line.strip() for line in f if line.strip()]

    if choice in ['2', '5']:
        json_data = []
        for proxy in proxies:
            parts = proxy.split('|')
            json_data.append({
                'proxy': parts[0].strip() if parts else proxy,
                'country': parts[1].strip() if len(parts) > 1 else 'Unknown',
                'isp': parts[2].strip() if len(parts) > 2 else 'Unknown',
                'type': parts[3].strip() if len(parts) > 3 else 'Unknown',
            })

        json_file = filename.replace('.txt', '.json')
        with open(json_file, 'w', encoding='utf-8') as jf:
            json.dump(json_data, jf, indent=2, ensure_ascii=False)
        print(f"{Fore.GREEN}[✓] Exported to JSON: {json_file}")

    if choice in ['3', '5']:
        import csv
        csv_file = filename.replace('.txt', '.csv')
        with open(csv_file, 'w', newline='', encoding='utf-8') as cf:
            writer = csv.writer(cf)
            writer.writerow(['Proxy', 'Country', 'ISP', 'Type'])
            for proxy in proxies:
                parts = proxy.split('|')
                row = [p.strip() for p in parts]
                while len(row) < 4:
                    row.append('Unknown')
                writer.writerow(row)
        print(f"{Fore.GREEN}[✓] Exported to CSV: {csv_file}")

    if choice in ['4', '5']:
        export_to_geojson(filename)


def view_database_stats():
    """View database statistics"""
    try:
        conn = sqlite3.connect('proxies.db')
        c = conn.cursor()

        print(f"\n{Fore.CYAN}{'=' * 70}")
        print(f"{Style.BRIGHT}{Fore.YELLOW}           DATABASE STATISTICS")
        print(f"{Fore.CYAN}{'=' * 70}\n")

        # Total
        c.execute("SELECT COUNT(*) FROM proxies WHERE status='LIVE'")
        total = c.fetchone()[0]
        print(f"{Fore.WHITE}Total Live Proxies: {Fore.GREEN}{total}")

        # By protocol
        for proto in ['socks5', 'socks4', 'http']:
            c.execute(f"SELECT COUNT(*) FROM proxies WHERE protocol='{proto}' AND status='LIVE'")
            count = c.fetchone()[0]
            print(f"{Fore.WHITE}{proto.upper()}: {Fore.CYAN}{count}")

        # By type
        c.execute("SELECT COUNT(*) FROM proxies WHERE type='RES' AND status='LIVE'")
        res = c.fetchone()[0]
        c.execute("SELECT COUNT(*) FROM proxies WHERE type='DC' AND status='LIVE'")
        dc = c.fetchone()[0]

        print(f"\n{Fore.CYAN}Residential: {Fore.GREEN}{res}")
        print(f"{Fore.YELLOW}Datacenter: {Fore.WHITE}{dc}")

        # Top countries
        print(f"\n{Fore.CYAN}Top 5 Countries:")
        c.execute("""
                  SELECT country_code, COUNT(*) as cnt
                  FROM proxies
                  WHERE status = 'LIVE'
                  GROUP BY country_code
                  ORDER BY cnt DESC LIMIT 5
                  """)

        for row in c.fetchall():
            print(f"  {Fore.WHITE}{row[0]}: {Fore.CYAN}{row[1]}")

        # Scan history
        print(f"\n{Fore.CYAN}Recent Scans:")
        c.execute("""
                  SELECT scan_date, total_checked, total_live, success_rate
                  FROM scan_history
                  ORDER BY scan_date DESC LIMIT 5
                  """)

        for row in c.fetchall():
            date = datetime.fromisoformat(row[0]).strftime('%Y-%m-%d %H:%M')
            print(f"  {Fore.WHITE}{date} | Checked: {row[1]} | Live: {row[2]} | Rate: {row[3]:.1f}%")

        conn.close()
        print(f"{Fore.CYAN}{'=' * 70}\n")

    except Exception as e:
        print(f"{Fore.RED}[!] Database error: {e}")


def send_telegram_notification(bot_token, chat_id, file_path, stats_data):
    """Send Telegram notification"""
    try:
        import telegram

        bot = telegram.Bot(token=bot_token)

        total_live = stats_data['socks5'] + stats_data['socks4'] + stats_data['http']
        success_rate = int((total_live / stats_data['total'] * 100)) if stats_data['total'] > 0 else 0

        message = f"""
🚀 **Proxy Checker - Completed!**

📊 Statistics:
✅ SOCKS5: {stats_data['socks5']}
✅ SOCKS4: {stats_data['socks4']}
✅ HTTP: {stats_data['http']}
🏠 Residential: {stats_data.get('residential', 0)}
🏢 Datacenter: {stats_data.get('datacenter', 0)}
🎭 Elite: {stats_data.get('elite', 0)}
📱 Google Passed: {stats_data.get('google_passed', 0)}
⚡ Ultra Fast: {stats_data.get('ultra_fast', 0)}
❌ Dead: {stats_data['dead']}

📈 Success Rate: {success_rate}%
        """

        bot.send_message(chat_id=chat_id, text=message, parse_mode='Markdown')

        if os.path.exists(file_path):
            with open(file_path, 'rb') as f:
                bot.send_document(chat_id=chat_id, document=f, filename=os.path.basename(file_path))

        print(f"{Fore.GREEN}[✓] Telegram notification sent!")

    except ImportError:
        print(f"{Fore.RED}[!] Install: pip install python-telegram-bot")
    except Exception as e:
        print(f"{Fore.RED}[!] Telegram failed: {e}")


# ==================== MAIN PROCESS ====================

def run_main_process():
    """Main checking process"""
    global stop_progress, working_proxies
    scan_start = time.time()

    # Reset stats
    for k in stats:
        stats[k] = 0
    stop_progress = False
    proxy_cache.clear()
    working_proxies.clear()

    output_file = select_or_create_file()
    existing_set = set()

    if os.path.exists(output_file):
        with open(output_file, "r", encoding='utf-8') as f:
            for line in f:
                existing_set.add(line.strip())

    try:
        limit = int(input(f"{Fore.YELLOW}Proxies to scrape (5000): ").strip() or "5000")
        threads = int(input(f"{Fore.YELLOW}Thread count (300): ").strip() or "300")
        proxychains_format = input(f"{Fore.YELLOW}Proxychains format? (y/n): ").lower() == 'y'

        print(f"\n{Fore.CYAN}{'━' * 70}")
        print(f"{Style.BRIGHT}{Fore.YELLOW}           ADVANCED OPTIONS")
        print(f"{Fore.CYAN}{'━' * 70}")

        enable_intel = input(f"{Fore.CYAN}Enable ISP/ASN Intelligence? (y/n): ").lower() == 'y'
        enable_anonymity = input(f"{Fore.MAGENTA}Check Anonymity Level? (y/n): ").lower() == 'y'
        enable_google = input(f"{Fore.GREEN}Test Google Access? (y/n): ").lower() == 'y'
        enable_speed = input(f"{Fore.YELLOW}Benchmark Speed? (y/n): ").lower() == 'y'
        enable_ssl = input(f"{Fore.BLUE}Check SSL Support? (y/n): ").lower() == 'y'
        enable_blacklist = input(f"{Fore.RED}Check Blacklist? (y/n): ").lower() == 'y'
        enable_ports = input(f"{Fore.CYAN}Scan Open Ports? (y/n): ").lower() == 'y'
        enable_database = input(f"{Fore.MAGENTA}Save to Database? (y/n): ").lower() == 'y'
        use_auto_discover = input(f"{Fore.GREEN}Auto-discover sources? (y/n): ").lower() == 'y'
        use_rotation = input(f"{Fore.YELLOW}Use Proxy Rotation? (y/n): ").lower() == 'y'
        enable_telegram = input(f"{Fore.CYAN}Send Telegram notification? (y/n): ").lower() == 'y'

        telegram_token = telegram_chat = None
        if enable_telegram:
            telegram_token = input(f"{Fore.YELLOW}Bot Token: ").strip()
            telegram_chat = input(f"{Fore.YELLOW}Chat ID: ").strip()

    except:
        limit = threads = 300
        proxychains_format = True
        enable_intel = enable_anonymity = enable_google = True
        enable_speed = enable_ssl = enable_blacklist = enable_ports = False
        enable_database = use_auto_discover = use_rotation = enable_telegram = False
        telegram_token = telegram_chat = None

    if enable_database:
        init_database()

    proxies = scrape_proxies(limit, use_auto_discover, use_rotation)
    if not proxies:
        return

    stats["total"] = len(proxies)

    progress_thread = threading.Thread(target=print_progress_bar_enhanced, daemon=True)
    progress_thread.start()

    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = [
            executor.submit(
                check_proxy_advanced,
                p, output_file, existing_set, proxychains_format,
                enable_intel, enable_anonymity, enable_google, enable_database,
                enable_speed, enable_ports, enable_ssl, enable_blacklist
            )
            for p in proxies
        ]

    stop_progress = True
    scan_duration = int(time.time() - scan_start)

    # Final stats
    total_live = stats['socks5'] + stats['socks4'] + stats['http']
    success_rate = int((total_live / stats['total'] * 100)) if stats['total'] > 0 else 0

    print(f"\n\n{Fore.GREEN}{'=' * 70}")
    print(f"{Style.BRIGHT}{Fore.CYAN}                 FINAL STATISTICS")
    print(f"{Fore.GREEN}{'=' * 70}\n")
    print(f"{Fore.MAGENTA}  SOCKS5:         {stats['socks5']}")
    print(f"{Fore.BLUE}  SOCKS4:         {stats['socks4']}")
    print(f"{Fore.GREEN}  HTTP:           {stats['http']}")

    if enable_intel:
        print(f"{Fore.CYAN}  Residential:    {stats['residential']}")
        print(f"{Fore.YELLOW}  Datacenter:     {stats['datacenter']}")

    if enable_anonymity:
        print(f"{Fore.GREEN}  Elite:          {stats['elite']}")
        print(f"{Fore.YELLOW}  Anonymous:      {stats['anonymous']}")
        print(f"{Fore.RED}  Transparent:    {stats['transparent']}")

    if enable_google:
        print(f"{Fore.GREEN}  Google Passed:  {stats['google_passed']}")

    if enable_speed:
        print(f"{Fore.GREEN}  Ultra Fast:     {stats['ultra_fast']}")
        print(f"{Fore.CYAN}  Fast:           {stats['fast']}")
        print(f"{Fore.YELLOW}  Medium:         {stats['medium']}")
        print(f"{Fore.RED}  Slow:           {stats['slow']}")

    if enable_ssl:
        print(f"{Fore.GREEN}  SSL Supported:  {stats['ssl_supported']}")

    if enable_blacklist:
        print(f"{Fore.RED}  Blacklisted:    {stats['blacklisted']}")

    print(f"{Fore.RED}  Dead:           {stats['dead']}")
    print(f"{Fore.WHITE}  Success Rate:   {success_rate}%")
    print(f"{Fore.CYAN}  Duration:       {scan_duration}s")
    print(f"{Fore.GREEN}{'=' * 70}\n")

    # Save scan history
    if enable_database:
        save_scan_history(stats['total'], total_live, scan_duration)

    # Re-check
    if input(f"{Fore.YELLOW}Re-check dead proxies? (y/n): ").lower() == 'y':
        filter_dead_proxies(output_file)

    # Telegram
    if enable_telegram and telegram_token and telegram_chat:
        send_telegram_notification(telegram_token, telegram_chat, output_file, stats)


def show_banner():
    """Display banner"""
    clear_screen()
    banner = f"""{Style.BRIGHT}{Fore.CYAN}
{'=' * 70}
{Fore.RED}
██╗   ██╗ ██████╗ ██╗██████╗ ██╗  ██╗ █████╗ 
██║   ██║██╔═████╗██║██╔══██╗╚██╗██╔╝██╔══██╗
██║   ██║██║██╔██║██║██║  ██║ ╚███╔╝ ███████║
╚██╗ ██╔╝████╔╝██║██║██║  ██║ ██╔██╗ ██╔══██║
 ╚████╔╝ ╚██████╔╝██║██████╔╝██╔╝ ██╗██║  ██║
  ╚═══╝   ╚═════╝ ╚═╝╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝


{Fore.YELLOW}         v11.0  Half Beta EDITION 🚀
{Fore.WHITE}    Speed Test | Port Scan | SSL Check | Blacklist | GeoMap
{Fore.CYAN}{'=' * 70}
"""
    print(banner)


# ==================== MAIN LOOP ====================

if __name__ == "__main__":
    show_banner()

    while True:
        print(f"{Style.BRIGHT}{Fore.RED}  [1] Start Scraper & Checker 🚀")
        print(f"{Fore.CYAN}  [2] Filter by Country 🌍")
        print(f"{Fore.YELLOW}  [3] Export Proxies 📁")
        print(f"{Fore.MAGENTA}  [4] View Database Stats 📊")
        print(f"{Fore.GREEN}  [5] Auto-discover Sources 🔍")
        print(f"{Fore.BLUE}  [6] Export GeoJSON Map 🗺️")
        print(f"{Fore.RED}  [7] Exit")

        cmd = input(f"\n{Fore.WHITE}Select > ").strip()

        if cmd == "1":
            run_main_process()
            input(f"\n{Fore.CYAN}Press ENTER to continue...")
            show_banner()

        elif cmd == "2":
            files = get_existing_files()
            if files:
                print(f"\n{Fore.GREEN}Available files:")
                for i, f in enumerate(files, 1):
                    print(f"  [{i}] {f}")
                try:
                    choice = int(input(f"{Fore.YELLOW}Select file: ").strip()) - 1
                    if 0 <= choice < len(files):
                        filter_by_country(files[choice])
                except:
                    print(f"{Fore.RED}[!] Invalid selection")
            else:
                print(f"{Fore.RED}[!] No files found")
            input(f"\n{Fore.CYAN}Press ENTER...")
            show_banner()

        elif cmd == "3":
            files = get_existing_files()
            if files:
                print(f"\n{Fore.GREEN}Available files:")
                for i, f in enumerate(files, 1):
                    print(f"  [{i}] {f}")
                try:
                    choice = int(input(f"{Fore.YELLOW}Select file: ").strip()) - 1
                    if 0 <= choice < len(files):
                        export_proxies(files[choice])
                except:
                    print(f"{Fore.RED}[!] Invalid selection")
            else:
                print(f"{Fore.RED}[!] No files found")
            input(f"\n{Fore.CYAN}Press ENTER...")
            show_banner()

        elif cmd == "4":
            if os.path.exists('proxies.db'):
                view_database_stats()
            else:
                print(f"{Fore.RED}[!] Database not found. Run a scan with database enabled first.")
            input(f"\n{Fore.CYAN}Press ENTER...")
            show_banner()

        elif cmd == "5":
            auto_discover_proxy_sources()
            input(f"\n{Fore.CYAN}Press ENTER...")
            show_banner()

        elif cmd == "6":
            files = get_existing_files()
            if files:
                print(f"\n{Fore.GREEN}Available files:")
                for i, f in enumerate(files, 1):
                    print(f"  [{i}] {f}")
                try:
                    choice = int(input(f"{Fore.YELLOW}Select file: ").strip()) - 1
                    if 0 <= choice < len(files):
                        export_to_geojson(files[choice])
                except:
                    print(f"{Fore.RED}[!] Invalid selection")
            else:
                print(f"{Fore.RED}[!] No files found")
            input(f"\n{Fore.CYAN}Press ENTER...")
            show_banner()

        elif cmd == "7":
            print(f"\n{Fore.YELLOW}Thanks for using the tool! 👋\n")
            sys.exit(0)

        else:
            print(f"{Fore.RED}[!] Invalid selection")
            time.sleep(1)
            show_banner()