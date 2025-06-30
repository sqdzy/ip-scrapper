import socket
import pandas as pd
from playwright.sync_api import sync_playwright
import dns.resolver
from urllib.parse import urlparse, unquote
import argparse
from tqdm import tqdm
from http.cookiejar import MozillaCookieJar
import time
import re


def load_cookies_from_netscape(cookie_file_path):
    """Загружает cookies из файла формата Netscape для аутентификации"""
    cookies = []
    cj = MozillaCookieJar(cookie_file_path)
    try:
        cj.load(ignore_discard=True, ignore_expires=True)
    except FileNotFoundError:
        print(f"Предупреждение: Файл cookies не найден по пути: {cookie_file_path}")
        return []
    except Exception as e:
        print(f"Предупреждение: Не удалось прочитать файл cookies. Ошибка: {e}")
        return []

    for cookie in cj:
        expires_timestamp = cookie.expires if cookie.expires is not None else -1

        cookies.append({
            "name": cookie.name,
            "value": cookie.value,
            "domain": cookie.domain,
            "path": cookie.path,
            "expires": expires_timestamp,
            "httpOnly": cookie.has_nonstandard_attr('httponly'),
            "secure": cookie.secure,
            "sameSite": "Lax"
        })
    return cookies


def resolve_domain_comprehensive(domain):
    """
    Расширенное разрешение домена с поддержкой множественных записей
    и резервных методов DNS-резолюции
    """
    ipv4_addrs = set()
    ipv6_addrs = set()

    try:
        answers = dns.resolver.resolve(domain, 'A')
        for r in answers:
            ipv4_addrs.add(r.address)
    except Exception:
        pass

    try:
        answers = dns.resolver.resolve(domain, 'AAAA')
        for r in answers:
            ipv6_addrs.add(r.address)
    except Exception:
        pass

    if not ipv4_addrs and not ipv6_addrs:
        try:
            host_ips = socket.getaddrinfo(domain, None)
            for rec in host_ips:
                ip = rec[4][0]
                if rec[0] == socket.AF_INET:
                    ipv4_addrs.add(ip)
                elif rec[0] == socket.AF_INET6:
                    ipv6_addrs.add(ip)
        except socket.gaierror:
            pass
        except Exception as e:
            print(f"Предупреждение: Не удалось определить IP для '{domain}': {e}")

    if ipv4_addrs:
        return list(ipv4_addrs)
    return list(ipv6_addrs)


def extract_domains_from_js(page_content):
    """
    Извлекает домены из JavaScript кода страницы
    Многие современные сайты хранят API endpoints в JS
    """
    domains = set()

    domain_patterns = [
        r'["\']https?://([^/"\'\s]+)',
        r'["\']//([^/"\'\s]+)',
        r'["\']([a-zA-Z0-9.-]+\.(?:com|net|org|io|co|tv|app|api|cdn|static))["\']',
        r'api["\']?\s*:\s*["\']([^"\']+)',
        r'cdn["\']?\s*:\s*["\']([^"\']+)',
    ]

    for pattern in domain_patterns:
        matches = re.findall(pattern, page_content, re.IGNORECASE)
        for match in matches:

            domain = match.strip().lower()
            if domain and '.' in domain and not domain.startswith('.'):
                domains.add(domain)

    return domains


def capture_comprehensive_network_activity(url, cookies_path=None, interaction_time=30):
    """
    Расширенный захват сетевой активности с эмуляцией пользовательского взаимодействия
    """
    records = []
    websocket_connections = []
    js_domains = set()

    with sync_playwright() as pw:

        browser = pw.chromium.launch(
            headless=False,
            args=[
                '--disable-blink-features=AutomationControlled',
                '--no-first-run',
                '--disable-default-apps',
                '--disable-extensions-file-access-check'
            ]
        )

        context = browser.new_context(
            user_agent='Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            viewport={'width': 1920, 'height': 1080},
            locale='en-US'
        )

        if cookies_path:
            print(f"Загружаю cookies из файла: {cookies_path}")
            cookies = load_cookies_from_netscape(cookies_path)
            if cookies:
                context.add_cookies(cookies)
                print(f"Загружено {len(cookies)} cookies.")

        page = context.new_page()

        def handle_request(req):
            records.append({
                "url": req.url,
                "resource_type": req.resource_type,
                "method": req.method,
                "timestamp": time.time(),
                "headers": dict(req.headers) if req.headers else {}
            })

        def handle_websocket(ws):
            websocket_connections.append({
                "url": ws.url,
                "timestamp": time.time()
            })

        page.on("request", handle_request)
        page.on("websocket", handle_websocket)

        try:
            print(f"Загружаю страницу: {url}")
            page.goto(url, wait_until="networkidle", timeout=60000)

            print("Анализирую JavaScript код на предмет скрытых доменов...")
            page_content = page.content()
            js_domains = extract_domains_from_js(page_content)

            if js_domains:
                print(f"Найдено {len(js_domains)} доменов в JavaScript коде")

            print(f"Эмулирую пользовательскую активность в течение {interaction_time} секунд...")

            for i in range(5):
                page.evaluate("window.scrollTo(0, document.body.scrollHeight)")
                time.sleep(2)
                page.evaluate("window.scrollTo(0, 0)")
                time.sleep(1)

            time.sleep(interaction_time - 15)

        except Exception as e:
            print(f"Ошибка при загрузке страницы {url}: {e}")
        finally:
            browser.close()

    return records, websocket_connections, js_domains


def main():
    parser = argparse.ArgumentParser(
        description="Расширенный анализатор сетевой активности для точного VPN-туннелирования.",
        formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument("url", help="URL страницы для анализа")
    parser.add_argument(
        "-o", "--output", default="output_analysis.xlsx",
        help="Имя итогового Excel-файла (по умолчанию: output_analysis.xlsx)"
    )
    parser.add_argument(
        "-c", "--cookies",
        help="Путь к файлу cookies.txt в формате Netscape"
    )
    parser.add_argument(
        "-t", "--time", type=int, default=30,
        help="Время эмуляции пользовательской активности в секундах (по умолчанию: 30)"
    )
    args = parser.parse_args()

    print(f"Запускаю расширенный анализ страницы: {args.url}")
    records, websockets, js_domains = capture_comprehensive_network_activity(
        args.url, args.cookies, args.time
    )

    print(f"Собрано {len(records)} HTTP-запросов")
    print(f"Обнаружено {len(websockets)} WebSocket соединений")
    print(f"Найдено {len(js_domains)} доменов в JavaScript")

    if not records and not websockets and not js_domains:
        print("Не удалось собрать данные. Проверьте URL и подключение.")
        return

    all_domains = set()

    for record in records:
        try:
            hostname = urlparse(record["url"]).hostname
            if hostname:
                all_domains.add(hostname)
        except Exception:
            pass

    for ws in websockets:
        try:
            hostname = urlparse(ws["url"]).hostname
            if hostname:
                all_domains.add(hostname)
        except Exception:
            pass

    all_domains.update(js_domains)

    print(f"Всего найдено {len(all_domains)} уникальных доменов")

    print("Начинаю разрешение IP-адресов...")
    ip_cache = {}
    failed_domains = []

    for domain in tqdm(sorted(list(all_domains)), desc="Определение IP-адресов"):
        ips = resolve_domain_comprehensive(domain)
        if ips:
            ip_cache[domain] = ips
        else:
            failed_domains.append(domain)

    if failed_domains:
        print(f"Предупреждение: Не удалось разрешить {len(failed_domains)} доменов")

    detailed_data = []
    seen_urls = set()

    for record in records:
        if record["url"] in seen_urls:
            continue
        seen_urls.add(record["url"])

        try:
            parsed = urlparse(record["url"])
            domain = parsed.hostname
        except Exception:
            continue

        if not domain:
            continue

        ips = ip_cache.get(domain, [])
        detailed_data.append({
            "domain": domain,
            "resource_type": record.get("resource_type", "unknown"),
            "method": record.get("method", "GET"),
            "full_url": unquote(record["url"]),
            "resolved_ips": ", ".join(ips),
            "ip_count": len(ips)
        })

    websocket_data = []
    for ws in websockets:
        try:
            parsed = urlparse(ws["url"])
            domain = parsed.hostname
            ips = ip_cache.get(domain, [])
            websocket_data.append({
                "domain": domain,
                "websocket_url": ws["url"],
                "resolved_ips": ", ".join(ips)
            })
        except Exception:
            pass

    summary_data = []
    for domain, ips in sorted(ip_cache.items()):
        if ips:
            summary_data.append({
                "domain": domain,
                "ip_addresses": ", ".join(ips),
                "ip_count": len(ips)
            })

    try:
        with pd.ExcelWriter(args.output, engine='xlsxwriter') as writer:

            df_summary = pd.DataFrame(summary_data)
            df_summary.to_excel(writer, sheet_name='Domains & IPs', index=False)

            df_detailed = pd.DataFrame(detailed_data)
            df_detailed.to_excel(writer, sheet_name='HTTP Requests', index=False)

            if websocket_data:
                df_websockets = pd.DataFrame(websocket_data)
                df_websockets.to_excel(writer, sheet_name='WebSocket Connections', index=False)

            all_unique_ips = set()
            for ip_list in ip_cache.values():
                all_unique_ips.update(ip_list)

            if all_unique_ips:
                df_all_ips = pd.DataFrame({
                    'all_ips_for_vpn': [", ".join(sorted(list(all_unique_ips)))]
                })
                df_all_ips.to_excel(writer, sheet_name='All IPs for VPN', index=False)

            if failed_domains:
                df_failed = pd.DataFrame({
                    'unresolved_domains': failed_domains
                })
                df_failed.to_excel(writer, sheet_name='Unresolved Domains', index=False)

        print(f"\nРезультат сохранён в файл '{args.output}'")
        print(f"Найдено {len(all_unique_ips)} уникальных IP-адресов")
        print(f"Обработано {len(all_domains)} доменов")

        if failed_domains:
            print(f"Внимание: {len(failed_domains)} доменов не удалось разрешить - проверьте лист 'Unresolved Domains'")

        print("\nРекомендации для VPN:")
        print("1. Используйте все IP из листа 'All IPs for VPN'")
        print("2. Обратите внимание на WebSocket соединения - они критичны для интерактивности")
        print("3. Если некоторые домены не разрешились, попробуйте запустить анализ еще раз")

    except Exception as e:
        print(f"Ошибка при сохранении файла: {e}")
        print("Проверьте, не открыт ли файл в Excel")


if __name__ == "__main__":
    main()
