import socket
import pandas as pd
from playwright.sync_api import sync_playwright
import dns.resolver
from urllib.parse import urlparse, unquote
import argparse
from tqdm import tqdm
from http.cookiejar import MozillaCookieJar


def load_cookies_from_netscape(cookie_file_path):
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


def resolve_domain(domain):
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

    if ipv4_addrs:
        return list(ipv4_addrs)
    if ipv6_addrs:
        return list(ipv6_addrs)

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


def capture_network_activity(url, cookies_path=None):
    records = []
    with sync_playwright() as pw:
        browser = pw.chromium.launch(headless=True)
        context = browser.new_context()

        if cookies_path:
            print(f"Загружаю cookies из файла: {cookies_path}")
            cookies = load_cookies_from_netscape(cookies_path)
            if cookies:
                context.add_cookies(cookies)
                print(f"Загружено {len(cookies)} cookies.")
            else:
                print("Продолжаю без cookies.")

        page = context.new_page()

        page.on("request", lambda req: records.append({
            "url": req.url,
            "resource_type": req.resource_type,
        }))

        try:
            print(f"Перехожу по URL: {url}")
            page.goto(url, wait_until="networkidle", timeout=60000)
        except Exception as e:
            print(f"Ошибка при загрузке страницы {url}: {e}")
        finally:
            browser.close()
    return records


def main():
    parser = argparse.ArgumentParser(
        description="Анализатор сетевой активности сайта для VPN-туннелирования.",
        formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument("url", help="URL страницы для анализа")
    parser.add_argument(
        "-o", "--output", default="out.xlsx",
        help="Имя итогового Excel-файла (по умолчанию: out.xlsx)"
    )
    parser.add_argument(
        "-c", "--cookies",
        help="Путь к файлу cookies.txt в формате Netscape для аутентифицированных сессий"
    )
    args = parser.parse_args()

    print(f"Анализирую страницу: {args.url}")
    records = capture_network_activity(args.url, args.cookies)
    print(f"Собрано {len(records)} сетевых запросов.")

    if not records:
        print("Не удалось собрать данные. Выход.")
        return

    unique_domains = set()
    for r in records:
        try:
            hostname = urlparse(r["url"]).hostname
            if hostname:
                unique_domains.add(hostname)
        except Exception:
            pass

    print(f"Найдено {len(unique_domains)} уникальных доменов.")

    ip_cache = {}
    for domain in tqdm(sorted(list(unique_domains)), desc="Определение IP-адресов"):
        ip_cache[domain] = resolve_domain(domain)

    print("Определение IP-адресов завершено.")

    processed_data = []
    seen_urls = set()
    for r in records:
        if r["url"] in seen_urls:
            continue
        seen_urls.add(r["url"])

        try:
            parsed = urlparse(r["url"])
            domain = parsed.hostname
        except Exception:
            continue

        if not domain:
            continue

        ips = ip_cache.get(domain, [])
        processed_data.append({
            "service_domain": domain,
            "purpose": r.get("resource_type", "unknown"),
            "full_url": unquote(r["url"]),
            "resolved_ips": ", ".join(ips)
        })

    summary_data = []
    for domain, ips in sorted(ip_cache.items()):
        if ips:
            summary_data.append({
                "domain": domain,
                "ips": ", ".join(ips)
            })

    df_detailed = pd.DataFrame(processed_data)
    df_summary = pd.DataFrame(summary_data)

    try:
        with pd.ExcelWriter(args.output, engine='xlsxwriter') as writer:
            df_summary.to_excel(writer, sheet_name='Summary (IPs by Domain)', index=False)
            df_detailed.to_excel(writer, sheet_name='Detailed Log', index=False)

            all_unique_ips = set()
            for ip_list in ip_cache.values():
                all_unique_ips.update(ip_list)

            if all_unique_ips:
                df_all_ips = pd.DataFrame({
                    'all_ips_combined': [", ".join(sorted(list(all_unique_ips)))]
                })
                df_all_ips.to_excel(writer, sheet_name='All IPs', index=False)

        print(f"Результат сохранён в файл '{args.output}'")
        print("В файле 3 листа: сводный (Summary), детальный (Detailed Log) и все IP (All IPs).")
    except Exception as e:
        print(f"Не удалось сохранить Excel-файл. Ошибка: {e}")
        print("Попробуйте закрыть файл, если он открыт, и запустить скрипт снова.")


if __name__ == "__main__":
    main()