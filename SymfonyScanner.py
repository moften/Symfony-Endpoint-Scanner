#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
import csv
import json
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from urllib.parse import urljoin

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

# --- (Opcional) Silenciar warning de urllib3+LibreSSL ---
# import warnings
# try:
#     from urllib3.exceptions import NotOpenSSLWarning
#     warnings.filterwarnings("ignore", category=NotOpenSSLWarning)
# except Exception:
#     pass
# --------------------------------------------------------

try:
    from colorama import Fore, Style, init as colorama_init
    colorama_init(autoreset=True)
except Exception:
    # Fallback si no está colorama
    class _Dummy:
        def __getattr__(self, k): return ""
    Fore = Style = _Dummy()

from typing import Optional, List, Dict, Any, Set  # compatibilidad Python 3.9

COMMON_PATHS: List[str] = [
    # JS Routing & FOSJsRoutingBundle
    "/js/fos_js_routes.json", "/js/routes.json", "/js/routing.json",
    "/js/fos_js_routes.js", "/js/routing.js",
    "/bundles/fosjsrouting/js/router.js", "/bundles/fosjsrouting/js/router.min.js",

    # Symfony debug / dev tools
    "/_profiler", "/_wdt", "/config.php", "/dev.php", "/index_dev.php", "/test.php",

    # Webpack Encore & frontend assets
    "/build/manifest.json", "/build/entrypoints.json",
    "/build/runtime.js", "/build/app.js", "/build/app.css", "/build/vendor.js",

    # Autenticación y paneles comunes
    "/login", "/logout", "/admin", "/admin/login", "/admin/dashboard",
    "/user/login", "/dashboard", "/easyadmin",

    # API comunes (REST, GraphQL, Swagger, JWT)
    "/api/users", "/api/v1/users", "/api/v1/token", "/api/login_check",
    "/api/doc", "/api/docs", "/api/swagger", "/api/platform", "/api/graphql",

    # Otros posibles accesos
    "/debug/", "/adminer",

    # FOSUserBundle
    "/register", "/register/check-email", "/register/confirmed",
    "/login", "/logout",
    "/resetting/request", "/resetting/check-email", "/resetting/reset", "/resetting/reset/abcdef1234",
    "/profile", "/profile/edit", "/profile/show", "/profile/change-password",
    "/confirm/abcdef1234",

    # SymfonyCasts bundles
    "/reset-password", "/reset-password/check-email", "/reset-password/reset", "/reset-password/reset/abcdef1234",
    "/verify/email", "/verify-email", "/verify-email/abcdef1234",
    "/2fa", "/2fa_check", "/2fa/qr-code",

    # API Platform / Swagger / GraphQL
    "/api", "/api/docs", "/api/docs.jsonld", "/api/docs.json", "/api/contexts/EntryPoint",
    "/docs", "/swagger.json", "/openapi.json",
    "/graphql", "/graphiql", "/graphql-playground",

    # Auth y JWT/OAuth
    "/login_check", "/api/login_check",
    "/token/refresh", "/api/token/refresh",
    "/oauth/v2/token", "/oauth/v2/auth", "/oauth/authorize", "/oauth/token", "/oauth/refresh_token",
    "/connect/",

    # Admin bundles
    "/easyadmin", "/admin/logout", "/admin/resetting/request",
    "/admin/resetting/reset/abcdef",
    "/adminer", "/adminer.php",

    # Dev/Debug
    "/_profiler/abcdef", "/_wdt/abcdef", "/_errors/500",
    "/phpinfo.php", "/info.php", "/index.php", "/app.php", "/app_dev.php",
    "/bundles/", "/vendor/", "/composer.lock", "/symfony.lock",

    # Salud/Monitoreo
    "/health", "/healthz", "/ready", "/status", "/ping", "/_ping", "/metrics",

    # Archivos de sitio
    "/robots.txt", "/sitemap.xml", "/sitemap_index.xml",

    # Well-known
    "/.well-known/security.txt", "/.well-known/change-password",
    "/.well-known/openid-configuration", "/.well-known/jwks.json",
    "/.well-known/assetlinks.json", "/.well-known/apple-app-site-association",
]

DEFAULT_HEADERS: Dict[str, str] = {
    "User-Agent": "Mozilla/5.0 (compatible; SymfonyScanner/1.2.1)",
    "Accept": "*/*",
}

def banner() -> None:
    print("==============================================")
    ascii_art = r"""
     /$$$$$$$$                 /$$                     /$$             /$$    
    | $$_____/                | $$                    |__/            | $$    
    | $$       /$$$$$$$   /$$$$$$$  /$$$$$$   /$$$$$$  /$$ /$$$$$$$  /$$$$$$  
    | $$$$$   | $$__  $$ /$$__  $$ /$$__  $$ /$$__  $$| $$| $$__  $$|_  $$_/  
    | $$__/   | $$  \ $$| $$  | $$| $$  \ $$| $$  \ $$| $$| $$  \ $$  | $$    
    | $$      | $$  | $$| $$  | $$| $$  | $$| $$  | $$| $$| $$  | $$  | $$ /$$
    | $$$$$$$$| $$  | $$|  $$$$$$$| $$$$$$$/|  $$$$$$/| $$| $$  | $$  |  $$$$/
    |________/|__/  |__/ \_______/| $$____/  \______/ |__/|__/  |__/   \___/  
                                  | $$                                        
                                  | $$                                        
                                  |__/                                        
    """
    print(ascii_art)
    print("       Symfony Endpoint Scanner v1.2.1        ")
    print("   Busca rutas públicas comunes de Symfony    ")
    print("               by m10sec (2025)               ")
    print("==============================================\n")

def build_session(timeout: int, retries: int, backoff: float, verify_tls: bool, proxy: Optional[str]) -> requests.Session:
    sess = requests.Session()
    retry = Retry(
        total=retries,
        read=retries,
        connect=retries,
        status=retries,
        backoff_factor=backoff,
        status_forcelist=[429, 500, 502, 503, 504],
        allowed_methods=frozenset(["GET", "HEAD"])
    )
    adapter = HTTPAdapter(max_retries=retry, pool_connections=50, pool_maxsize=50)
    sess.mount("http://", adapter)
    sess.mount("https://", adapter)
    sess.verify = verify_tls
    if proxy:
        sess.proxies = {"http": proxy, "https": proxy}
    sess.headers.update(DEFAULT_HEADERS)
    # atributo simple para reusar en llamadas
    sess.request_timeout = timeout  # type: ignore[attr-defined]
    return sess

def parse_headers(headers_list: List[str]) -> Dict[str, str]:
    out: Dict[str, str] = {}
    for h in headers_list:
        if ":" not in h:
            print(f"{Fore.YELLOW}[!] Header inválido (usa Clave: Valor):{Style.RESET_ALL} {h}")
            continue
        k, v = h.split(":", 1)
        out[k.strip()] = v.strip()
    return out

def is_interesting_status(code: int, allow_codes: Set[int]) -> bool:
    if allow_codes:
        return code in allow_codes
    # por defecto, consideramos “interesantes”
    return code in (200, 301, 302, 401, 403)

def symfony_fingerprints(resp: requests.Response, body_sample: Optional[str]) -> List[str]:
    hints: List[str] = []
    # Cabeceras típicas del profiler
    if resp.headers.get("X-Debug-Token"):
        hints.append("X-Debug-Token presente (Symfony Profiler)")
    if resp.headers.get("X-Debug-Token-Link"):
        hints.append("X-Debug-Token-Link presente (Symfony Profiler link)")
    # EasyAdmin
    if "easyadmin" in resp.url.lower():
        hints.append("Ruta relacionada con EasyAdmin")
    # FOSJsRouting patterns
    if body_sample and ("routes" in body_sample and "base_url" in body_sample and "prefix" in body_sample):
        hints.append("Estructura FOSJsRouting detectada")
    # Encore/manifest
    try:
        if resp.request.path_url.endswith(("manifest.json", "entrypoints.json")):  # type: ignore[attr-defined]
            hints.append("Archivo de Encore (manifest/entrypoints)")
    except Exception:
        pass
    return hints

def fetch(session: requests.Session, base: str, path: str, follow: bool, head_first: bool, extra_headers: Dict[str, str], head_fallback_get: bool = True) -> Dict[str, Any]:
    url = urljoin(base, path)
    t0 = time.time()
    try:
        # HEAD primero si se pidió
        resp = None
        if head_first:
            resp = session.head(url, allow_redirects=follow, timeout=session.request_timeout, headers=extra_headers)  # type: ignore[attr-defined]
            # si HEAD no permitido o sin info útil, probamos GET
            if resp.status_code in (405, 501) or ("content-type" not in resp.headers and head_fallback_get):
                resp = None  # forzar GET
        if resp is None:
            resp = session.get(url, allow_redirects=follow, timeout=session.request_timeout, headers=extra_headers)  # type: ignore[attr-defined]
        dt = time.time() - t0

        body_sample: Optional[str] = None
        try:
            ctype = resp.headers.get("Content-Type", "")
            if ctype.startswith("text/") or "json" in ctype:
                body_sample = resp.text[:1000]
        except Exception:
            body_sample = None

        hints = symfony_fingerprints(resp, body_sample)
        result: Dict[str, Any] = {
            "url": url,
            "status": resp.status_code,
            "reason": getattr(resp, "reason", None),
            "content_type": resp.headers.get("Content-Type"),
            "length": resp.headers.get("Content-Length"),
            "location": resp.headers.get("Location"),
            "elapsed_ms": int(dt * 1000),
            "hints": hints,
        }
        return result
    except requests.RequestException as e:
        return {"url": url, "error": str(e)}

def load_wordlist(path: Optional[str]) -> List[str]:
    if not path:
        return []
    p = Path(path)
    if not p.exists():
        print(f"{Fore.RED}[X] Wordlist no encontrada:{Style.RESET_ALL} {path}")
        return []
    items: List[str] = []
    with p.open("r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if not line.startswith("/"):
                line = "/" + line
            items.append(line)
    return items

def save_results(results: List[Dict[str, Any]], out_path: str, fmt: str) -> None:
    if fmt == "json":
        with open(out_path, "w", encoding="utf-8") as f:
            json.dump(results, f, ensure_ascii=False, indent=2)
    elif fmt == "csv":
        keys = sorted({k for r in results for k in r.keys()})
        with open(out_path, "w", newline="", encoding="utf-8") as f:
            w = csv.DictWriter(f, fieldnames=keys)
            w.writeheader()
            for r in results:
                w.writerow(r)
    else:
        print(f"{Fore.YELLOW}[!] Formato no soportado, use json o csv.{Style.RESET_ALL}")

def main() -> None:
    banner()
    parser = argparse.ArgumentParser(description="Escanea rutas públicas típicas de Symfony (rápido y concurrente).")
    parser.add_argument("url", help="URL base (ej: https://example.com)")
    parser.add_argument("-w", "--wordlist", help="Archivo con rutas adicionales (una por línea).")
    parser.add_argument("-p", "--paths", nargs="*", default=[], help="Rutas extra separadas por espacios (ej: /health /metrics).")
    parser.add_argument("--codes", help="Códigos permitidos (coma, ej: 200,301,302,403). Por defecto: 200,301,302,401,403")
    parser.add_argument("--follow", action="store_true", help="Seguir redirecciones.")
    parser.add_argument("--head-first", action="store_true", help="Probar HEAD antes de GET.")
    parser.add_argument("--timeout", type=int, default=7, help="Timeout por petición (s).")
    parser.add_argument("--retries", type=int, default=2, help="Reintentos por fallo/transitorio.")
    parser.add_argument("--backoff", type=float, default=0.4, help="Backoff exponencial base.")
    parser.add_argument("--threads", type=int, default=20, help="Hilos concurrentes.")
    parser.add_argument("--proxy", help="Proxy (ej: http://127.0.0.1:8080).")
    parser.add_argument("--insecure", action="store_true", help="No verificar TLS (equivalente a -k en curl).")
    parser.add_argument("-H", "--header", action="append", default=[], help='Header extra (repetible). Ej: -H "Cookie: a=b"')
    parser.add_argument("--format", choices=["json","csv"], help="Guardar resultados en JSON o CSV.")
    parser.add_argument("--out", help="Ruta del archivo de salida (requerido si usa --format).")
    parser.add_argument("--verbose", action="store_true", help="Mostrar también respuestas que no coincidan con --codes.")
    parser.add_argument("--save-all", action="store_true", help="Guardar todos los resultados incluso si --codes está activo.")
    args = parser.parse_args()

    base_url = args.url.rstrip("/")
    if not base_url.startswith(("http://", "https://")):
        print(f"{Fore.YELLOW}[!] La URL no contiene esquema, asumiendo https://{Style.RESET_ALL}")
        base_url = "https://" + base_url

    # códigos permitidos
    allow_codes: Set[int] = set()
    if args.codes:
        try:
            allow_codes = {int(x.strip()) for x in args.codes.split(",") if x.strip()}
        except ValueError:
            print(f"{Fore.YELLOW}[!] --codes inválido, usando por defecto.{Style.RESET_ALL}")
            allow_codes = set()

    # construir session
    session = build_session(
        timeout=args.timeout,
        retries=args.retries,
        backoff=args.backoff,
        verify_tls=not args.insecure,
        proxy=args.proxy
    )

    # headers extra
    extra_headers = parse_headers(args.header)
    if extra_headers:
        session.headers.update(extra_headers)

    # compilar lista de paths (dedup manteniendo orden)
    targets = list(dict.fromkeys(COMMON_PATHS + args.paths + load_wordlist(args.wordlist)))

    print(f"🔍 Escaneando endpoints comunes de Symfony en: {Fore.CYAN}{base_url}{Style.RESET_ALL}")
    print(f"   Rutas objetivo: {len(targets)} | Hilos: {args.threads} | Timeout: {args.timeout}s\n")

    results: List[Dict[str, Any]] = []
    ok_count = 0           # “interesantes” según la lógica activa
    err_count = 0
    match_count = 0        # coinciden con --codes cuando --codes está activo

    with ThreadPoolExecutor(max_workers=args.threads) as ex:
        future_map = {ex.submit(
            fetch, session, base_url, path, args.follow, args.head_first, extra_headers
        ): path for path in targets}

        for fut in as_completed(future_map):
            r = fut.result()
            results.append(r)
            if "error" in r:
                err_count += 1
                print(f"{Fore.RED}[!] Error{Style.RESET_ALL} {r['url']} => {r['error']}")
                continue

            code = r.get("status")
            interesting = is_interesting_status(code, allow_codes) if code is not None else False
            color = Fore.GREEN if interesting else Fore.LIGHTBLACK_EX

            # Si hay --codes, solo mostramos coincidentes a menos que --verbose esté activo
            if args.codes and not interesting and not args.verbose:
                continue

            if interesting:
                ok_count += 1
                if args.codes:
                    match_count += 1

            loc = f" -> {r.get('location')}" if r.get("location") else ""
            ctype = f" [{r.get('content_type')}]" if r.get("content_type") else ""
            size = f" len={r.get('length')}" if r.get("length") else ""
            ms = f" ({r.get('elapsed_ms')} ms)" if r.get("elapsed_ms") is not None else ""
            hints = (" | " + "; ".join(r.get("hints", []))) if r.get("hints") else ""

            sign = "[+]" if interesting else "[-]"
            print(f"{color}{sign} {r['url']} (Status {code}){ms}{ctype}{size}{loc}{hints}{Style.RESET_ALL}")

    print()
    if args.codes:
        print(f"{Fore.CYAN}Resumen:{Style.RESET_ALL} coinciden={match_count} | interesantes={ok_count} | errores={err_count} | total_vistos={len(results)}")
    else:
        print(f"{Fore.CYAN}Resumen:{Style.RESET_ALL} interesantes={ok_count} | errores={err_count} | total={len(results)}")

    # Guardado: si --codes está activo, por defecto guardamos solo coincidentes
    to_save = results
    if args.codes and not args.save_all:
        to_save = [r for r in results if ("status" in r and is_interesting_status(r["status"], allow_codes))]

    if args.format and args.out:
        save_results(to_save, args.out, args.format)
        desc = "(solo coincidentes con --codes)" if (args.codes and not args.save_all) else "(todos)"
        print(f"{Fore.CYAN}Guardado:{Style.RESET_ALL} {args.out} ({args.format}) {desc}")
    elif args.format and not args.out:
        print(f"{Fore.YELLOW}[!] --format requiere --out para guardar resultados.{Style.RESET_ALL}")

if __name__ == "__main__":
    main()