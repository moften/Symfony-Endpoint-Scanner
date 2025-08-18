import requests
from urllib.parse import urljoin
import argparse

COMMON_PATHS = [
    # JS Routing & FOSJsRoutingBundle
    "/js/fos_js_routes.json",
    "/js/routes.json",
    "/js/routing.json",
    "/js/fos_js_routes.js",
    "/js/routing.js",
    "/bundles/fosjsrouting/js/router.js",
    "/bundles/fosjsrouting/js/router.min.js",

    # Symfony debug / dev tools
    "/_profiler",
    "/_profiler/open?file=...",
    "/_wdt",
    "/config.php",
    "/dev.php",
    "/index_dev.php",
    "/test.php",

    # Webpack Encore & frontend assets
    "/build/manifest.json",
    "/build/entrypoints.json",
    "/build/runtime.js",
    "/build/app.js",
    "/build/app.css",
    "/build/vendor.js",

    # Autenticación y paneles comunes
    "/login",
    "/logout",
    "/admin",
    "/admin/login",
    "/admin/dashboard",
    "/user/login",
    "/dashboard",
    "/easyadmin",

    # API comunes (REST, GraphQL, Swagger, JWT)
    "/api/users",
    "/api/v1/users",
    "/api/v1/token",
    "/api/login_check",
    "/api/doc",
    "/api/docs",
    "/api/swagger",
    "/api/platform",
    "/api/graphql",

    # Otros posibles accesos
    "/debug/",
    "/adminer",
]

HEADERS = {
    "User-Agent": "Mozilla/5.0 (compatible; SymfonyScanner/1.0)",
    "Accept": "*/*",
}

def banner():
    print("==============================================")
    print("       Symfony Endpoint Scanner v1.1          ")
    print("   Busca rutas públicas comunes de Symfony    ")
    print("               by m10sec (2025)               ")
    print("==============================================\n")

def check_endpoint(base_url, path):
    try:
        url = urljoin(base_url, path)
        response = requests.get(url, headers=HEADERS, timeout=5, allow_redirects=False)
        status = response.status_code
        if status in [200, 301, 302, 403]:
            print(f"[+] Posible endpoint válido: {url} (Status: {status})")
        else:
            print(f"[-] No válido: {url} (Status: {status})")
    except requests.RequestException as e:
        print(f"[!] Error en {path}: {e}")

def main():
    banner()

    parser = argparse.ArgumentParser(description="Escanea rutas públicas típicas de Symfony.")
    parser.add_argument("url", help="URL base (ej: https://example.com)")
    args = parser.parse_args()

    base_url = args.url.rstrip("/")

    print(f"🔍 Escaneando endpoints comunes de Symfony en: {base_url}\n")

    for path in COMMON_PATHS:
        check_endpoint(base_url, path)

if __name__ == "__main__":
    main()