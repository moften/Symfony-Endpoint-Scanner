#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
import csv
import json
import sys
import time
import re
import threading
import random
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from urllib.parse import urljoin, urlparse, urlunparse

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from requests.exceptions import SSLError, ConnectionError

try:
    from colorama import Fore, Style, init as colorama_init
    colorama_init(autoreset=True)
except Exception:
    class _Dummy:
        def __getattr__(self, k): return ""
    Fore = Style = _Dummy()

from typing import Optional, List, Dict, Any, Set, Tuple

# =========================
# Listas de rutas (las tuyas)
# =========================

COMMON_PATHS: List[str] = [
    # ... (misma lista que antes; truncated here for brevity in this snippet)
    "/js/fos_js_routes.json",
    "/.docs/vams-api.md",
    "/.docs/vams-webhooks.md",
    "/Readme.md",
    "/_babel.config.js",
    "/bitbucket-pipelines.yml",
    "/deploy.sh",
    "/phpunit.xml.dist",
    "/symfony.lock",
    "/webpack.config.js",
    "/js/routes.json",
    "/js/routing.json",
    "/js/fos_js_routes.js",
    "/js/routing.js",
    "/bundles/fosjsrouting/js/router.js",
    "/bundles/fosjsrouting/js/router.min.js",
    "/_wdt/{token}",
    "/_profiler/",
    "/_profiler/search",
    "/_profiler/search_bar",
    "/_profiler/phpinfo",
    "/_profiler/xdebug",
    "/_profiler/font/{fontName}.woff2",
    "/_profiler/open",
    "/_profiler/{token}",
    "/_profiler/{token}/router",
    "/_profiler/{token}/exception",
    "/_profiler/{token}/exception.css",
    "/_profiler/{token}/search/results",
    "/account",
    "/movements",
    "/download/{id}",
    "/category/{slug}",
    "/",
    "/categories",
    "/events",
    "/save-cookies",
    "/save-all-cookies",
    "/save-required-cookies",
    "/open-contact",
    "/contact",
    "/exchange-code",
    "/verify-exchange-code",
    "/event/{slug}",
    "/product/{id}",
    "/reset-password",
    "/reset-password/check-email",
    "/reset-password/reset/{token}",
    "/build/manifest.json",
    "/build/entrypoints.json",
    "/build/runtime.js",
    "/build/app.js",
    "/build/app.css",
    "/build/vendor.js",
    "/login",
    "/logout",
    "/admin",
    "/admin/login",
    "/admin/dashboard",
    "/user/login",
    "/dashboard",
    "/easyadmin",
    "/api/users",
    "/api/v1/users",
    "/api/v1/token",
    "/api/login_check",
    "/api/doc",
    "/api/docs",
    "/api/swagger",
    "/api/platform",
    "/api/graphql",
    "/swagger",
    "/swagger-ui",
    "/_docs",
    "/api/doc",
    "/api/doc.json",
    "/api/v1/doc",
    "/debug/",
    "/adminer",
    "/_fragment",
    "/_profiler/{token}",
    "/_wdt/{token}",
    "/_error/404",
    "/_error/500",
    "app_dev.php/_profiler",
    "app_dev.php/_wdt",
    "/authentication_token",
    "/connect/{provider}",
    "/login/check-{provider}",
    "/graphql-playground",
    "/playground",
    "/voyager",
    "/altair",
    "/.well-known/mercure",
    "/mercure",
    "/phpmyadmin",
    "/pma",
    "/bundles/easyadmin/",
    "/bundles/sonataadmin/",
    "/.env",
    "/.env.test",
    "/.env.example",
    "/.env.local",
    "/.env.prod",
    "/.git/HEAD",
    "/.git/config",
    "/.svn/entries",
    "/composer.json",
    "/package.json",
    "/yarn.lock",
    "/.htaccess",
    "/.htpasswd",
    "/.DS_Store",
    "/server-status",
    "/server-info",
    "package-lock.json",
    "npm-shrinkwrap.json",
    "node_modules/",
    "/maintenance",
    "/register",
    "/register/check-email",
    "/register/confirmed",
    "/login", "/logout",
    "/resetting/request",
    "/resetting/check-email",
    "/resetting/reset",
    "/resetting/reset/abcdef1234",
    "/profile",
    "/profile/edit",
    "/profile/show",
    "/profile/change-password",
    "/confirm/abcdef1234",
    "/reset-password",
    "/reset-password/reset",
    "/reset-password/reset/abcdef1234",
    "/verify/email",
    "/verify-email",
    "/verify-email/abcdef1234",
    "/2fa",
    "/2fa_check",
    "/2fa/qr-code",
    "/api",
    "/api/docs",
    "/api/docs.jsonld",
    "/api/docs.json",
    "/api/contexts/EntryPoint",
    "/docs",
    "/swagger.json",
    "/openapi.json",
    "/graphql",
    "/graphiql",
    "/graphql-playground",
    "/login_check",
    "/api/login_check",
    "/token/refresh",
    "/api/token/refresh",
    "/oauth/v2/token",
    "/oauth/v2/auth",
    "/oauth/authorize",
    "/oauth/token",
    "/oauth/refresh_token",
    "/connect/",
    "/easyadmin",
    "/admin/logout",
    "/admin/resetting/request",
    "/admin/resetting/reset/abcdef",
    "/adminer",
    "/adminer.php",
    "/_profiler/abcdef",
    "/_wdt/abcdef",
    "/_errors/500",
    "/phpinfo.php",
    "/info.php",
    "/index.php",
    "/app.php",
    "/app_dev.php",
    "/bundles/",
    "/vendor/",
    "/composer.lock",
    "/symfony.lock",
    "/health",
    "/healthz",
    "/ready",
    "/status",
    "/ping",
    "/_ping",
    "/metrics",
    "/robots.txt",
    "/sitemap.xml",
    "/sitemap_index.xml",
    "/sitemap.xml.gz",
    "/sitemap1.xml",
    "/sitemap2.xml",
    "/.well-known/security.txt",
    "/.well-known/change-password",
    "/.well-known/openid-configuration",
    "/.well-known/jwks.json",
    "/.well-known/assetlinks.json",
    "/.well-known/apple-app-site-association",
]

BACKUP_PATHS: List[str] = [
    "/backup/", "/backups/", "/_backup/", "/_backups/",
    "/var/backups/", "/storage/backups/", "/tmp/backups/",
    "/db/backup/", "/database/backup/", "/mysql/backup/", "/pg/backup/",
    "/dump.sql", "/dump.sql.gz", "/dump.sql.zip", "/dump.tar.gz",
    "/database.sql", "/database.sql.gz", "/database.sql.zip",
    "/db.sql", "/db.sql.gz", "/db.sql.zip",
    "/export.sql", "/export.sql.gz",
    "/mysql.sql", "/postgres.sql",
    "/backup.sql", "/backup.sql.gz", "/backup.tar.gz",
    "/.env.bak", "/.env.backup", "/.env.old", "/.env~",
    "/.env.local.bak", "/.env.prod.bak",
    "/parameters.yml.bak", "/parameters.yml~", "/parameters.yaml.bak",
    "/config/packages/prod/framework.yaml.bak",
    "/composer.json.bak", "/composer.lock.bak",
    "/symfony.lock.bak", "/.htaccess.bak", "/.htaccess~",
    "/backup.zip", "/backups.zip", "/site-backup.zip",
    "/backup.tar", "/backup.tar.gz", "/backup.tgz",
    "/full-backup.zip", "/public-backup.zip", "/app-backup.zip",
    "/.env.save", "/.env.tmp", "/.env.swp", "/.env.swo",
    "/parameters.yml.orig", "/parameters.yml.save",
    "/.env.copy", "/.env.tmp.bak",
]

# Generador de candidatos de backup
SENSITIVE_BASENAMES = [
    ".env", ".env.local", ".env.prod",
    "composer.json", "composer.lock", "symfony.lock",
    "parameters.yml", "parameters.yaml",
    "config/packages/prod/framework.yaml",
    "config/services.yaml", ".htaccess",
    "public/index.php", "app.php", "app_dev.php",
]
BACKUP_SUFFIXES = [".bak", ".old", ".orig", ".save", "~", ".tmp", ".swp", ".swo",
                   ".zip", ".tar", ".tar.gz", ".tgz", ".gz", ".7z", ".rar"]
BACKUP_DIRS = ["/", "/public/", "/web/", "/var/", "/var/backups/", "/backup/", "/backups/", "/tmp/", "/storage/backups/"]

def gen_backup_candidates() -> List[str]:
    out: List[str] = []
    for base in SENSITIVE_BASENAMES:
        for d in BACKUP_DIRS:
            for suf in BACKUP_SUFFIXES:
                out.append(f"{d}{base}{suf}")
    dump_names = ["dump", "database", "db", "backup", "export", "mysql", "postgres"]
    dump_exts  = [".sql", ".sql.gz", ".sql.zip", ".tar.gz", ".zip", ".tgz"]
    for d in BACKUP_DIRS:
        for n in dump_names:
            for ext in dump_exts:
                out.append(f"{d}{n}{ext}")
    out += [
        "/backup/", "/backups/", "/_backup/", "/_backups/",
        "/db/backup/", "/database/backup/", "/mysql/backup/", "/pg/backup/",
        "/storage/backups/", "/var/backups/", "/tmp/backups/"
    ]
    seen = set(); uniq: List[str] = []
    for p in out:
        if p not in seen:
            uniq.append(p); seen.add(p)
    return uniq

# =========================
# Smart placeholders & fuzz
# =========================

PLACEHOLDER_RE = re.compile(r"\{([A-Za-z_][A-Za-z0-9_]*)\}")

SEED_VALUES: Dict[str, str] = {
    "id": "1",
    "token": "abcdef1234",
    "slug": "test-slug",
    "provider": "google",
    "code": "404",
    "_format": "json",
    "fontName": "OpenSans-Regular",
}

FUZZ_CATALOG: Dict[str, List[str]] = {
    "id": ["1","2","3","5","10","25","50","100","999","0","-1"],
    "token": [
        "abcdef1234",
        "deadbeef",
        "0123456789abcdef",
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "12345678",
        "0000000000000000",
        "cafebabedeadbeef",
    ],
    "slug": ["test","admin","profile","config","sitemap","api","graphql","docs"],
    "provider": ["google","github","facebook","twitter","microsoft","azure","apple"],
    "code": ["200","302","400","401","403","404","500"],
    "_format": ["json","html","xml","txt"],
    "fontName": ["OpenSans-Regular","Roboto-Regular","Inter-Regular","NotoSans-Regular"],
}

def find_placeholders(p: str) -> List[str]:
    return PLACEHOLDER_RE.findall(p)

def substitute(p: str, mapping: Dict[str, str]) -> str:
    def _rep(m: re.Match) -> str:
        key = m.group(1)
        return mapping.get(key, m.group(0))
    return PLACEHOLDER_RE.sub(_rep, p)

def initial_variant_for(p: str) -> Tuple[str, List[str]]:
    keys = find_placeholders(p)
    if not keys:
        return p, []
    mapping = {k: SEED_VALUES.get(k, "1") for k in keys}
    return substitute(p, mapping), keys

def gen_fuzz_variants(p_template: str, keys: List[str], limit: int) -> List[str]:
    vals_by_key: List[Tuple[str, List[str]]] = []
    for k in keys:
        vals = FUZZ_CATALOG.get(k, [SEED_VALUES.get(k, "1")])
        vals_by_key.append((k, vals[:limit]))

    variants: List[str] = []
    def _recurse(idx: int, current: Dict[str, str]):
        nonlocal variants
        if len(variants) >= max(limit, 1) * len(keys):
            return
        if idx == len(vals_by_key):
            variants.append(substitute(p_template, current))
            return
        k, vals = vals_by_key[idx]
        for v in vals:
            current[k] = v
            _recurse(idx + 1, current)
        current.pop(k, None)
    _recurse(0, {})
    seen=set(); out=[]
    for v in variants:
        if v not in seen:
            out.append(v); seen.add(v)
    return out

# =========================
# HTTP helpers
# =========================

DEFAULT_HEADERS: Dict[str, str] = {
    "User-Agent": "Mozilla/5.0 (compatible; SymfonyScanner/1.3.0)",
    "Accept": "*/*",
}

def banner() -> None:
    print("====================================================================================")
    ascii_art = r"""
░▒▓████████▓▒░▒▓███████▓▒░░▒▓███████▓▒░░▒▓███████▓▒░ ░▒▓██████▓▒░░▒▓█▓▒░▒▓███████▓▒░▒▓████████▓▒░ 
░▒▓█▓▒░      ░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░ ░▒▓█▓▒░     
░▒▓█▓▒░      ░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░ ░▒▓█▓▒░     
░▒▓██████▓▒░ ░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓███████▓▒░░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░ ░▒▓█▓▒░     
░▒▓█▓▒░      ░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░      ░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░ ░▒▓█▓▒░     
░▒▓█▓▒░      ░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░      ░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░ ░▒▓█▓▒░     
░▒▓████████▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓███████▓▒░░▒▓█▓▒░       ░▒▓██████▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░ ░▒▓█▓▒░
    """
    print(ascii_art)
    print("     ☠️ Symfony Endpoint Scanner v1.4.0 ☠️     ")
    print("   Escaneo Symfony + fallback HTTP + dual-scan   ")
    print("===================================================================================\n")

# ------------------------
# Rate limiter simple
# ------------------------
class RateLimiter:
    def __init__(self, rps: float):
        if rps <= 0:
            raise ValueError("rps must be > 0")
        self.interval = 1.0 / float(rps)
        self._lock = threading.Lock()
        self._next_allowed = time.monotonic()

    def acquire(self) -> None:
        with self._lock:
            now = time.monotonic()
            if now < self._next_allowed:
                to_sleep = self._next_allowed - now
                time.sleep(to_sleep)
                now = time.monotonic()
            self._next_allowed = now + self.interval

def build_session(timeout: int, retries: int, backoff: float, verify_tls: bool, proxy: Optional[str]) -> requests.Session:
    sess = requests.Session()
    retry = Retry(
        total=retries, read=retries, connect=retries, status=retries,
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
    sess.request_timeout = timeout  # type: ignore[attr-defined]

    sess._rate_limiter = None  # type: ignore[attr-defined]
    sess._request_delay = 0.0  # type: ignore[attr-defined]
    sess._request_jitter = 0.0  # type: ignore[attr-defined]

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
    return code in (200, 301, 302, 401, 403)

def symfony_fingerprints(resp: requests.Response, body_sample: Optional[str]) -> List[str]:
    hints: List[str] = []
    if resp.headers.get("X-Debug-Token"):
        hints.append("X-Debug-Token presente (Symfony Profiler)")
    if resp.headers.get("X-Debug-Token-Link"):
        hints.append("X-Debug-Token-Link presente (Symfony Profiler link)")
    if "easyadmin" in resp.url.lower():
        hints.append("Ruta relacionada con EasyAdmin")
    try:
        ctype = resp.headers.get("Content-Type", "")
        if body_sample and ("routes" in body_sample and "base_url" in body_sample and "prefix" in body_sample):
            hints.append("Estructura FOSJsRouting detectada")
        if resp.request.path_url.endswith(("manifest.json", "entrypoints.json")):  # type: ignore[attr-defined]
            hints.append("Archivo de Encore (manifest/entrypoints)")
    except Exception:
        pass
    return hints

# ------------------------
# Host status tracking (thread-safe)
# ------------------------
host_status_lock = threading.Lock()
host_status: Dict[str, str] = {}  # netloc -> one of: HTTPS-only, HTTP-only, Dual, HTTPS-broken-API, Unknown

def set_host_status(netloc: str, status: str) -> None:
    with host_status_lock:
        prev = host_status.get(netloc)
        # Prefer statuses with more information, but allow overrides in some cases
        if prev == status:
            return
        # If switching from Unknown -> something, set it
        if not prev or prev == "Unknown":
            host_status[netloc] = status
            return
        # If previously HTTPS-only and now HTTP also works, set Dual
        if prev == "HTTPS-only" and status == "HTTP-only":
            host_status[netloc] = "Dual"
            return
        if prev == "HTTP-only" and status == "HTTPS-only":
            host_status[netloc] = "Dual"
            return
        # If HTTPS-only and now we detect HTTPS-broken-API but HTTP works => HTTPS-broken-API
        if status == "HTTPS-broken-API":
            host_status[netloc] = status
            return
        # Otherwise keep previous
        host_status[netloc] = status

def get_host_status(netloc: str) -> str:
    with host_status_lock:
        return host_status.get(netloc, "Unknown")

# ------------------------
# Probe logic: detect schemes alive for host
# ------------------------
def probe_host(session: requests.Session, netloc: str, follow: bool, head_first: bool) -> None:
    """
    Probe root (/) on https and http for a given netloc and register host_status.
    """
    https_url = urlunparse(("https", netloc, "/", "", "", ""))
    http_url = urlunparse(("http", netloc, "/", "", "", ""))
    https_ok = False
    http_ok = False
    https_broken_api = False

    # Try HTTPS
    try:
        if head_first:
            r = session.head(https_url, allow_redirects=follow, timeout=session.request_timeout)
            if r.status_code in (405, 501):
                r = session.get(https_url, allow_redirects=follow, timeout=session.request_timeout)
        else:
            r = session.get(https_url, allow_redirects=follow, timeout=session.request_timeout)
        if r.status_code < 500:
            https_ok = True
        else:
            https_broken_api = True
    except Exception:
        https_ok = False

    # Try HTTP :)
    try:
        if head_first:
            r2 = session.head(http_url, allow_redirects=follow, timeout=session.request_timeout)
            if r2.status_code in (405, 501):
                r2 = session.get(http_url, allow_redirects=follow, timeout=session.request_timeout)
        else:
            r2 = session.get(http_url, allow_redirects=follow, timeout=session.request_timeout)
        if r2.status_code < 500:
            http_ok = True
    except Exception:
        http_ok = False

    if https_ok and http_ok:
        set_host_status(netloc, "Dual")
    elif https_ok and not http_ok:
        set_host_status(netloc, "HTTPS-only")
    elif http_ok and not https_ok:
        set_host_status(netloc, "HTTP-only")
    elif https_broken_api and http_ok:
        set_host_status(netloc, "HTTPS-broken-API")
    else:
        set_host_status(netloc, "Unknown")

# ------------------------
# Enhanced fetch with fallback to HTTP when appropriate
# ------------------------
def fetch(session: requests.Session, base: str, path: str, follow: bool, head_first: bool, extra_headers: Dict[str, str], head_fallback_get: bool = True, prefer_http: bool = False) -> Dict[str, Any]:
    """
    base should be a scheme+netloc (e.g. https://example.com) or a full base URL without trailing slash.
    This function respects session._rate_limiter and session._request_delay/_request_jitter.
    If prefer_http=True it will try http before https for bases that are ambiguous.
    It implements a one-time fallback from https -> http on certain failures.
    """
    # Rate limiting
    rl = getattr(session, "_rate_limiter", None)
    if rl is not None:
        try:
            rl.acquire()
        except Exception:
            pass

    # Per-request delay + jitter
    try:
        d = float(getattr(session, "_request_delay", 0.0) or 0.0)
        j = float(getattr(session, "_request_jitter", 0.0) or 0.0)
        if d > 0 or j > 0:
            if j > 0:
                jitter = random.uniform(-j, j)
                to_sleep = max(0.0, d + jitter)
            else:
                to_sleep = d
            if to_sleep > 0:
                time.sleep(to_sleep)
    except Exception:
        pass

    # Build URL
    url = urljoin(base.rstrip("/") + "/", path.lstrip("/"))
    parsed = urlparse(url)
    netloc = parsed.netloc
    scheme = parsed.scheme

    t0 = time.time()
    tried_http_fallback = False

    def _do_request(u: str):
        try:
            if head_first:
                resp = session.head(u, allow_redirects=follow, timeout=session.request_timeout, headers=extra_headers)  # type: ignore[attr-defined]
                if resp.status_code in (405, 501) or ("content-type" not in resp.headers and head_fallback_get):
                    resp = session.get(u, allow_redirects=follow, timeout=session.request_timeout, headers=extra_headers)  # type: ignore[attr-defined]
            else:
                resp = session.get(u, allow_redirects=follow, timeout=session.request_timeout, headers=extra_headers)  # type: ignore[attr-defined]
            return resp
        except Exception as e:
            raise

    try:
        resp = None
        # Possibly prefer HTTP
        host_state = get_host_status(netloc)
        # If prefer_http flag enabled globally or host is HTTP-only, use http first
        if prefer_http or host_state == "HTTP-only":
            alt_url = urlunparse(("http", netloc, parsed.path, parsed.params, parsed.query, parsed.fragment))
            try:
                resp = _do_request(alt_url)
                set_host_status(netloc, "HTTP-only" if get_host_status(netloc) == "Unknown" else get_host_status(netloc))
                url_used = alt_url
            except Exception:
                # try original
                resp = _do_request(url)
                url_used = url
        else:
            # default: try provided scheme first
            try:
                resp = _do_request(url)
                url_used = url
            except Exception as e:
                # If original was https, attempt HTTP fallback once
                if scheme == "https":
                    # avoid duplicate attempts if host probe already said HTTP dead
                    http_url = urlunparse(("http", netloc, parsed.path, parsed.params, parsed.query, parsed.fragment))
                    try:
                        resp = _do_request(http_url)
                        tried_http_fallback = True
                        set_host_status(netloc, "HTTP-only" if get_host_status(netloc) in ("Unknown","HTTPS-broken-API") else get_host_status(netloc))
                        url_used = http_url
                    except Exception:
                        raise
                else:
                    raise

        dt = time.time() - t0

        body_sample: Optional[str] = None
        try:
            ctype = resp.headers.get("Content-Type", "")
            if ctype and (ctype.startswith("text/") or "json" in ctype):
                body_sample = resp.text[:1000]
        except Exception:
            body_sample = None

        # If response indicates server error (5xx) and original scheme was https and we didn't try http fallback yet,
        # try http once (to detect HTTPS-broken-API)
        if resp is not None and resp.status_code >= 500 and scheme == "https" and not tried_http_fallback and get_host_status(netloc) != "HTTP-only":
            http_url = urlunparse(("http", netloc, parsed.path, parsed.params, parsed.query, parsed.fragment))
            try:
                r2 = _do_request(http_url)
                # if HTTP works better, mark accordingly
                if r2.status_code < 500:
                    set_host_status(netloc, "HTTPS-broken-API")
                    # prefer returning the HTTP result (so it's visible)
                    resp = r2
                    url_used = http_url
            except Exception:
                pass

        # If succeeded, update host status if unknown
        if resp is not None:
            if scheme == "https" and resp.status_code < 500 and get_host_status(netloc) in ("Unknown",):
                # if http also works, probe_host will later set Dual; we set HTTPS-only tentatively
                set_host_status(netloc, "HTTPS-only")
            if scheme == "http" and resp.status_code < 500 and get_host_status(netloc) in ("Unknown",):
                set_host_status(netloc, "HTTP-only")

        hints = symfony_fingerprints(resp, body_sample) if resp is not None else []
        result: Dict[str, Any] = {
            "url": url_used,
            "path": path,
            "status": resp.status_code if resp is not None else None,
            "reason": getattr(resp, "reason", None) if resp is not None else None,
            "content_type": resp.headers.get("Content-Type") if resp is not None else None,
            "length": resp.headers.get("Content-Length") if resp is not None else None,
            "location": resp.headers.get("Location") if resp is not None else None,
            "elapsed_ms": int(dt * 1000),
            "hints": hints,
        }
        return result
    except requests.RequestException as e:
        # If it's a requests exception and original scheme was https, try http fallback once
        if scheme == "https" and not tried_http_fallback and get_host_status(netloc) != "HTTP-only":
            http_url = urlunparse(("http", netloc, parsed.path, parsed.params, parsed.query, parsed.fragment))
            try:
                r2 = _do_request(http_url)
                dt = time.time() - t0
                body_sample = None
                try:
                    ctype = r2.headers.get("Content-Type", "")
                    if ctype and (ctype.startswith("text/") or "json" in ctype):
                        body_sample = r2.text[:1000]
                except Exception:
                    body_sample = None
                hints = symfony_fingerprints(r2, body_sample)
                set_host_status(netloc, "HTTP-only")
                return {
                    "url": http_url,
                    "path": path,
                    "status": r2.status_code,
                    "reason": getattr(r2, "reason", None),
                    "content_type": r2.headers.get("Content-Type"),
                    "length": r2.headers.get("Content-Length"),
                    "location": r2.headers.get("Location"),
                    "elapsed_ms": int(dt * 1000),
                    "hints": hints,
                }
            except Exception:
                pass
        return {"url": url, "path": path, "error": str(e)}

# ------------------------
# Remaining helpers (load_wordlist, save_results) - unchanged
# ------------------------
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

# =========================
# Main
# =========================

def main() -> None:
    banner()
    parser = argparse.ArgumentParser(description="Escanea rutas públicas típicas de Symfony (rápido, concurrente, con smart fuzz).")
    parser.add_argument("url", help="URL base (ej: https://example.com) — admite esquema http/https")
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

    # NEW FLAGS
    parser.add_argument("--smart-fuzz", action="store_true", help="Si un endpoint con placeholders devuelve 200, fuzzear valores de prueba (id, token, slug, etc.).")
    parser.add_argument("--fuzz-limit", type=int, default=8, help="Máximo de combinaciones por placeholder (aprox).")
    parser.add_argument("--fuzz-threads", type=int, default=8, help="Hilos para fuzzing (aparte de --threads).")
    parser.add_argument("--delay", type=float, default=0.0, help="Delay fijo por petición en segundos (por hilo). Ej: 0.1")
    parser.add_argument("--jitter", type=float, default=0.0, help="Jitter +/- (s) aplicado a --delay, para evitar patrones exactos.")
    parser.add_argument("--rps", type=float, default=0.0, help="Requests por segundo global máximo (ej: 5). Si >0 se aplica rate limiter global.")
    parser.add_argument("--prefer-http", action="store_true", help="Probar HTTP antes que HTTPS (cuando tenga sentido).")
    parser.add_argument("--dual", action="store_true", help="Probar ambos esquemas (https y http) para cada ruta (duplica peticiones).")

    args = parser.parse_args()

    base_input = args.url.rstrip("/")
    if not base_input.startswith(("http://", "https://")):
        print(f"{Fore.YELLOW}[!] La URL no contiene esquema, asumiendo https://{Style.RESET_ALL}")
        base_input = "https://" + base_input

    allow_codes: Set[int] = set()
    if args.codes:
        try:
            allow_codes = {int(x.strip()) for x in args.codes.split(",") if x.strip()}
        except ValueError:
            print(f"{Fore.YELLOW}[!] --codes inválido, usando por defecto.{Style.RESET_ALL}")
            allow_codes = set()

    session = build_session(
        timeout=args.timeout,
        retries=args.retries,
        backoff=args.backoff,
        verify_tls=not args.insecure,
        proxy=args.proxy
    )

    extra_headers = parse_headers(args.header)
    if extra_headers:
        session.headers.update(extra_headers)

    # Configure rate limiter and delay
    if getattr(args, "rps", 0.0) and args.rps > 0:
        try:
            session._rate_limiter = RateLimiter(args.rps)  # type: ignore[attr-defined]
            print(f"{Fore.YELLOW}[!] Rate limiter global activado: {args.rps} req/s{Style.RESET_ALL}")
        except Exception as e:
            print(f"{Fore.YELLOW}[!] No se pudo inicializar rate limiter: {e}{Style.RESET_ALL}")

    session._request_delay = float(getattr(args, "delay", 0.0) or 0.0)  # type: ignore[attr-defined]
    session._request_jitter = float(getattr(args, "jitter", 0.0) or 0.0)  # type: ignore[attr-defined]
    if session._request_delay > 0 or session._request_jitter > 0:
        print(f"{Fore.YELLOW}[!] Delay por petición: {session._request_delay}s ±{session._request_jitter}s{Style.RESET_ALL}")

    # --- Preparar objetivos: expandimos plantillas a una variante inicial ---
    raw_targets = COMMON_PATHS + BACKUP_PATHS + gen_backup_candidates() + args.paths + load_wordlist(args.wordlist)
    seen = set(); raw_targets = [t for t in raw_targets if not (t in seen or seen.add(t))]

    # Build per-host list and do probes
    parsed_base = urlparse(base_input)
    base_netloc = parsed_base.netloc
    base_scheme = parsed_base.scheme

    # For simplicity we only probe the specified host. If you pass multiple hosts, adapt accordingly.
    print(f"{Fore.CYAN}» Probeando esquemas para host: {base_netloc}{Style.RESET_ALL}")
    # set Unknown initially
    set_host_status(base_netloc, "Unknown")
    try:
        probe_host(session, base_netloc, args.follow, args.head_first)
    except Exception:
        pass
    print(f"{Fore.CYAN}» Estado detectado: {get_host_status(base_netloc)}{Style.RESET_ALL}\n")

    # Build scan_items: each item includes base (scheme+netloc), path, template, keys, phase
    ScanItem = Dict[str, Any]
    scan_items: List[ScanItem] = []
    for p in raw_targets:
        sub, keys = initial_variant_for(p)
        if args.dual:
            # create both https and http base entries
            https_base = urlunparse(("https", base_netloc, "", "", "", ""))
            http_base = urlunparse(("http", base_netloc, "", "", "", ""))
            if keys:
                scan_items.append({"base": https_base, "template": p, "path": sub, "keys": keys, "phase": "base"})
                scan_items.append({"base": http_base, "template": p, "path": sub, "keys": keys, "phase": "base"})
            else:
                scan_items.append({"base": https_base, "template": None, "path": p, "keys": [], "phase": "base"})
                scan_items.append({"base": http_base, "template": None, "path": p, "keys": [], "phase": "base"})
        else:
            # choose base according to input scheme or prefer-http flag or host probe
            chosen_scheme = base_scheme
            host_state = get_host_status(base_netloc)
            if args.prefer_http:
                chosen_scheme = "http"
            else:
                # if host probe said HTTP-only, use http; if HTTPS-only, use https; else use user input
                if host_state == "HTTP-only":
                    chosen_scheme = "http"
                elif host_state == "HTTPS-only":
                    chosen_scheme = "https"
                # else keep base_scheme
            chosen_base = urlunparse((chosen_scheme, base_netloc, "", "", "", ""))
            if keys:
                scan_items.append({"base": chosen_base, "template": p, "path": sub, "keys": keys, "phase": "base"})
            else:
                scan_items.append({"base": chosen_base, "template": None, "path": p, "keys": [], "phase": "base"})

    print(f"☠️ Escaneando endpoints comunes de Symfony en: {Fore.CYAN}{base_input}{Style.RESET_ALL}")
    print(f"☠️ Objetivos base: {len(scan_items)} | Hilos: {args.threads} | Timeout: {args.timeout}s\n")

    results: List[Dict[str, Any]] = []
    ok_count = 0
    err_count = 0
    match_count = 0

    # Ejecutamos fase base
    with ThreadPoolExecutor(max_workers=args.threads) as ex:
        future_map = {ex.submit(
            fetch, session, it["base"], it["path"], args.follow, args.head_first, extra_headers, True, args.prefer_http
        ): it for it in scan_items}

        fuzz_queue: List[ScanItem] = []

        for fut in as_completed(future_map):
            r = fut.result()
            it = future_map[fut]
            r["phase"] = it["phase"]
            if it["template"]:
                r["template"] = it["template"]
                r["placeholders"] = ",".join(it["keys"])
            results.append(r)

            if "error" in r:
                err_count += 1
                print(f"{Fore.RED}[!] Error{Style.RESET_ALL} {r.get('url','?')} => {r['error']}")
                continue

            code = r.get("status")
            interesting = is_interesting_status(code, allow_codes) if code is not None else False
            color = Fore.GREEN if interesting else Fore.LIGHTBLACK_EX

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
            phase = f"[{r.get('phase')}]" if r.get("phase") else ""

            sign = "[+]" if interesting else "[-]"
            print(f"{color}{sign} {phase} {r.get('url','?')} (Status {code}){ms}{ctype}{size}{loc}{hints}{Style.RESET_ALL}")

            # Programar fuzzing si aplica
            if args.smart_fuzz and code == 200 and it.get("template") and it.get("keys"):
                variants = gen_fuzz_variants(it["template"], it["keys"], args.fuzz_limit)
                base_used = it["base"]
                variants = [v for v in variants if v != it["path"]]
                for v in variants:
                    fuzz_queue.append({"base": base_used, "template": it["template"], "path": v, "keys": it["keys"], "phase": "fuzz", "parent": it["path"]})

    # Ejecutar fuzzing
    if args.smart_fuzz and fuzz_queue:
        print(f"\n{Fore.MAGENTA}» Lanzando fuzzing dirigido:{Style.RESET_ALL} {len(fuzz_queue)} variantes | hilos={args.fuzz_threads}\n")
        with ThreadPoolExecutor(max_workers=args.fuzz_threads) as ex2:
            future_map2 = {ex2.submit(
                fetch, session, it["base"], it["path"], args.follow, args.head_first, extra_headers, True, args.prefer_http
            ): it for it in fuzz_queue}

            for fut in as_completed(future_map2):
                r = fut.result()
                it = future_map2[fut]
                r["phase"] = it["phase"]
                r["template"] = it.get("template")
                r["placeholders"] = ",".join(it.get("keys", []))
                r["parent"] = it.get("parent")
                results.append(r)

                if "error" in r:
                    err_count += 1
                    print(f"{Fore.RED}[!] Error (fuzz){Style.RESET_ALL} {r.get('url','?')} => {r['error']}")
                    continue

                code = r.get("status")
                interesting = is_interesting_status(code, allow_codes) if code is not None else False
                color = Fore.GREEN if interesting else Fore.LIGHTBLACK_EX

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
                parent = f" [parent={r.get('parent')}]" if r.get("parent") else ""
                phase = f"[{r.get('phase')}]" if r.get("phase") else ""

                sign = "[+]" if interesting else "[-]"
                print(f"{color}{sign} {phase} {r.get('url','?')} (Status {code}){ms}{ctype}{size}{loc}{parent}{hints}{Style.RESET_ALL}")

    # Final summary
    print()
    if args.codes:
        print(f"{Fore.CYAN}Resumen:{Style.RESET_ALL} coinciden={match_count} | interesantes={ok_count} | errores={err_count} | total_vistos={len(results)}")
    else:
        print(f"{Fore.CYAN}Resumen:{Style.RESET_ALL} interesantes={ok_count} | errores={err_count} | total={len(results)}")

    # Print final host status
    print(f"\n{Fore.CYAN}Host status:{Style.RESET_ALL} {base_netloc} = {get_host_status(base_netloc)}")

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