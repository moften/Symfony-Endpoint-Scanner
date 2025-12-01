# 🏴‍☠️ Symfony Endpoint Scanner

Busca rutas públicas comunes de aplicaciones Symfony.

Desarrollado por **m10sec (2025)**.

---

## 🏴‍☠️ Descripción
Symfony Endpoint Scanner es una herramienta avanzada escrita en Python diseñada para analizar de forma exhaustiva servidores web que potencialmente ejecutan Symfony o frameworks similares.
El script realiza miles de peticiones HTTP controladas, detecta endpoints expuestos, identifica artefactos de desarrollo, localiza archivos de backup y dumps filtrados, y detecta huellas de tecnologías que podrían representar una superficie de ataque crítica.

Además, implementa fuzzing inteligente sobre plantillas parametrizadas para descubrir rutas internas o endpoints ocultos.

---

## Características
	•	Basado en requests con reintentos (Retry) y pool HTTP.
	•	Wordlist adicional y paths por CLI.
	•	HEAD primero (--head-first) y follow redirects (--follow).
	•	Proxy fácilmente integrable (Burp/ZAP).
	•	Filtrado de códigos interesantes (--codes) y modo verbose.
	•	Guardado en JSON o CSV.
	•	Detección de fingerprints Symfony (p. ej., X-Debug-Token, FOSJsRouting, Encore manifest/entrypoints).

---

## 🏴‍☠️ Instalación

```bash
# Clonar el repositorio
git clone https://github.com/m10often/Symfony-Endpoint-Scanner.git
cd Symfony-Endpoint-Scanner

# (Opcional) Entorno virtual
python3 -m venv venv && source venv/bin/activate

# Instalar dependencias
pip3 install -r requirements.txt
```
---
## 🏴‍☠️ Uso

# [+] Escaneo rápido de rutas conocidas:

```bash
python3 SymfonyScanner.py https://example.com
```

# [+] Mostrar solo resultados que coincidan con ciertos códigos y, si quieres ver también no coincidentes, añade --verbose.
```bash
python3 SymfonyScanner.py https://example.com --codes 200,301,302,403 --verbose
```

# [+] Escaneo con wordlist adicional y seguimiento de redirecciones:

```bash
python3 SymfonyScanner.py https://example.com -w rutas.txt --follow
```

# [+] Escaneo con limitación de tasa y guardar resultados:

```bash
python3 SymfonyScanner.py https://example.com --rps 4 --threads 20 --format json --out host_scan.json --codes 200,301,302 --save-all
```

# [+] inimizar ruido en clientes:

```bash
--head-first --codes 200,301,302,401,403
```
# [+] Inspección en BurpSuite (proxy):

```bash
--proxy http://127.0.0.1:8080
--insecure    # Desactiva verificación TLS
```
```bash
python3 SymfonyScanner.py https://example.com --proxy http://127.0.0.1:8080
```

# [+] Probar HEAD antes de GET (más corto en respuestas que soportan HEAD)
```bash
python3 SymfonyScanner.py https://example.com --head-first
```

# [+] Ralentizar por petición (delay) — por hilo
```bash
# cada hilo espera ~100ms antes de cada petición
python scanner.py https://example.com --threads 20 --delay 0.1
```

# Opciones:
```bash
	•	-w, --wordlist → Archivo de rutas adicionales.
	•	-p, --paths → Rutas extra por CLI (/health /metrics).
	•	--codes → Filtrar solo ciertos códigos de estado (200,301,302,403).
	•	--head-first → Intenta HEAD antes de GET (más sigiloso).
	•	--proxy → Enviar tráfico a un proxy (http://127.0.0.1:8080).
	•	--threads → Número de hilos concurrentes (default: 20).
	•	--format y --out → Guardar resultados en json o csv.
```

# Escanear una app Symfony filtrando solo respuestas relevantes:
```bash
python3 SymfonyScanner.py https://target.com --head-first --codes 200,301,302,401,403
```

# Las no coincidencias:
```bash
python3 SymfonyScanner.py https://target.com --head-first --codes 200,301,302,401,403 --verbose
```

# Escanear con wordlist y guardar en CSV:
```bash
python3 SymfonyScanner.py https://target.com -w symfony-common.txt --format csv --out resultados.csv
```

---


## 🏴‍☠️ Ejemplo de salida

```bash
====================================================================================
     ☠️ Symfony Endpoint Scanner v1.3.0 ☠️
   Busca rutas públicas comunes de Symfony
       + Smart placeholders & fuzzing
====================================================================================

☠️ Escaneando endpoints comunes de Symfony en: https://target.com 

[+] [base] https://target.com/_profiler (Status 200) (123 ms) [text/html] | X-Debug-Token presente (Symfony Profiler)
[-] [base] https://target.com/build/vendor.js (Status 404) (45 ms) [text/html]
[+] [base] https://target.com/_wdt/abcdef1234 (Status 200) (98 ms) [text/html]

» Lanzando fuzzing dirigido: 12 variantes | hilos=8

[+] [fuzz] https://target.com/_wdt/0000000000000000 (Status 200) (91 ms) [text/html] [parent=/ _wdt/abcdef1234]
[-] [fuzz] https://target.com/_wdt/deadbeef (Status 404) (87 ms) [text/html] [parent=/ _wdt/abcdef1234]

```
---

## 🏴‍☠️ Apóyame

Si esta herramienta te ha sido útil o quieres apoyar futuros desarrollos, puedes invitarme un café ☕ o hacer una donación. ¡Cualquier apoyo cuenta!

[![Donate with PayPal](https://img.shields.io/badge/PayPal-Donate-blue.svg)](https://www.paypal.com/paypalme/moften)

---

## 🏴‍☠️ Contacto y redes

- 💌 Correo: [m10sec@proton.me](mailto:m10sec@proton.me)
- 🌐 Blog: [https://m10.com.mx](https://m10.com.mx)
- 🐦 Twitter: [@hack4lifemx](https://twitter.com/hack4lifemx)
- 💼 LinkedIn: [Francisco Santibañez](https://www.linkedin.com/in/franciscosantibanez)
- 🐙 GitHub: [github.com/m10sec](https://github.com/moften)

---

## 🏴‍☠️ Filosofía

Creo en un mundo donde los usuarios tienen control sobre su privacidad. Esta herramienta nace desde la trinchera del pentesting real, con amor por la libertad digital y el hacking con propósito.

---

⭐ Si te gustó este proyecto, dale una estrella en GitHub y compártelo con tu comunidad.
Si este proyecto te sirve, puedes invitarme un café ☕
