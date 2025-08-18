# Symfony Endpoint Scanner

Busca rutas públicas comunes de aplicaciones Symfony.

Desarrollado por **m10sec (2025)**.

---

## Descripción
Symfony Endpoint Scanner es una herramienta simple en Python que realiza peticiones HTTP a rutas comunes utilizadas en entornos Symfony. Su propósito es detectar endpoints expuestos como `/_profiler`, `/config.php`, `/admin`, `/login`, entre otros, que pueden representar vectores de ataque si están accesibles.

---

## Características

- Basado en `requests`
- Rutas predefinidas comunes en Symfony (debug, autenticación, APIs, rutas JS)
- Banner personalizado
- Modo consola con `argparse`
- Resultados con códigos HTTP indicativos (200, 301, 302, 403)

---

## Instalación

```bash
# Clonar el repositorio
$ git clone https://github.com/m10sec/Symfony-Endpoint-Scanner.git
$ cd Symfony-Endpoint-Scanner

# Crear entorno virtual (opcional)
$ python3 -m venv venv && source venv/bin/activate

# Instalar dependencias
$ pip3 install -r requirements.txt
```
---
## Uso

# [+] Escaneo rápido de rutas conocidas:

```bash
python3 SymfonyScanner.py https://example.com
```

# [+] Escaneo con wordlist adicional y seguimiento de redirecciones:

```bash
python3 SymfonyScanner.py https://example.com -w rutas.txt --follow
```
# Minimizar ruido en clientes:

```bash
--head-first --codes 200,301,302,401,403
```
Inspección en BurpSuite:
```bash
--proxy http://127.0.0.1:8080
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


## 🧪 Ejemplo de salida

```bash
==============================================

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
    
       Symfony Endpoint Scanner v1.2.0        
   Busca rutas públicas comunes de Symfony    
               by m10sec (2025)               
==============================================

🔍 Escaneando endpoints comunes de Symfony en: https://target.com 

[+] Posible endpoint válido: https://target.com/_profiler (Status: 200)
[-] No válido: https://target.com/build/vendor.js (Status: 404)
[+] Posible endpoint válido: https://target.com/login (Status: 403)

```
---

## 🙌 Apóyame

Si esta herramienta te ha sido útil o quieres apoyar futuros desarrollos, puedes invitarme un café ☕ o hacer una donación. ¡Cualquier apoyo cuenta!

[![Donate with PayPal](https://img.shields.io/badge/PayPal-Donate-blue.svg)](https://www.paypal.com/paypalme/moften)

---

## 📬 Contacto y redes

- 💌 Correo: [m10sec@proton.me](mailto:m10sec@proton.me)
- 🌐 Blog: [https://m10.com.mx](https://m10.com.mx)
- 🐦 Twitter: [@hack4lifemx](https://twitter.com/hack4lifemx)
- 💼 LinkedIn: [Francisco Santibañez](https://www.linkedin.com/in/franciscosantibanez)
- 🐙 GitHub: [github.com/m10sec](https://github.com/moften)

---

## 🛡️ Filosofía

Creo en un mundo donde los usuarios tienen control sobre su privacidad. Esta herramienta nace desde la trinchera del pentesting real, con amor por la libertad digital y el hacking con propósito.

---

⭐ Si te gustó este proyecto, dale una estrella en GitHub y compártelo con tu comunidad.

