# Symfony Endpoint Scanner

Busca rutas públicas comunes de aplicaciones Symfony.

Desarrollado por **m10sec (2025)**.

---

## 🔍 Descripción
Symfony Endpoint Scanner es una herramienta simple en Python que realiza peticiones HTTP a rutas comunes utilizadas en entornos Symfony. Su propósito es detectar endpoints expuestos como `/_profiler`, `/config.php`, `/admin`, `/login`, entre otros, que pueden representar vectores de ataque si están accesibles.

---

## ⚖️ Características

- Basado en `requests`
- Rutas predefinidas comunes en Symfony (debug, autenticación, APIs, rutas JS)
- Banner personalizado
- Modo consola con `argparse`
- Resultados con códigos HTTP indicativos (200, 301, 302, 403)

---

## 🚀 Instalación

```bash
# Clonar el repositorio
$ git clone https://github.com/m10sec/Symfony-Endpoint-Scanner.git
$ cd Symfony-Endpoint-Scanner

# Crear entorno virtual (opcional)
$ python3 -m venv venv && source venv/bin/activate

# Instalar dependencias
$ pip install -r requirements.txt

---

## 🧪 Ejemplo de salida

```bash
==============================================
       Symfony Endpoint Scanner v1.0          
   Busca rutas públicas comunes de Symfony    
               by m10sec (2025)               
==============================================

🔍 Escaneando endpoints comunes de Symfony en: https://demo.ejemplo.com

[+] Posible endpoint válido: https://demo.ejemplo.com/_profiler (Status: 200)
[-] No válido: https://demo.ejemplo.com/build/vendor.js (Status: 404)
[+] Posible endpoint válido: https://demo.ejemplo.com/login (Status: 403)

```


