#!/usr/bin/env python3

import subprocess
import re
from datetime import datetime
import os
from collections import defaultdict

LOG_ALARMAS = "/var/log/hips/alarmas.log"
LOG_PREVENCION = "/var/log/hips/prevencion.log"
MSMTP_LOG = os.path.expanduser("~/.msmtp.log")
HTTP_LOG = "/var/log/apache2/access.log"
DESTINATARIO = "eliasdavidroman@gmail.com"
LIMITE_INTENTOS = 5

# Crea el directorio del log si no existe (por si es la primera vez que se ejecuta)
os.makedirs(os.path.dirname(LOG_ALARMAS), exist_ok=True)

# ------------------------------------------------------
# Devuelve la fecha y hora formateada para encabezados de mensajes
def encabezado_fecha():
    return f"[{datetime.now().strftime('%d/%m/%Y %H:%M')}]"

# ------------------------------------------------------
# Función para registrar eventos en un log (por defecto, en el de alarmas)
def registrar_log(tipo, mensaje, ip="N/A", archivo=LOG_ALARMAS):
    fecha = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    log = f"{fecha} :: {tipo} :: {ip} :: {mensaje}\n"
    with open(archivo, 'a') as f:
        f.write(log)

# ------------------------------------------------------
# Envía un correo de alerta con asunto y cuerpo personalizados
def enviar_mail(asunto, cuerpo):
    mensaje = f"Subject: {asunto}\n\n{cuerpo}"
    try:
        subprocess.run(['msmtp', DESTINATARIO], input=mensaje.encode(), check=True)
        print("[+] Correo enviado.")
    except Exception as e:
        print(f"[!] Error al enviar correo: {e}")

# ------------------------------------------------------
# Bloquea una IP con iptables si no es localhost y aún no está bloqueada
def bloquear_ip(ip):
    if ip in {"127.0.0.1", "::1"}:
        return "IP local detectada, no se bloqueó"
    try:
        reglas = subprocess.check_output(['iptables', '-L', 'INPUT', '-n']).decode()
        if ip not in reglas:
            subprocess.run(['iptables', '-A', 'INPUT', '-s', ip, '-j', 'DROP'], check=True)
            registrar_log("Prevención", "IP bloqueada por intentos fallidos", ip, LOG_PREVENCION)
            return "IP bloqueada exitosamente con iptables"
        else:
            return "IP ya estaba bloqueada previamente"
    except Exception as e:
        return f"Error al intentar bloquear IP: {e}"

# ------------------------------------------------------
# Verifica si una IP ya fue alertada anteriormente, para evitar duplicar notificaciones
def ip_ya_alertada(ip):
    if not os.path.exists(LOG_ALARMAS):
        return False
    with open(LOG_ALARMAS) as f:
        return any(ip in linea for linea in f)

# ------------------------------------------------------
# Analiza los últimos 10 minutos del log SSH (journalctl)
# Busca intentos fallidos de login y registra o bloquea si exceden el límite
def analizar_fallos_journalctl():
    print("[i] Analizando intentos SSH...")
    ip_fails = {}         # Conteo de intentos fallidos por IP
    usuario_fails = {}    # Conteo de intentos por usuario
    ip_usuarios = {}      # Qué usuarios intentaron acceder desde cada IP

    try:
        salida = subprocess.check_output(
            ['journalctl', '-u', 'ssh', '--no-pager', '--since', '10 minutes ago'],
            stderr=subprocess.DEVNULL
        ).decode()

        # Recorre cada línea del log buscando coincidencias
        for linea in salida.splitlines():
            if "Failed password" in linea:
                match_ip = re.search(r'from ([\d.:a-fA-F]+)', linea)
                ip = match_ip.group(1) if match_ip else None
                user_match = re.search(r'Failed password for (invalid user )?(\w+)', linea)
                usuario = user_match.group(2) if user_match else "desconocido"

                if ip:
                    ip_fails[ip] = ip_fails.get(ip, 0) + 1
                    usuario_fails[usuario] = usuario_fails.get(usuario, 0) + 1
                    ip_usuarios.setdefault(ip, set()).add(usuario)

    except Exception as e:
        print(f"[!] Error journalctl: {e}")
        return

    # Verifica cuáles IPs superaron el límite de intentos
    for ip, intentos in ip_fails.items():
        if intentos >= LIMITE_INTENTOS:
            usuarios = ', '.join(ip_usuarios[ip])
            accion = bloquear_ip(ip)
            mensaje = (
                f"{intentos} fallos desde {ip}\n"
                f"Usuarios: {usuarios}\n"
                f"Prevención: {accion}"
            )
            registrar_log("Alarma", mensaje.replace("\n", " "), ip)
            enviar_mail("[HIPS] SSH: Fallos de autenticación", mensaje)

# ------------------------------------------------------
# Analiza el archivo de log de Apache para detectar múltiples errores HTTP
# Si una IP acumula muchos errores (4xx o 5xx), se alerta y se bloquea
def analizar_http_log():
    if not os.path.exists(HTTP_LOG):
        print("[!] Log HTTP no encontrado.")
        return

    print("[i] Analizando errores HTTP...")
    errores_por_ip = defaultdict(int)
    with open(HTTP_LOG) as f:
        for linea in f:
            match = re.search(r'^(\S+).+" \d{3}', linea)
            if match:
                ip = match.group(1)
                status = re.search(r'" (\d{3}) ', linea)
                if status and status.group(1).startswith(("4", "5")):
                    errores_por_ip[ip] += 1

    # Si una IP tiene muchos errores y no fue alertada antes, se bloquea
    for ip, errores in errores_por_ip.items():
        if errores >= LIMITE_INTENTOS and not ip_ya_alertada(ip):
            accion = bloquear_ip(ip)
            mensaje = (
                f"{encabezado_fecha()}\n"
                f"{errores} errores HTTP desde {ip}\n"
                f"Prevención: {accion}"
            )
            registrar_log("Alarma", mensaje.replace("\n", " "), ip)
            enviar_mail("[HIPS] HTTP: Accesos indebidos", mensaje)

# ------------------------------------------------------
# Analiza el log de msmtp para detectar si algún remitente envió muchos correos
# Si ocurre, se genera alerta y se limpia el log para evitar sobrecarga
def analizar_correo_msmtp():
    if not os.path.exists(MSMTP_LOG):
        print("[!] Log msmtp no encontrado.")
        return

    print("[i] Analizando msmtp.log...")
    cuentas = defaultdict(int)
    with open(MSMTP_LOG) as f:
        for linea in f:
            match = re.search(r'from=(\S+)', linea)
            if match:
                remitente = match.group(1)
                cuentas[remitente] += 1

    for cuenta, cantidad in cuentas.items():
        if cantidad >= LIMITE_INTENTOS:
            mensaje = (
                f"{encabezado_fecha()}\n"
                f"{cantidad} correos enviados desde {cuenta}\n"
                f"Prevención: vaciar el log para evitar saturación"
            )
            registrar_log("Alarma", mensaje.replace("\n", " "), "N/A")
            registrar_log("Prevención", f"Se vació el log de msmtp tras detectar envío masivo desde {cuenta}", "N/A", LOG_PREVENCION)
            enviar_mail("[HIPS] Envío de correos masivos", mensaje)

            # Limpia el archivo de log para prevenir spam continuo
            try:
                with open(MSMTP_LOG, 'w') as f:
                    f.write("")
                print("[+] Log de correos msmtp limpiado.")
            except Exception as e:
                print(f"[!] Error al limpiar log msmtp: {e}")

# ------------------------------------------------------
# Función principal que ejecuta todas las verificaciones del módulo
def main():
    analizar_fallos_journalctl()
    analizar_http_log()
    analizar_correo_msmtp()

# ------------------------------------------------------
# Punto de entrada del script
if __name__ == "__main__":
    main()
