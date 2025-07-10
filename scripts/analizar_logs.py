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

os.makedirs(os.path.dirname(LOG_ALARMAS), exist_ok=True)

def encabezado_fecha():
    return f"[{datetime.now().strftime('%d/%m/%Y %H:%M')}]"

def registrar_log(tipo, mensaje, ip="N/A", archivo=LOG_ALARMAS):
    fecha = datetime.now().strftime("%d/%m/%Y")
    log = f"{fecha} :: {tipo} :: {ip} :: {mensaje}\n"
    with open(archivo, 'a') as f:
        f.write(log)

def enviar_mail(asunto, cuerpo):
    mensaje = f"Subject: {asunto}\n\n{cuerpo}"
    try:
        subprocess.run(['msmtp', DESTINATARIO], input=mensaje.encode(), check=True)
        print("[+] Correo enviado.")
    except Exception as e:
        print(f"[!] Error al enviar correo: {e}")

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

def ip_ya_alertada(ip):
    if not os.path.exists(LOG_ALARMAS):
        return False
    with open(LOG_ALARMAS) as f:
        return any(ip in linea for linea in f)

def analizar_fallos_journalctl():
    print("[i] Analizando intentos SSH...")
    ip_fails = {}
    usuario_fails = {}
    ip_usuarios = {}

    try:
        salida = subprocess.check_output(
            ['journalctl', '-u', 'ssh', '--no-pager', '--since', '10 minutes ago'],
            stderr=subprocess.DEVNULL
        ).decode()
        #with open("/tmp/falso_log.txt") as f:
    	#    salida = f.read()

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

    for ip, intentos in ip_fails.items():
        if intentos >= LIMITE_INTENTOS:
            usuarios = ', '.join(ip_usuarios[ip])
            accion = bloquear_ip(ip)
            mensaje = (
                #f"{encabezado_fecha()}\n"
                f"{intentos} fallos desde {ip}\n"
                f"Usuarios: {usuarios}\n"
                f"Prevención: {accion}"
            )
            registrar_log("Alarma", mensaje.replace("\n", " "), ip)
            enviar_mail("[HIPS] SSH: Fallos de autenticación", mensaje)

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
            try:
                with open(MSMTP_LOG, 'w') as f:
                    f.write("")
                print("[+] Log de correos msmtp limpiado.")
            except Exception as e:
                print(f"[!] Error al limpiar log msmtp: {e}")

def main():
    analizar_fallos_journalctl()
    analizar_http_log()
    analizar_correo_msmtp()

if __name__ == "__main__":
    main()

