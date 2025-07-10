#!/usr/bin/env python3

import subprocess
import re
import os
from datetime import datetime
from collections import defaultdict

# CONFIGURACIÓN
LIMITE_USUARIO = 5
LIMITE_IP = 5
LOG_ALARMAS = "/var/log/hips/alarmas.log"
LOG_PREVENCION = "/var/log/hips/prevencion.log"
DESTINATARIO = "eliasdavidroman@gmail.com"

os.makedirs(os.path.dirname(LOG_ALARMAS), exist_ok=True)

def encabezado_fecha():
    return f"[{datetime.now().strftime('%d/%m/%Y %H:%M')}]"

def registrar_log(tipo, mensaje, archivo):
    fecha = datetime.now().strftime("%d/%m/%Y")
    entrada = f"{fecha} :: {tipo} :: N/A :: {mensaje}\n"
    with open(archivo, 'a') as f:
        f.write(entrada)

def enviar_mail(asunto, cuerpo):
    mensaje = f"Subject: {asunto}\n\n{cuerpo}"
    try:
        subprocess.run(["msmtp", DESTINATARIO], input=mensaje.encode(), check=True)
        print("[+] Correo enviado.")
    except Exception as e:
        print(f"[!] Error al enviar correo: {e}")

def bloquear_ip(ip):
    try:
        reglas = subprocess.check_output(['iptables', '-L', 'INPUT', '-n']).decode()
        if ip not in reglas:
            subprocess.run(['iptables', '-A', 'INPUT', '-s', ip, '-j', 'DROP'], check=True)
            registrar_log("Prevención", f"IP {ip} bloqueada por múltiples intentos", LOG_PREVENCION)
            return f"IP {ip} bloqueada"
        else:
            return f"IP {ip} ya estaba bloqueada"
    except Exception as e:
        return f"Error bloqueando IP {ip}: {e}"

def bloquear_usuario(usuario):
    try:
        subprocess.run(['usermod', '-L', usuario], check=True)
        registrar_log("Prevención", f"Usuario {usuario} bloqueado por múltiples intentos", LOG_PREVENCION)
        return f"Usuario {usuario} bloqueado"
    except Exception as e:
        return f"Error bloqueando usuario {usuario}: {e}"

def analizar_ssh():
    print("[i] Analizando intentos fallidos SSH...")
    ip_fails = defaultdict(int)
    usuario_fails = defaultdict(int)
    ip_usuarios = defaultdict(set)

    try:
        salida = subprocess.check_output(
            ['journalctl', '-u', 'ssh.service', '--no-pager', '--since', '10 minutes ago'],
            stderr=subprocess.DEVNULL
        ).decode()

        for linea in salida.splitlines():
            if "Failed password" in linea:
                match_ip = re.search(r'from ([\d.:a-fA-F]+)', linea)
                ip = match_ip.group(1) if match_ip else None

                match_user = re.search(r'Failed password for (invalid user )?(\w+)', linea)
                usuario = match_user.group(2) if match_user else None

                if ip and usuario:
                    ip_fails[ip] += 1
                    usuario_fails[usuario] += 1
                    ip_usuarios[ip].add(usuario)

    except Exception as e:
        print(f"[!] Error al analizar journalctl: {e}")
        return

    cuerpo = f"Intentos fallidos detectados:\n"
    se_detecto = False

    for usuario, cantidad in usuario_fails.items():
        if cantidad >= LIMITE_USUARIO:
            accion = bloquear_usuario(usuario)
            mensaje = f"Usuario {usuario} tuvo {cantidad} intentos fallidos consecutivos. Acción: {accion}"
            registrar_log("Alarma", mensaje, LOG_ALARMAS)
            cuerpo += f"- {mensaje}\n"
            se_detecto = True

    for ip, cantidad in ip_fails.items():
        if cantidad >= LIMITE_IP and len(ip_usuarios[ip]) >= LIMITE_IP:
            accion = bloquear_ip(ip)
            usuarios = ', '.join(ip_usuarios[ip])
            mensaje = f"IP {ip} intentó acceder con múltiples usuarios ({usuarios}). Acción: {accion}"
            registrar_log("Alarma", mensaje, LOG_ALARMAS)
            cuerpo += f"- {mensaje}\n"
            se_detecto = True

    if se_detecto:
        enviar_mail("[HIPS] Accesos no válidos detectados", cuerpo)

if __name__ == "__main__":
    analizar_ssh()
