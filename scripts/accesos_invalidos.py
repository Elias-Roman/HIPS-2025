k#!/usr/bin/env python3

import subprocess
import re
import os
from datetime import datetime
from collections import defaultdict

# CONFIGURACIÓN GENERAL

# Límite de intentos fallidos por usuario o por IP antes de generar una alerta
LIMITE_USUARIO = 5
LIMITE_IP = 5

# Rutas de logs donde se guardarán las alertas y las acciones preventivas
LOG_ALARMAS = "/var/log/hips/alarmas.log"
LOG_PREVENCION = "/var/log/hips/prevencion.log"

# Dirección de correo a la que se enviarán las alertas
DESTINATARIO = "eliasdavidroman@gmail.com"

# Asegura que el directorio del log exista (útil en la primera ejecución)
os.makedirs(os.path.dirname(LOG_ALARMAS), exist_ok=True)

# ----------------------------------------
# Devuelve la fecha y hora actual formateada
def encabezado_fecha():
    return f"[{datetime.now().strftime('%d/%m/%Y %H:%M')}]"

# ----------------------------------------
# Registra una línea en el log correspondiente (alarma o prevención)
def registrar_log(tipo, mensaje, archivo):
    fecha = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    entrada = f"{fecha} :: {tipo} :: N/A :: {mensaje}\n"
    with open(archivo, 'a') as f:
        f.write(entrada)

# ----------------------------------------
# Envía un correo utilizando msmtp con un asunto y un cuerpo personalizados
def enviar_mail(asunto, cuerpo):
    mensaje = f"Subject: {asunto}\n\n{cuerpo}"
    try:
        subprocess.run(["msmtp", DESTINATARIO], input=mensaje.encode(), check=True)
        print("[+] Correo enviado.")
    except Exception as e:
        print(f"[!] Error al enviar correo: {e}")

# ----------------------------------------
# Bloquea una IP con iptables si no ha sido bloqueada antes
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

# ----------------------------------------
# Bloquea un usuario del sistema deshabilitando su cuenta (usermod -L)
def bloquear_usuario(usuario):
    try:
        subprocess.run(['usermod', '-L', usuario], check=True)
        registrar_log("Prevención", f"Usuario {usuario} bloqueado por múltiples intentos", LOG_PREVENCION)
        return f"Usuario {usuario} bloqueado"
    except Exception as e:
        return f"Error bloqueando usuario {usuario}: {e}"

# ----------------------------------------
# Analiza los logs SSH (últimos 10 minutos) y detecta intentos fallidos de login
# Si una IP o usuario supera los límites definidos, se genera alerta y se toma acción
def analizar_ssh():
    print("[i] Analizando intentos fallidos SSH...")

    # Diccionarios para llevar el conteo de fallos
    ip_fails = defaultdict(int)
    usuario_fails = defaultdict(int)
    ip_usuarios = defaultdict(set)

    try:
        # Consulta los logs del servicio SSH desde hace 10 minutos
        salida = subprocess.check_output(
            ['journalctl', '-u', 'ssh.service', '--no-pager', '--since', '10 minutes ago'],
            stderr=subprocess.DEVNULL
        ).decode()

        # Analiza línea por línea buscando "Failed password"
        for linea in salida.splitlines():
            if "Failed password" in linea:
                match_ip = re.search(r'from ([\d.:a-fA-F]+)', linea)
                ip = match_ip.group(1) if match_ip else None

                match_user = re.search(r'Failed password for (invalid user )?(\w+)', linea)
                usuario = match_user.group(2) if match_user else None

                # Si se logró extraer IP y usuario, se cuentan los intentos
                if ip and usuario:
                    ip_fails[ip] += 1
                    usuario_fails[usuario] += 1
                    ip_usuarios[ip].add(usuario)

    except Exception as e:
        print(f"[!] Error al analizar journalctl: {e}")
        return

    # Mensaje general para el correo si se detectan eventos sospechosos
    cuerpo = f"Intentos fallidos detectados:\n"
    se_detecto = False

    # Revisa usuarios que hayan superado el límite de intentos
    for usuario, cantidad in usuario_fails.items():
        if cantidad >= LIMITE_USUARIO:
            accion = bloquear_usuario(usuario)
            mensaje = f"Usuario {usuario} tuvo {cantidad} intentos fallidos consecutivos. Acción: {accion}"
            registrar_log("Alarma", mensaje, LOG_ALARMAS)
            cuerpo += f"- {mensaje}\n"
            se_detecto = True

    # Revisa IPs que hayan intentado múltiples accesos con diferentes usuarios
    for ip, cantidad in ip_fails.items():
        if cantidad >= LIMITE_IP and len(ip_usuarios[ip]) >= LIMITE_IP:
            accion = bloquear_ip(ip)
            usuarios = ', '.join(ip_usuarios[ip])
            mensaje = f"IP {ip} intentó acceder con múltiples usuarios ({usuarios}). Acción: {accion}"
            registrar_log("Alarma", mensaje, LOG_ALARMAS)
            cuerpo += f"- {mensaje}\n"
            se_detecto = True

    # Si se detectó alguna condición sospechosa, se envía el correo
    if se_detecto:
        enviar_mail("[HIPS] Accesos no válidos detectados", cuerpo)

# ----------------------------------------
# Punto de entrada del script
if __name__ == "__main__":
    analizar_ssh()

