#!/usr/bin/env python3

import subprocess
import re
import sys
import os
from datetime import datetime
from collections import defaultdict

LOG_ALARMAS = "/var/log/hips/alarmas.log"
LOG_PREVENCION = "/var/log/hips/prevencion.log"
DESTINATARIO = "eliasdavidroman@gmail.com"
LIMITE_CORREOS = 10

# Asegura que el directorio del log de alarmas exista
os.makedirs(os.path.dirname(LOG_ALARMAS), exist_ok=True)

# ------------------------------------------------------
# Devuelve una cadena con la fecha y hora actual
def encabezado_fecha():
    return f"[{datetime.now().strftime('%d/%m/%Y %H:%M')}]"

# ------------------------------------------------------
# Registra un evento en el log (puede ser alarma o prevención)
def registrar_log(tipo, mensaje, ip="N/A", archivo=LOG_ALARMAS):
    fecha = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    log = f"{fecha} :: {tipo} :: {ip} :: {mensaje}\n"
    with open(archivo, 'a') as f:
        f.write(log)

# ------------------------------------------------------
# Envía un correo de alerta utilizando msmtp
def enviar_mail(asunto, cuerpo):
    mensaje = f"Subject: {asunto}\n\n{cuerpo}"
    try:
        subprocess.run(['msmtp', DESTINATARIO], input=mensaje.encode(), check=True)
        print("[+] Correo enviado.")
    except Exception as e:
        print(f"[!] Error al enviar correo: {e}")

# ------------------------------------------------------
# Bloquea a un usuario del sistema usando usermod -L para evitar más envíos
def bloquear_usuario(usuario):
    try:
        subprocess.run(['usermod', '-L', usuario], check=True)
        registrar_log("Prevención", f"Usuario {usuario} bloqueado por correo masivo", "N/A", LOG_PREVENCION)
        return f"Usuario {usuario} bloqueado exitosamente"
    except Exception as e:
        return f"Error al bloquear usuario {usuario}: {e}"

# ------------------------------------------------------
# Analiza la cola de correos para detectar si hay usuarios enviando spam
# Si se pasa un archivo como argumento, lo analiza en vez de usar mailq
def analizar_cola(file_path=None):
    print("[i] Analizando cola de correos con mailq…")

    try:
        # Si no se pasa archivo de prueba, ejecuta el comando mailq
        salida = subprocess.check_output(['mailq'], stderr=subprocess.DEVNULL).decode()
    except Exception as e:
        print(f"[!] Error al obtener cola: {e}")
        return

    # Guarda la cantidad de correos en cola por cada remitente detectado
    usuarios = defaultdict(int)

    for linea in salida.splitlines():
        # Busca líneas que terminan con una dirección de correo
        match = re.search(r'\s+(\S+@\S+)$', linea.strip())
        if match:
            remitente = match.group(1)
            usuarios[remitente] += 1

    # Revisa si algún usuario superó el límite de correos permitidos
    for user, cantidad in usuarios.items():
        if cantidad >= LIMITE_CORREOS:
            usuario = user.split('@')[0]  # Toma solo la parte antes del @
            accion = bloquear_usuario(usuario)
            mensaje = (
                f"{cantidad} correos en cola del usuario: {user}\n"
                f"Prevención: {accion}"
            )
            registrar_log("Alarma", mensaje.replace("\n", " "), "N/A")
            enviar_mail("[HIPS] MailQueue: Envío masivo de correos", mensaje)

# ------------------------------------------------------
# Punto de entrada del script
# Si se pasa un archivo como argumento, lo usa como input en vez de ejecutar mailq
if __name__ == "__main__":
    archivo = sys.argv[1] if len(sys.argv) > 1 else None
    analizar_cola(archivo)

