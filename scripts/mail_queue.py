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

def bloquear_usuario(usuario):
    try:
        subprocess.run(['usermod', '-L', usuario], check=True)
        registrar_log("Prevención", f"Usuario {usuario} bloqueado por correo masivo", "N/A", LOG_PREVENCION)
        return f"Usuario {usuario} bloqueado exitosamente"
    except Exception as e:
        return f"Error al bloquear usuario {usuario}: {e}"

def analizar_cola(file_path=None):
    print("[i] Analizando cola de correos con mailq…")

    try:
        #if file_path:
        #    with open(file_path, 'r') as f:
        #        salida = f.read()
        #else:
            salida = subprocess.check_output(['mailq'], stderr=subprocess.DEVNULL).decode()
    except Exception as e:
        print(f"[!] Error al obtener cola: {e}")
        return

    usuarios = defaultdict(int)

    for linea in salida.splitlines():
        match = re.search(r'\s+(\S+@\S+)$', linea.strip())
        if match:
            remitente = match.group(1)
            usuarios[remitente] += 1

    for user, cantidad in usuarios.items():
        if cantidad >= LIMITE_CORREOS:
            accion = bloquear_usuario(user.split('@')[0])
            mensaje = (
                #f"{encabezado_fecha()}\n"
                f"{cantidad} correos en cola del usuario: {user}\n"
                f"Prevención: {accion}"
            )
            registrar_log("Alarma", mensaje.replace("\n", " "), "N/A")
            enviar_mail("[HIPS] MailQueue: Envío masivo de correos", mensaje)

if __name__ == "__main__":
    archivo = sys.argv[1] if len(sys.argv) > 1 else None
    analizar_cola(archivo)
