#!/usr/bin/env python3

import os
import re
import shutil
import subprocess
from datetime import datetime

# CONFIG
LOG_ALARMAS = "/var/log/hips/alarmas.log"
LOG_PREVENCION = "/var/log/hips/prevencion.log"
CUARENTENA = "/opt/hips/cuarentena"
DESTINATARIO = "eliasdavidroman@gmail.com"
RUTAS_CRON = [
    "/etc/crontab",
    "/etc/cron.d/",
    "/var/spool/cron/"
]

# PATRONES sospechosos
PATRONES_SOSPECHOSOS = [
    r'/tmp/',
    r'/dev/shm/',
    r'(https?://\S+)',
    r'\bcurl\b',
    r'\bwget\b',
    r'\bnc\b',
    r'python\s+-m\s+http\.server',
]

os.makedirs(CUARENTENA, exist_ok=True)
os.makedirs(os.path.dirname(LOG_ALARMAS), exist_ok=True)

def encabezado_fecha():
    return f"[{datetime.now().strftime('%d/%m/%Y %H:%M')}]"

def registrar_log(tipo, mensaje, archivo):
    fecha = datetime.now().strftime("%d/%m/%Y")
    entrada = f"{fecha} :: {tipo} :: N/A :: {mensaje}\n"
    with open(archivo, "a") as f:
        f.write(entrada)

def enviar_mail(asunto, cuerpo):
    mensaje = f"Subject: {asunto}\n\n{cuerpo}"
    try:
        subprocess.run(["msmtp", DESTINATARIO], input=mensaje.encode(), check=True)
        print("[+] Correo enviado.")
    except Exception as e:
        print(f"[!] Error al enviar correo: {e}")

def analizar_linea_cron(linea):
    for patron in PATRONES_SOSPECHOSOS:
        if re.search(patron, linea):
            return True
    return False

def analizar_crontab(ruta):
    sospechoso = False
    cuerpo = f"{encabezado_fecha()}\nArchivo cron sospechoso: {ruta}\n\n"
    lineas_sospechosas = []

    try:
        with open(ruta) as f:
            for num, linea in enumerate(f, 1):
                if analizar_linea_cron(linea):
                    cuerpo += f"Línea {num}: {linea}"
                    lineas_sospechosas.append(f"Línea {num}: {linea}")
                    sospechoso = True
    except Exception as e:
        print(f"[!] Error al leer {ruta}: {e}")
        return

    if sospechoso:
        timestamp = int(datetime.now().timestamp())
        nombre = os.path.basename(ruta).replace("/", "_")
        nombre_respaldo = f"{nombre}_sospechoso_{timestamp}.txt"
        destino = os.path.join(CUARENTENA, nombre_respaldo)

        try:
            with open(destino, "w") as f:
                f.write("\n".join(lineas_sospechosas))
        except Exception as e:
            destino = f"Error al crear respaldo: {e}"

        registrar_log("Alarma", f"CRON sospechoso: {ruta} → líneas específicas extraídas", LOG_ALARMAS)
        registrar_log("Prevención", f"Líneas maliciosas de {ruta} respaldadas en: {destino}", LOG_PREVENCION)
        cuerpo += f"\n→ Líneas sospechosas guardadas en: {destino}\n"
        enviar_mail("[HIPS] CRON sospechoso detectado", cuerpo)

def main():
    print("[i] Analizando cronjobs...")
    for ruta in RUTAS_CRON:
        if os.path.isfile(ruta):
            analizar_crontab(ruta)
        elif os.path.isdir(ruta):
            for archivo in os.listdir(ruta):
                full_path = os.path.join(ruta, archivo)
                if os.path.isfile(full_path):
                    analizar_crontab(full_path)

if __name__ == "__main__":
    main()
