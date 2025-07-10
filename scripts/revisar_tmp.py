#!/usr/bin/env python3

import os
import subprocess
from datetime import datetime
import shutil
import psutil

TMP_DIR = "/tmp"
CUARENTENA_DIR = "/opt/hips/cuarentena"
LOG_ALARMAS = "/var/log/hips/alarmas.log"
LOG_PREVENCION = "/var/log/hips/prevencion.log"
DESTINATARIO = "eliasdavidroman@gmail.com"

SCRIPTS_SOSPECHOSOS = [".sh", ".py", ".pl", ".php", ".exe", ".bin"]

os.makedirs(CUARENTENA_DIR, exist_ok=True)
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
        subprocess.run(['msmtp', DESTINATARIO], input=mensaje.encode(), check=True)
        print("[+] Correo enviado.")
    except Exception as e:
        print(f"[!] Error al enviar correo: {e}")

def mover_a_cuarentena(ruta):
    nombre = os.path.basename(ruta)
    destino = os.path.join(CUARENTENA_DIR, f"{nombre}_{int(datetime.now().timestamp())}")
    try:
        shutil.move(ruta, destino)
        return destino
    except Exception as e:
        return f"Error al mover a cuarentena: {e}"

def buscar_archivos_sospechosos():
    archivos_sospechosos = []
    for root, _, files in os.walk(TMP_DIR):
        for f in files:
            ruta = os.path.join(root, f)
            if any(ruta.endswith(ext) for ext in SCRIPTS_SOSPECHOSOS) or os.access(ruta, os.X_OK):
                archivos_sospechosos.append(ruta)
    return archivos_sospechosos

def buscar_procesos_en_tmp():
    procesos = []
    for proc in psutil.process_iter(['pid', 'exe', 'cmdline']):
        try:
            if proc.info['exe'] and proc.info['exe'].startswith(TMP_DIR):
                procesos.append(proc)
            elif proc.info['cmdline'] and any(arg.startswith(TMP_DIR) for arg in proc.info['cmdline']):
                procesos.append(proc)
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
    return procesos

def main():
    print("[i] Revisando /tmp...")
    cuerpo_mensaje = f"Análisis del directorio /tmp:\n\n"
    se_detecto_algo = False

    sospechosos = buscar_archivos_sospechosos()
    procesos = buscar_procesos_en_tmp()

    for archivo in sospechosos:
        cuarentena = mover_a_cuarentena(archivo)
        if "Error" not in cuarentena:
            log_mensaje = f"Archivo sospechoso detectado en /tmp: {archivo} movido a: {cuarentena}"
            registrar_log("Alarma", log_mensaje, LOG_ALARMAS)
            registrar_log("Prevención", f"{archivo} movido a cuarentena", LOG_PREVENCION)
            cuerpo_mensaje += f"- Archivo: {archivo}\n  → Movido a: {cuarentena}\n"
            se_detecto_algo = True
        else:
            print(f"[!] No se pudo mover {archivo}: {cuarentena}")

    for proc in procesos:
        try:
            cmd = ' '.join(proc.cmdline())
            mensaje = f"Proceso en ejecución desde /tmp\n  PID: {proc.pid}\n  CMD: {cmd}"
            registrar_log("Alarma", mensaje.replace("\n", " "), LOG_ALARMAS)
            cuerpo_mensaje += f"- Proceso sospechoso:\n  PID: {proc.pid}\n  CMD: {cmd}\n"
            se_detecto_algo = True
        except Exception:
            continue

    if se_detecto_algo:
        enviar_mail("[HIPS] Análisis de /tmp: amenazas detectadas", cuerpo_mensaje)
    else:
        print("[i] No se detectaron amenazas en /tmp.")

if __name__ == "__main__":
    main()
