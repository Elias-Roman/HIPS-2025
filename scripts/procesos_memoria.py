k#!/usr/bin/env python3

import psutil
import time
import subprocess
from datetime import datetime
import os

UMBRAL_MEMORIA = 2.0         # % mínimo de RAM para considerar consumo excesivo
TIEMPO_ESPERA = 10           # Duración (en segundos) del consumo sostenido
DESTINATARIO = "eliasdavidroman@gmail.com"  # Correo para enviar alertas
LOG_ALARMAS = "/var/log/hips/alarmas.log"   # Log de alarmas
LOG_PREVENCION = "/var/log/hips/prevencion.log"  # Log de acciones de mitigación

# Asegura la existencia del directorio donde van los logs
os.makedirs(os.path.dirname(LOG_ALARMAS), exist_ok=True)

# Devuelve un encabezado de fecha para logs
def encabezado_fecha():
    return f"[{datetime.now().strftime('%d/%m/%Y %H:%M')}]"

# Registra mensajes en los logs correspondientes
def registrar_log(tipo, mensaje, archivo):
    fecha = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    entrada = f"{fecha} :: {tipo} :: N/A :: {mensaje}\n"
    with open(archivo, "a") as f:
        f.write(entrada)

# Envía un correo de alerta con msmtp
def enviar_mail(asunto, cuerpo):
    mensaje = f"Subject: {asunto}\n\n{cuerpo}"
    try:
        subprocess.run(['msmtp', DESTINATARIO], input=mensaje.encode(), check=True)
        print("[+] Correo enviado.")
    except Exception as e:
        print(f"[!] Error al enviar correo: {e}")

# Obtiene los procesos que superan el umbral de memoria
def obtener_procesos_excesivos():
    procesos_excesivos = []
    for proc in psutil.process_iter(attrs=['pid', 'name', 'memory_percent']):
        try:
            if proc.info['memory_percent'] > UMBRAL_MEMORIA:
                procesos_excesivos.append(proc)
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
    return procesos_excesivos

def monitorear_y_matar():
    print("[i] Monitoreando procesos con alto consumo de memoria...")

    # Toma un registro inicial del consumo de memoria
    procesos_iniciales = {p.pid: p.memory_percent() for p in obtener_procesos_excesivos()}

    # Espera un tiempo definido para verificar si el consumo se mantiene
    time.sleep(TIEMPO_ESPERA)

    # Evalúa nuevamente y elimina los procesos que mantuvieron consumo alto
    for proc in obtener_procesos_excesivos():
        try:
            pid = proc.pid
            nombre = proc.name()
            mem_final = proc.memory_percent()

            if pid in procesos_iniciales:
                mem_inicial = procesos_iniciales[pid]
                if mem_inicial > UMBRAL_MEMORIA and mem_final > UMBRAL_MEMORIA:
                    mensaje = (
                        f"PID={pid}, Nombre={nombre}\n"
                        f"Consumo sostenido: {mem_final:.2f}% RAM durante {TIEMPO_ESPERA} segundos\n"
                        f"Acción: proceso terminado"
                    )

                    registrar_log("Alarma", mensaje.replace("\n", " "), LOG_ALARMAS)
                    registrar_log("Prevención", f"Proceso {nombre} (PID {pid}) eliminado por RAM alta", LOG_PREVENCION)
                    enviar_mail("[HIPS] Proceso eliminado por uso de RAM", mensaje)
                    proc.kill()
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue

if __name__ == "__main__":
    monitorear_y_matar()

