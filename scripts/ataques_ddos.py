k#!/usr/bin/env python3

import re
from collections import defaultdict
from datetime import datetime
import subprocess
import os

LOG_FILE = "/opt/hips/logs/ddos_dns.log"
UMBRAL_CONSULTAS = 10
PUERTO_DNS = ".53:"
DESTINATARIO = "eliasdavidroman@gmail.com"
LOG_ALARMAS = "/var/log/hips/alarmas.log"
LOG_PREVENCION = "/var/log/hips/prevencion.log"
os.makedirs(os.path.dirname(LOG_ALARMAS), exist_ok=True)

# Devuelve la fecha y hora actual con formato legible
def encabezado_fecha():
    return f"[{datetime.now().strftime('%d/%m/%Y %H:%M')}]"

# Registra una entrada en el log indicado (alarma o prevención)
def registrar_log(tipo, mensaje, archivo):
    fecha = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    entrada = f"{fecha} :: {tipo} :: N/A :: {mensaje}\n"
    with open(archivo, "a") as f:
        f.write(entrada)

# Envía un correo utilizando msmtp con asunto y mensaje indicados
def enviar_mail(asunto, cuerpo):
    mensaje = f"Subject: {asunto}\n\n{cuerpo}"
    try:
        subprocess.run(["msmtp", DESTINATARIO], input=mensaje.encode(), check=True)
        print("[+] Correo enviado.")
    except Exception as e:
        print(f"[!] Error al enviar correo: {e}")

# Bloquea una IP sospechosa mediante iptables si aún no está bloqueada
def bloquear_ip(ip):
    try:
        reglas = subprocess.check_output(['sudo', 'iptables', '-L', 'INPUT', '-n']).decode()
        if ip not in reglas:
            subprocess.run(['sudo', 'iptables', '-A', 'INPUT', '-s', ip, '-j', 'DROP'], check=True)
            registrar_log("Prevención", f"IP {ip} bloqueada por ataque DNS", LOG_PREVENCION)
            return f"IP {ip} bloqueada"
        else:
            return f"IP {ip} ya estaba bloqueada"
    except Exception as e:
        return f"Error bloqueando IP {ip}: {e}"

def analizar_log():
    print("[i] Analizando posibles ataques DDoS DNS...")

    # Diccionario que guarda la cantidad de consultas por IP
    consultas_por_ip = defaultdict(int)

    # Lee línea por línea el log DNS proporcionado
    with open(LOG_FILE) as f:
        for linea in f:
            if PUERTO_DNS in linea and "ANY?" in linea:
                # Busca IP de origen en cada línea con expresión regular
                match = re.search(r'IP ([\d.]+)\.', linea)
                if match:
                    ip = match.group(1)
                    consultas_por_ip[ip] += 1

    # Inicializa variables de informe
    cuerpo = f"Análisis de log DNS:\n\n"
    se_detecto = False

    # Revisa qué IPs superaron el umbral y ejecuta medidas
    for ip, cantidad in consultas_por_ip.items():
        if cantidad >= UMBRAL_CONSULTAS:
            se_detecto = True
            accion = bloquear_ip(ip)
            mensaje = f"IP sospechosa: {ip} realizó {cantidad} consultas DNS tipo ANY.\n• Acción: {accion}"
            registrar_log("Alarma", mensaje, LOG_ALARMAS)
            cuerpo += f"- {mensaje}\n"

    # Si se detectaron ataques, se notifica por correo
    if se_detecto:
        enviar_mail("[HIPS] Ataque DDoS DNS detectado", cuerpo)
    else:
        print("[i] No se detectaron ataques DDoS.")

if __name__ == "__main__":
    analizar_log()

