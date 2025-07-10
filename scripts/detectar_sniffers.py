#!/usr/bin/env python3

import subprocess
from datetime import datetime
import os

LOG_ALARMAS = "/var/log/hips/alarmas.log"
LOG_PREVENCION = "/var/log/hips/prevencion.log"
DESTINATARIO = "eliasdavidroman@gmail.com"
HERRAMIENTAS_PROHIBIDAS = ["tcpdump", "wireshark", "tshark", "dsniff", "ettercap"]

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

def interfaz_en_promiscuo():
    try:
        salida = subprocess.check_output(['ip', 'link']).decode()
        interfaces = []
        for linea in salida.split('\n'):
            if "PROMISC" in linea:
                interfaces.append(linea.strip())
        return interfaces
    except Exception as e:
        print(f"[!] Error al detectar modo promiscuo: {e}")
        return []

def detectar_sniffers():
    sniffers_encontrados = []
    for prog in HERRAMIENTAS_PROHIBIDAS:
        try:
            salida = subprocess.check_output(['pgrep', '-f', prog])
            sniffers_encontrados.append(prog)
        except subprocess.CalledProcessError:
            pass
    return sniffers_encontrados

def matar_sniffer(prog):
    try:
        subprocess.run(['sudo', 'pkill', '-f', prog])
        registrar_log("Prevención", f"Proceso relacionado con '{prog}' eliminado", "local", LOG_PREVENCION)
        print(f"[+] Proceso relacionado con '{prog}' terminado.")
    except Exception as e:
        print(f"[!] Error al matar procesos relacionados con '{prog}': {e}")

def main():
    # 1. Modo promiscuo
    interfaces = interfaz_en_promiscuo()
    for linea in interfaces:
        registrar_log("Alarma", f"Interfaz en modo promiscuo detectada: {linea}", "local")
        enviar_mail("[HIPS] Alerta: Interfaz en modo promiscuo", f"Se detectó:\n{linea}")

    # 2. Procesos sniffers
    sniffers = detectar_sniffers()
    for sniffer in sniffers:
        registrar_log("Alarma", f"Herramienta de sniffing detectada: {sniffer}", "local")
        enviar_mail("[HIPS] Alerta: Sniffer activo", f"Se detectó la herramienta '{sniffer}' en ejecución.")
        matar_sniffer(sniffer)

if __name__ == "__main__":
    main()
