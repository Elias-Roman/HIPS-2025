#!/usr/bin/env python3

import subprocess
from datetime import datetime

LOG_ALARMAS = "/var/log/hips/alarmas.log"
LOG_PREVENCION = "/var/log/hips/prevencion.log"
USUARIOS_PERMITIDOS = ["kali", "root"]
DESTINATARIO = "eliasdavidroman@gmail.com"

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

def obtener_usuarios_conectados():
    try:
        salida = subprocess.check_output(['who']).decode().strip().split('\n')
        return salida
    except Exception as e:
        print(f"[!] Error al ejecutar who: {e}")
        return []

def ip_ya_bloqueada(ip):
    try:
        reglas = subprocess.check_output(['iptables', '-L', 'INPUT', '-n']).decode()
        return ip in reglas
    except Exception as e:
        print(f"[!] Error al verificar iptables: {e}")
        return False

def bloquear_ip(ip):
    if not ip_ya_bloqueada(ip):
        try:
            subprocess.run(['iptables', '-A', 'INPUT', '-s', ip, '-j', 'DROP'], check=True)
            registrar_log("Prevención", f"IP bloqueada por conexión sospechosa", ip, LOG_PREVENCION)
            print(f"[+] IP bloqueada: {ip}")
        except Exception as e:
            print(f"[!] Error al bloquear IP {ip}: {e}")
    else:
        print(f"[i] La IP {ip} ya está bloqueada.")

def cerrar_sesion_local(usuario):
    try:
        subprocess.run(['pkill', '-KILL', '-u', usuario])
        registrar_log("Prevención", f"Sesión local de {usuario} finalizada", "local", LOG_PREVENCION)
        print(f"[+] Sesión de {usuario} finalizada.")
    except Exception as e:
        print(f"[!] Error al cerrar sesión de {usuario}: {e}")

def analizar_conexiones():
    conexiones = obtener_usuarios_conectados()
    for linea in conexiones:
        partes = linea.split()
        if len(partes) >= 1:
            usuario = partes[0]
            origen = partes[-1] if '(' in partes[-1] else "local"
            ip = origen.strip("()") if "(" in origen else None

            if usuario not in USUARIOS_PERMITIDOS:
                mensaje = f"Usuario no permitido conectado: {usuario} desde {origen}"
                registrar_log("Alarma", mensaje, ip or "local")
                enviar_mail(f"[HIPS] Alerta: Usuario sospechoso", mensaje)
                print(f"[!] Alerta: {mensaje}")

                if ip:
                    bloquear_ip(ip)
                else:
                    cerrar_sesion_local(usuario)
            else:
                print(f"[OK] Usuario {usuario} conectado desde {origen}")

def main():
    analizar_conexiones()

if __name__ == "__main__":
    main()
