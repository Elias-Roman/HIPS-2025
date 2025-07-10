#!/usr/bin/env python3

import subprocess
from datetime import datetime

# Archivos de log donde se registran las alertas y las acciones preventivas
LOG_ALARMAS = "/var/log/hips/alarmas.log"
LOG_PREVENCION = "/var/log/hips/prevencion.log"

# Lista blanca de usuarios que tienen permitido conectarse
USUARIOS_PERMITIDOS = ["kali", "root"]

# Dirección de correo a la que se enviarán las alertas
DESTINATARIO = "eliasdavidroman@gmail.com"

# ------------------------------------------------------
# Registra una entrada en un log (por defecto en el de alarmas)
# Incluye la fecha, tipo de evento, IP y mensaje
def registrar_log(tipo, mensaje, ip="N/A", archivo=LOG_ALARMAS):
    fecha = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    log = f"{fecha} :: {tipo} :: {ip} :: {mensaje}\n"
    with open(archivo, 'a') as f:
        f.write(log)

# ------------------------------------------------------
# Envía un correo con msmtp usando el asunto y mensaje que se le pasan
def enviar_mail(asunto, cuerpo):
    mensaje = f"Subject: {asunto}\n\n{cuerpo}"
    try:
        subprocess.run(['msmtp', DESTINATARIO], input=mensaje.encode(), check=True)
        print("[+] Correo enviado.")
    except Exception as e:
        print(f"[!] Error al enviar correo: {e}")

# ------------------------------------------------------
# Ejecuta el comando who para obtener los usuarios conectados al sistema
def obtener_usuarios_conectados():
    try:
        salida = subprocess.check_output(['who']).decode().strip().split('\n')
        return salida
    except Exception as e:
        print(f"[!] Error al ejecutar who: {e}")
        return []

# ------------------------------------------------------
# Verifica si una IP ya se encuentra bloqueada en las reglas actuales de iptables
def ip_ya_bloqueada(ip):
    try:
        reglas = subprocess.check_output(['iptables', '-L', 'INPUT', '-n']).decode()
        return ip in reglas
    except Exception as e:
        print(f"[!] Error al verificar iptables: {e}")
        return False

# ------------------------------------------------------
# Si la IP no está bloqueada, la bloquea usando iptables
# También registra la acción en el log de prevención
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

# ------------------------------------------------------
# Si el usuario se conectó desde una terminal local y no se puede bloquear IP,
# se cierra su sesión directamente usando pkill
def cerrar_sesion_local(usuario):
    try:
        subprocess.run(['pkill', '-KILL', '-u', usuario])
        registrar_log("Prevención", f"Sesión local de {usuario} finalizada", "local", LOG_PREVENCION)
        print(f"[+] Sesión de {usuario} finalizada.")
    except Exception as e:
        print(f"[!] Error al cerrar sesión de {usuario}: {e}")

# ------------------------------------------------------
# Función principal que analiza todos los usuarios conectados
# Si alguno no está en la lista de permitidos, genera una alerta, envía correo y aplica medidas
def analizar_conexiones():
    conexiones = obtener_usuarios_conectados()
    for linea in conexiones:
        partes = linea.split()
        if len(partes) >= 1:
            usuario = partes[0]

            # Si el campo de origen tiene una IP, estará entre paréntesis, ej: (192.168.0.5)
            origen = partes[-1] if '(' in partes[-1] else "local"
            ip = origen.strip("()") if "(" in origen else None

            # Si el usuario no está autorizado, se genera alerta y se toma acción
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

# ------------------------------------------------------
# Llamada principal cuando el script se ejecuta directamente
def main():
    analizar_conexiones()

# ------------------------------------------------------
# Punto de entrada
if __name__ == "__main__":
    main()

