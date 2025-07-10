#!/usr/bin/env python3
import os
import hashlib
import subprocess
from datetime import datetime
import psycopg2
import psycopg2.extras

# Parámetros de conexión (mejor cargarlos con .env o config externa)
DB_HOST = '127.0.0.1'
DB_PORT = '5432'
DB_NAME = 'hips_db'
DB_USER = 'hips_user'
DB_PASS = 'elias2004'

LOG_ALARMAS    = '/var/log/hips/alarmas.log'
LOG_PREVENCION = '/var/log/hips/prevencion.log'
EMAIL_DEST     = 'eliasdavidroman@gmail.com'

# ----------------------------------------
def get_connection():
    return psycopg2.connect(host=DB_HOST, port=DB_PORT, dbname=DB_NAME,
                            user=DB_USER, password=DB_PASS)

# ----------------------------------------
def calcular_hash(ruta):
    try:
        cmd = ['sha256sum', ruta] if ruta != '/etc/shadow' else ['sudo', 'sha256sum', ruta]
        salida = subprocess.check_output(cmd, stderr=subprocess.DEVNULL)
        return salida.decode().split()[0]
    except Exception as e:
        registrar_prevencion(f'ERROR al calcular hash de {ruta}: {e}', ruta)
        return None

# ----------------------------------------
def registrar_alarma(mensaje):
    fecha = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    log = f"{fecha} :: Alarma: {mensaje}\n"
    # Graba en log de fichero
    with open(LOG_ALARMAS, 'a') as f:
        f.write(log)
    # También muestra en consola para que scripts.php lo capture
    print(log.strip())

# ----------------------------------------
def registrar_prevencion(accion, ruta=None, ret=None):
    fecha = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    parts = [fecha]
    if ruta:
        parts.append(ruta)
    if ret is not None:
        parts.append(f'ret={ret}')
    parts.append(accion)
    log = ' :: '.join(parts) + '\n'
    # Graba en fichero
    with open(LOG_PREVENCION, 'a') as f:
        f.write(log)
    # Mostrar en consola para que scripts.php lo capture
    print(log.strip())

# ----------------------------------------
def enviar_mail(asunto, cuerpo):
    msg = f"Subject: {asunto}\n\n{cuerpo}"
    try:
        subprocess.run(['msmtp', EMAIL_DEST], input=msg.encode(), check=True)
    except Exception as e:
        registrar_prevencion(f'ERROR al enviar mail: {e}')

# ----------------------------------------
def verificar_tabla():
    conn = get_connection()
    cur = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)

    # Traer registros existentes
    cur.execute('SELECT id, archivo, hash FROM archivos_criticos;')
    registros = cur.fetchall()

    for row in registros:
        rec_id     = row['id']
        ruta       = row['archivo']
        hash_guard = row['hash']
        hash_act   = calcular_hash(ruta)

        if not hash_act:
            continue

        if hash_act != hash_guard:
            msg = f"{ruta} modificado (antes {hash_guard[:8]}..., ahora {hash_act[:8]}...)"
            registrar_alarma(msg)
            enviar_mail(f"[HIPS] Alerta integridad: {ruta}", msg)

            try:
                cur.execute(
                    'UPDATE archivos_criticos SET hash = %s, fecha = NOW() WHERE id = %s',
                    (hash_act, rec_id)
                )
                conn.commit()
                registrar_prevencion('PREVENCIÓN: hash actualizado', ruta, 0)
            except Exception as e:
                registrar_prevencion(f'ERROR BD al actualizar hash: {e}', ruta)
        else:
            registrar_prevencion('VERIFICADO OK', ruta, 0)

    cur.close()
    conn.close()

# ----------------------------------------
if __name__ == '__main__':
    verificar_tabla()
