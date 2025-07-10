#!/usr/bin/env python3
import os
import hashlib
import subprocess
from datetime import datetime
import psycopg2
import psycopg2.extras

# Datos de conexión a la base de datos
DB_HOST = '127.0.0.1'
DB_PORT = '5432'
DB_NAME = 'hips_db'
DB_USER = 'hips_user'
DB_PASS = 'elias2004'

# Rutas a los logs donde se registran las alarmas y acciones tomadas
LOG_ALARMAS    = '/var/log/hips/alarmas.log'
LOG_PREVENCION = '/var/log/hips/prevencion.log'

# Correo al que se enviarán las alertas
EMAIL_DEST     = 'eliasdavidroman@gmail.com'

# ----------------------------------------
# Función que establece la conexión con la base de datos PostgreSQL
def get_connection():
    return psycopg2.connect(host=DB_HOST, port=DB_PORT, dbname=DB_NAME,
                            user=DB_USER, password=DB_PASS)

# ----------------------------------------
# Calcula el hash SHA-256 de un archivo determinado
# Si el archivo es /etc/shadow, lo hace con sudo porque es un archivo protegido
def calcular_hash(ruta):
    try:
        cmd = ['sha256sum', ruta] if ruta != '/etc/shadow' else ['sudo', 'sha256sum', ruta]
        salida = subprocess.check_output(cmd, stderr=subprocess.DEVNULL)
        return salida.decode().split()[0]
    except Exception as e:
        registrar_prevencion(f'ERROR al calcular hash de {ruta}: {e}', ruta)
        return None

# ----------------------------------------
# Guarda una línea en el archivo de alarmas con la fecha y el mensaje de alerta
def registrar_alarma(mensaje):
    fecha = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    log = f"{fecha} :: Alarma: {mensaje}\n"
    with open(LOG_ALARMAS, 'a') as f:
        f.write(log)
    print(log.strip())  # También lo muestra por consola (útil si se ejecuta desde PHP)

# ----------------------------------------
# Registra una acción de prevención, sea exitosa o con error
# Se guarda en el log de prevención con la fecha, la ruta del archivo (si aplica), código de retorno y mensaje
def registrar_prevencion(accion, ruta=None, ret=None):
    fecha = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    parts = [fecha]
    if ruta:
        parts.append(ruta)
    if ret is not None:
        parts.append(f'ret={ret}')
    parts.append(accion)
    log = ' :: '.join(parts) + '\n'
    with open(LOG_PREVENCION, 'a') as f:
        f.write(log)
    print(log.strip())  # Para que también se vea en salida estándar

# ----------------------------------------
# Envía un correo usando msmtp en caso de que se detecte una modificación
def enviar_mail(asunto, cuerpo):
    msg = f"Subject: {asunto}\n\n{cuerpo}"
    try:
        subprocess.run(['msmtp', EMAIL_DEST], input=msg.encode(), check=True)
    except Exception as e:
        registrar_prevencion(f'ERROR al enviar mail: {e}')

# ----------------------------------------
# Función principal que consulta la base de datos, verifica los archivos y actúa en base a eso
def verificar_tabla():
    conn = get_connection()
    cur = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)

    # Trae todos los archivos registrados como críticos en la tabla
    cur.execute('SELECT id, archivo, hash FROM archivos_criticos;')
    registros = cur.fetchall()

    for row in registros:
        rec_id     = row['id']
        ruta       = row['archivo']
        hash_guard = row['hash']
        hash_act   = calcular_hash(ruta)

        # Si no se pudo calcular el hash, pasa al siguiente archivo
        if not hash_act:
            continue

        # Si el hash actual no coincide con el guardado, se detecta modificación
        if hash_act != hash_guard:
            msg = f"{ruta} modificado (antes {hash_guard[:8]}..., ahora {hash_act[:8]}...)"
            registrar_alarma(msg)  # Se guarda como alarma
            enviar_mail(f"[HIPS] Alerta integridad: {ruta}", msg)  # Y se manda correo

            # Intenta actualizar el nuevo hash en la base de datos
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
            # Si no hubo cambios, se registra que está todo bien
            registrar_prevencion('VERIFICADO OK', ruta, 0)

    # Cierre de conexión
    cur.close()
    conn.close()

# ----------------------------------------
# Punto de entrada del script
if __name__ == '__main__':
    verificar_tabla()
