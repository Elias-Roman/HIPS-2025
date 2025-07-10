# HIPS-2025
Trabajo Practico Final - SO2

Manual de Instalacion del Sistema HIPS
1. Preparación del entorno
  1.1. Actualizar el sistema
  sudo apt update && sudo apt upgrade -y
  1.2. Instalar dependencias
  sudo apt install python3 python3-pip apache2 php libapache2-mod-php postgresql php-pgsql postfix msmtp mailutils net-tools -y

2. Estructura de directorios
sudo mkdir -p /opt/hips/scripts
sudo mkdir -p /var/log/hips
sudo touch /var/log/hips/alarmas.log /var/log/hips/prevencion.log
sudo chmod 750 /var/log/hips
sudo chown root:root /var/log/hips/*

3. Instalar dependencias de Python
pip3 install bcrypt psycopg2

4. Configuración de PostgreSQL segura (CIS Benchmark)
  4.1. Crear base y usuario
  sudo -u postgres psql
  CREATE USER hips_user WITH PASSWORD 'ContraseñaSegura';
  CREATE DATABASE hips_db OWNER hips_user;
  \q
  4.2. Crear tablas básicas
  \c hips_db
  CREATE TABLE usuarios (
      id SERIAL PRIMARY KEY,
      usuario VARCHAR(50) UNIQUE NOT NULL,
      contrasena_hash TEXT NOT NULL
  );
  
  CREATE TABLE alertas (
      id SERIAL PRIMARY KEY,
      fecha TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      descripcion TEXT NOT NULL,
      severidad VARCHAR(20),
      ip_origen VARCHAR(45)
  );
  4.3. Configurar autenticación segura (pg_hba.conf)
  Reemplazar:
  local   all             all                                     md5
  Por:
  local   all             all                                     scram-sha-256
  Luego reiniciar:
  sudo systemctl restart postgresql

5. Configurar msmtp para envío de correos
Editar /etc/msmtprc:
defaults
auth           on
tls            on
tls_trust_file /etc/ssl/certs/ca-certificates.crt
logfile        ~/.msmtp.log

account        correo
host           smtp.example.com
port           587
from           tu_correo@example.com
user           tu_correo@example.com
password       <TU_CONTRASEÑA_DE_APLICACION_DE_16_CARACTERES)

account default : gmail

6. Configurar interfaz web (PHP + Apache)
  6.1. Ubicar archivos en /var/www/html/hips
  login.php, verificar_login.php, logout.php, dispatcher.php
  index.php, alertas.php, configuracion.php, scripts.php
  db.php, config.json
  6.2. Asegurar archivos sensibles
  sudo chown -R www-data:www-data /var/www/html/hips
  sudo chmod 640 /var/www/html/hips/config.json
  6.3 Dar permisos al usuaurio www-data
  sudo visudo
  Agregar esta linea al final:
  www-data ALL=(ALL) NOPASSWD: ALL

7. Automatización (crontab)
sudo crontab -u www-data -e
Agregar esta linea al final:
* * * * * php /var/www/html/hips/dispatcher.php
