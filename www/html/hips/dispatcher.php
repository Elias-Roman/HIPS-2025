<?php
// Dispatcher que ejecuta solo tus scripts .py de /opt/hips/scripts

// Configuración y tiempos
$configFile = __DIR__ . '/config.json';
$stampFile  = __DIR__ . '/.last_run_timestamp';

if (!file_exists($configFile)) exit;
$cfg = json_decode(file_get_contents($configFile), true);
if (!$cfg['auto_run_enabled']) exit;

$last = file_exists($stampFile) ? (int)file_get_contents($stampFile) : 0;
$now  = time();
if (($now - $last) < ($cfg['auto_run_interval'] * 60)) exit;

// Ejecutar .py en carpeta de scripts
$sdir = '/opt/hips/scripts';
$py   = glob($sdir.'/*.py');
foreach ($py as $file) {
    $cmd = 'python3 '.escapeshellarg($file).' 2>&1';
    exec($cmd, $out, $ret);
    // Loguea salida
    $log = date('c') . " :: $file :: ret=$ret\n" . implode("\n", $out) . "\n";
    file_put_contents('/var/log/hips/prevencion.log', $log, FILE_APPEND);
    $out = [];
}

// Actualiza timestamp\ nfile_put_contents($stampFile, $now);
