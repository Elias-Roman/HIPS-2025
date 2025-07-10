<?php
session_start();
if (!isset($_SESSION['usuario'])) {
    header("Location: login.php");
    exit;
}

$scriptDir = '/opt/hips/scripts';
$output = '';
$error = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['script'])) {
    $script = basename($_POST['script']);
    $scriptPath = "$scriptDir/$script";

    if (is_file($scriptPath) && is_readable($scriptPath)) {
        $command = escapeshellcmd("python3 $scriptPath 2>&1");
        $output = shell_exec($command);
    } else {
        $error = "Script inválido o no accesible.";
    }
}

$scripts = [
    "Seguridad" => [
        "verificar_integridad.py" => "Verificar Archivos Críticos",
        "accesos_invalidos.py"    => "Detectar Accesos Fallidos",
        "detectar_sniffers.py"    => "Detectar Herramientas de Sniffing",
        "ataques_ddos.py"         => "Detectar Ataques DDoS DNS",
    ],
    "Monitoreo" => [
        "usuarios_conectados.py" => "Ver Usuarios Conectados",
        "procesos_memoria.py"    => "Monitorear Consumo de Memoria",
    ],
    "Sistema" => [
        "mail_queue.py"    => "Verificar Cola de Correos (msmtp)",
        "revisar_tmp.py"   => "Revisar Archivos Temporales (/tmp)",
        "revisar_cron.py"  => "Analizar Tareas Programadas (cron)",
    ]
];
?>

<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <title>Ejecutar Scripts</title>
    <link href="https://fonts.googleapis.com/css2?family=Orbitron:wght@400;700&family=Share+Tech+Mono&display=swap" rel="stylesheet">
    <style>
        :root {
            --bg-dark: #121212;
            --bg-sidebar: #1a1a1a;
            --text-light: #f4f4f4;
            --accent: #e67e22;
            --accent-hover: #d35400;
        }

        * { box-sizing: border-box; margin: 0; padding: 0; }
        body {
            font-family: 'Share Tech Mono', monospace;
            background-color: var(--bg-dark);
            color: var(--text-light);
            display: flex;
        }

        .sidebar {
            height: 100vh;
            width: 240px;
            background-color: var(--bg-sidebar);
            display: flex;
            flex-direction: column;
            justify-content: space-between;
            padding: 30px 0;
        }

        .sidebar h2 {
            font-family: 'Orbitron', sans-serif;
            text-align: center;
            color: var(--accent);
            margin-bottom: 30px;
        }

        .sidebar a {
            display: block;
            padding: 12px 20px;
            margin: 10px 20px;
            background-color: var(--accent);
            color: var(--text-light);
            text-align: center;
            border-radius: 5px;
            text-decoration: none;
            transition: background 0.3s;
            font-weight: bold;
        }

        .sidebar a:hover {
            background-color: var(--accent-hover);
        }

        .main-content {
            flex: 1;
            padding: 40px;
        }

        h1 {
            font-family: 'Orbitron', sans-serif;
            margin-bottom: 25px;
            color: var(--accent);
        }

        h3 {
            margin-top: 30px;
            color: var(--accent);
            font-size: 1.3rem;
        }

        .botones-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 12px;
            margin-top: 15px;
        }

        .botones-grid form {
            margin: 0;
        }

        button {
            width: 100%;
            padding: 12px;
            background-color: var(--accent);
            color: var(--text-light);
            border: none;
            border-radius: 5px;
            font-size: 1rem;
            font-family: 'Share Tech Mono', monospace;
            font-weight: bold;
            cursor: pointer;
            transition: background-color 0.3s;
        }

        button:hover {
            background-color: var(--accent-hover);
        }

        pre {
            background: #222;
            color: #00ff7f;
            padding: 15px;
            border-radius: 6px;
            margin-top: 25px;
            white-space: pre-wrap;
            border-left: 4px solid var(--accent);
        }

        .error {
            color: #f44336;
            margin-top: 20px;
        }
    </style>
</head>
<body>

    <div class="sidebar">
        <div>
            <h2>HIPS</h2>
            <a href="alertas.php">Ver Alertas</a>
            <a href="scripts.php">Ejecutar Scripts</a>
            <a href="configuracion.php">Configurar Módulos</a>
        </div>
        <div>
            <a href="logout.php">Cerrar sesión</a>
        </div>
    </div>

    <div class="main-content">
        <h1>Ejecutar Scripts del Sistema</h1>

        <?php foreach ($scripts as $categoria => $grupo): ?>
            <h3><?= $categoria ?></h3>
            <div class="botones-grid">
                <?php foreach ($grupo as $file => $nombre): ?>
                    <form method="POST">
                        <input type="hidden" name="script" value="<?= htmlspecialchars($file) ?>">
                        <button type="submit"><?= htmlspecialchars($nombre) ?></button>
                    </form>
                <?php endforeach; ?>
            </div>
        <?php endforeach; ?>

        <?php if ($output): ?>
            <h3>Resultado</h3>
            <pre><?= htmlspecialchars($output) ?></pre>
        <?php endif; ?>

        <?php if ($error): ?>
            <div class="error"><?= htmlspecialchars($error) ?></div>
        <?php endif; ?>
    </div>
</body>
</html>
