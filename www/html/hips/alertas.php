<?php
session_start();
if (!isset($_SESSION['usuario'])) {
    header("Location: login.php");
    exit;
}

function leer_log($ruta) {
    if (!file_exists($ruta)) {
        return ["[No existe el archivo: $ruta]"];
    }
    $lineas = file($ruta, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
    return array_reverse($lineas);
}

$alarmas = leer_log("/var/log/hips/alarmas.log");
$prevencion = leer_log("/var/log/hips/prevencion.log");
?>
<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <title>Alertas HIPS</title>
    <link href="https://fonts.googleapis.com/css2?family=Orbitron:wght@400;700&family=Share+Tech+Mono&display=swap" rel="stylesheet">
    <script src="https://kit.fontawesome.com/a2d2706b45.js" crossorigin="anonymous"></script>
    <style>
        :root {
            --bg-dark: #121212;
            --bg-sidebar: #1a1a1a;
            --text-light: #f4f4f4;
            --accent: #e67e22;
            --accent-hover: #d35400;
            --log-bg: #222;
            --log-text: #00ff7f;
            --log-border: #e67e22;
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
            font-size: 2rem;
            margin-bottom: 25px;
            color: var(--accent);
        }

        .section-title {
            font-size: 1.3rem;
            margin: 25px 0 12px;
            color: var(--accent);
            display: flex;
            align-items: center;
            gap: 10px;
            font-family: 'Orbitron', sans-serif;
        }

        .log-section {
            background-color: var(--log-bg);
            border-left: 4px solid var(--log-border);
            padding: 15px;
            border-radius: 6px;
            max-height: 250px;
            overflow-y: auto;
            margin-bottom: 30px;
        }

        .linea {
            color: var(--log-text);
            font-size: 0.85rem;
            line-height: 1.4;
            padding: 3px 0;
            border-bottom: 1px dashed #333;
            white-space: pre-wrap;
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
        <h1>Alertas del Sistema</h1>

        <div class="section-title">Alarmas</div>
        <div class="log-section">
            <?php foreach ($alarmas as $linea): ?>
                <div class="linea"><?= htmlspecialchars($linea) ?></div>
            <?php endforeach; ?>
        </div>

        <div class="section-title">Prevención</div>
        <div class="log-section">
            <?php foreach ($prevencion as $linea): ?>
                <div class="linea"><?= htmlspecialchars($linea) ?></div>
            <?php endforeach; ?>
        </div>
    </div>
</body>
</html>

