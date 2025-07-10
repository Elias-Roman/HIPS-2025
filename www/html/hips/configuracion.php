<?php
session_start();
if (!isset($_SESSION['usuario'])) {
    header("Location: login.php");
    exit;
}

define('CONFIG_FILE', __DIR__ . '/config.json');

if (file_exists(CONFIG_FILE)) {
    $cfg = json_decode(file_get_contents(CONFIG_FILE), true);
    if (json_last_error() !== JSON_ERROR_NONE) {
        $cfg = ['auto_run_enabled'=>false, 'auto_run_interval'=>60];
    }
} else {
    $cfg = ['auto_run_enabled'=>false, 'auto_run_interval'=>60];
}

$msg = '';
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $enabled  = isset($_POST['auto_run_enabled']) && $_POST['auto_run_enabled'] === '1';
    $interval = filter_input(INPUT_POST, 'auto_run_interval', FILTER_VALIDATE_INT, ['options'=>['min_range'=>1]]) ?: 1;

    $cfg['auto_run_enabled']  = $enabled;
    $cfg['auto_run_interval'] = $interval;

    if (file_put_contents(CONFIG_FILE, json_encode($cfg, JSON_PRETTY_PRINT)) !== false) {
        $msg = '¡Configuración guardada!';
    } else {
        $msg = 'Error al guardar. Revisa permisos.';
    }
}
?>
<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <title>Configuración HIPS</title>
    <link href="https://fonts.googleapis.com/css2?family=Orbitron:wght@400;700&family=Share+Tech+Mono&display=swap" rel="stylesheet">
    <style>
        :root {
            --bg-dark: #121212;
            --bg-sidebar: #1a1a1a;
            --text-light: #f4f4f4;
            --accent: #e67e22;
            --accent-hover: #d35400;
            --ok: #27ae60;
            --err: #e74c3c;
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

        .msg {
            padding: 10px 15px;
            border-radius: 4px;
            margin-bottom: 20px;
            font-weight: bold;
        }

        .ok { background-color: rgba(39, 174, 96, 0.1); border-left: 5px solid var(--ok); color: var(--ok); }
        .err { background-color: rgba(231, 76, 60, 0.1); border-left: 5px solid var(--err); color: var(--err); }

        form {
            background-color: #1e1e1e;
            padding: 20px;
            border-radius: 8px;
            max-width: 400px;
        }

        label {
            display: block;
            margin-bottom: 10px;
            font-size: 1rem;
        }

        input[type="number"] {
            width: 100%;
            padding: 8px;
            margin-top: 5px;
            background-color: #2b2b2b;
            color: var(--text-light);
            border: 1px solid #444;
            border-radius: 4px;
            font-family: 'Share Tech Mono', monospace;
        }

        input[type="checkbox"] {
            transform: scale(1.2);
            margin-right: 10px;
        }

        button {
            margin-top: 15px;
            background-color: var(--accent);
            color: var(--text-light);
            padding: 10px 20px;
            border: none;
            font-family: 'Orbitron', sans-serif;
            font-size: 1rem;
            border-radius: 4px;
            cursor: pointer;
            transition: background 0.2s;
        }

        button:hover {
            background-color: var(--accent-hover);
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
        <h1>Configuración de Ejecución Automática</h1>

        <?php if($msg): ?>
            <div class="msg <?= strpos($msg, 'Error') === 0 ? 'err' : 'ok' ?>">
                <?= htmlspecialchars($msg) ?>
            </div>
        <?php endif; ?>

        <form method="post">
            <label>
                <input type="checkbox" name="auto_run_enabled" value="1" <?= $cfg['auto_run_enabled'] ? 'checked' : '' ?>>
                Habilitar auto-run
            </label>

            <label for="int">Intervalo (minutos):</label>
            <input id="int" type="number" name="auto_run_interval" min="1" value="<?= $cfg['auto_run_interval'] ?>">

            <button type="submit">Guardar</button>
        </form>
    </div>
</body>
</html>
