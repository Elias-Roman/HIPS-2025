<?php
session_start();
if (!isset($_SESSION['usuario'])) {
    header("Location: login.php");
    exit();
}
?>
<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <title>Panel HIPS</title>
    <!-- Google Fonts -->
    <link href="https://fonts.googleapis.com/css2?family=Orbitron:wght@400;700&family=Share+Tech+Mono&display=swap" rel="stylesheet">
    <style>
        :root {
            --bg-dark: #121212;
            --bg-sidebar: #1a1a1a;
            --text-light: #f4f4f4;
            --accent: #e67e22;
            --accent-hover: #d35400;
        }

        * {
            box-sizing: border-box;
            margin: 0;
            padding: 0;
        }

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

        .main-content h1 {
            font-family: 'Orbitron', sans-serif;
            font-size: 2rem;
            margin-bottom: 20px;
            color: var(--accent);
        }

        .main-content p {
            font-size: 1rem;
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
        <h1>Bienvenido, <?= htmlspecialchars($_SESSION['usuario']); ?></h1>
        <p>Selecciona una opción del panel lateral para comenzar.</p>
    </div>
</body>
</html>
