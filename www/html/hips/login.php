<?php
session_start();
$error = $_SESSION['login_error'] ?? '';
unset($_SESSION['login_error']);
?>
<!DOCTYPE html>
<html lang="es">
<head>
  <meta charset="UTF-8">
  <title>Login HIPS</title>
  <link href="https://fonts.googleapis.com/css2?family=Orbitron:wght@400;700&family=Share+Tech+Mono&display=swap" rel="stylesheet">
  <style>
    :root {
      --bg-dark: #121212;
      --text-light: #f4f4f4;
      --accent:   #e67e22;
      --input-bg: #1e1e1e;
      --input-border: #333;
      --error-bg: #3e1f1f;
      --error-text: #f44336;
    }
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      background: var(--bg-dark);
      color: var(--text-light);
      display: flex;
      justify-content: center;
      align-items: center;
      height: 100vh;
      font-family: 'Share Tech Mono', monospace;
    }
    .login-box {
      background: #1a1a1a;
      padding: 2rem;
      border-radius: 6px;
      box-shadow: 0 4px 12px rgba(0,0,0,0.7);
      width: 320px;
    }
    .login-box h1 {
      font-family: 'Orbitron', sans-serif;
      text-align: center;
      margin-bottom: 1.5rem;
      color: var(--accent);
      letter-spacing: 1px;
    }
    .login-box label {
      display: block;
      margin-bottom: 0.3rem;
      font-size: 0.9rem;
    }
    .login-box input {
      width: 100%;
      padding: 0.5rem;
      margin-bottom: 1rem;
      background: var(--input-bg);
      border: 1px solid var(--input-border);
      border-radius: 4px;
      color: var(--text-light);
      font-size: 1rem;
    }
    .login-box button {
      width: 100%;
      padding: 0.7rem;
      background: var(--accent);
      border: none;
      border-radius: 4px;
      color: var(--text-light);
      font-size: 1rem;
      cursor: pointer;
      transition: background 0.2s;
      font-family: 'Orbitron', sans-serif;
      letter-spacing: 0.5px;
    }
    .login-box button:hover {
      background: #d35400;
    }
    .error {
      background: var(--error-bg);
      color: var(--error-text);
      padding: 0.7rem;
      border-radius: 4px;
      margin-bottom: 1rem;
      text-align: center;
      font-size: 0.9rem;
    }
  </style>
</head>
<body>
  <div class="login-box">
    <h1>INICIAR SESIÓN</h1>
    <?php if (!empty($error)): ?>
      <div class="error"><?= htmlspecialchars($error) ?></div>
    <?php endif; ?>
    <form method="post" action="verificar_login.php">
      <label for="usuario">Usuario</label>
      <input type="text" id="usuario" name="usuario" required autofocus>

      <label for="clave">Clave</label>
      <input type="password" id="clave" name="clave" required>

      <button type="submit">ENTRAR</button>
    </form>
  </div>
</body>
</html>
