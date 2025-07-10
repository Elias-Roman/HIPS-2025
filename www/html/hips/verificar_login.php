<?php
session_start();
require 'db.php';

$username = $_POST['usuario'] ?? '';
$password = $_POST['clave'] ?? '';

$stmt = $pdo->prepare("SELECT password FROM credenciales WHERE username = :username");
$stmt->execute(['username' => $username]);
$row = $stmt->fetch();

if ($row && password_verify($password, $row['password'])) {
    $_SESSION['usuario'] = $username;
    header("Location: index.php");
    exit;
} else {
    if (!$row) {
        $_SESSION['login_error'] = "Usuario no encontrado.";
    } else {
        $_SESSION['login_error'] = "Contraseña incorrecta.";
    }
    header("Location: login.php");
    exit;
}
