<?php
declare(strict_types=1);

require_once __DIR__ . '/config.php';

setcookie('remember_me', '', time() - 3600, '/', '', false, true);

$_SESSION = [];
if (session_status() === PHP_SESSION_ACTIVE) {
    session_unset();
    session_destroy();
}

header('Location: index.php');
exit;
