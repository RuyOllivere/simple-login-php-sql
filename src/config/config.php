<?php
//enviroment configuration

define('ENVIRONMENT', 'production');

// Database configurations

$host = 'localhost';
$user = 'root';
$pass = '';
$dbName = 'sistema_login_prod';
$charset = 'utf8mb4';

// Include utilities
require_once '../utils/Security.php';
require_once '../utils/Session.php';

// Initialize secure session
Session::start();

// Conecition pdo errors

try{
    $pdo = new PDO("mysql:host=$host;dbName=$dbName;charset=$charset;", $user, $pass, [
        PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
        PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
        PDO::ATTR_EMULATE_PREPARES => false
    ]);
} catch(PDOException $e){
    error_log('Connection error: ' . $e->getMessage());
    die('System error. Try again later.');
}

// Verifing if user is logged

function isLoggedIn() {
    return isset($_SESSION['user_id']) && !empty($_SESSION['user_id']);
}

?>