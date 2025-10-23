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

?>