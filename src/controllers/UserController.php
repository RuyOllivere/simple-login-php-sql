<?php

require_once '../config/config.php';
require_once '../models/User.php';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $action = $_GET['action'] ?? '';

    if($action === 'update_profile' && isLoggedIn()){
        handleUpdateProfile($pdo);
    }
}
function handleUpdateProfile($pdo) {
    // CSRF Token verify
    
}
?>