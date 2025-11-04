<?php

require_once '../src/config/config.php';

if(isset($_SESSION['user_id'])){
    try{
        Security::logAccess($pdo, $_SESSION['user_id'], 'logout', true);
    } catch(Exception $e){
        error_log("Error logout: " . $e->getMessage());
    }
}

// Destroying session completely
Session::destroy();

Session::setFlash('success', 'logout concluído');
header('Location: login.php')

?>