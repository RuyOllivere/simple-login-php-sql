<?php

class Security{
    public static function sanitizeInput($data) {
        return htmlspecialchars(trim($data), ENT_QUOTES, 'UTF-8');
    }

    public static function generateCSFRToken(){
        if (empty($_SESSION['csrf_token'])){
            $_SESSION['csrf_token'] = bin2hex(random_bytes(64));
        }

        return $_SESSION['csrf_token'];
    }

    public static function verifyCSRFToken($token){
        return isset($_SESSION['csrf_token']) && hash_equals($_SESSION['csrf_token'], $token);
    }

    public static function validateEmail($email){
        return filter_var($email, FILTER_VALIDATE_EMAIL);
    }

    public static function validatePassword($password){
        return strlen($password) >= 8;
    }

    public static function validateName($name) {
        return !empty($name) && strlen($name) >= 2;
    }
}

?>