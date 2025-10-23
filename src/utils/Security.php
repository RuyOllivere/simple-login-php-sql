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
        return !empty($name) && strlen($name) >= 2 && strlen($name) <= 100;
    }

    public static function logAccess($pdo, $user_id, $action, $success){
        try{
            $sql = "INSERT INTO logs_acesso (usuario_id, ip_address, user_agent, acao, sucesso) 
            VALUES (?, ?, ?, ?, ?)";

            $stmt = $pdo->prepare($sql);

            $stmt->execute([
                $user_id,
                $_SERVER['REMOTE_ADDR'],
                $_SERVER['HTTP_USER_AGENT'] ?? 'Unknown',
                $action,
                $success ? 1 : 0
            ]);
            return true;
        } catch(PDOException $e){
            error_log("Error to registrate: " . $e->getMessage());
            return false;
        }
    }

    public static function redirect($url, $message = null){
        if($message){
            $_SESSION['flash_message'] = $message;
        }
        header('Location:' . $url);

        exit();
    }

}

?>