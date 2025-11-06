<?php

class Security{

    // remove danger inputs and prevent XSS
    public static function sanitizeInput($data) {
        return htmlspecialchars(trim($data), ENT_QUOTES, 'UTF-8');
    }

    // Generate Token
    public static function generateCSFRToken(){
        if (empty($_SESSION['csrf_token'])){
            $_SESSION['csrf_token'] = bin2hex(random_bytes(64));
        }

        return $_SESSION['csrf_token'];
    }

    // Verify if the token is valid
    public static function verifyCSRFToken($token){
        return isset($_SESSION['csrf_token']) && hash_equals($_SESSION['csrf_token'], $token);
    }

    // Validate email
    public static function validateEmail($email){
        return filter_var($email, FILTER_VALIDATE_EMAIL);
    }

    // Validate if the password is "safe"
    public static function validatePassword($password){
        return strlen($password) >= 8 && preg_match('/[A-Za-z0-9]/', $password) && preg_match('/[0-9]/', $password) && preg_match('/[A-Z]/', $password) && preg_match('/[a-z]/', $password);

    }

    // Validate the lenght min and max of a name
    public static function validateName($name) {
        return !empty($name) && strlen($name) >= 2 && strlen($name) <= 100;
    }

    // Generate the log access of a user for aud
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