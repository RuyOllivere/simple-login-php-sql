<?php

class Session {
    public static function start() {
        if (session_status() == PHP_SESSION_NONE) {
            session_set_cookie_params([
                'lifetime' => 0,
                'path' => '/', // cookie em todas as pág do site
                'domain' => '', // localhost
                'secure' => true,
                'httponly' => true,
                'samesite' => 'Strict'
            ]);
 
            session_start();
        }
    }
 
    public static function destroy() {
        $_SESSION = [];
        session_destroy();
        setcookie(session_name(), '', time() - 3600, '/');
    }
 
    public static function setFlash($type, $message) {
        $_SESSION['flash'][$type] = $message;
    }
 
    public static function getFlash($type) {
        if(isset($_SESSION['flash'][$type])) {
            $message = $_SESSION['flash'][$type];
            unset($_SESSION['flash'][$type]);
            return $message;
        }
 
        return null;
    }

    public static function setUser($user){
        $_SESSION['user_id'] = $user['id'];
        $_SESSION['user_nome'] = $user['nome'];
        $_SESSION['user_email'] = $user['email'];
        $_SESSION['loged_in'] = true;
    }

    public static function getUser(){
        return [
            'id'   => $_SESSION['user_id'] ?? null,
            'nome' => $_SESSION['user_nome'] ?? null,
            'email'=> $_SESSION['user_email'] ?? null,
        ];
    }

}

?>