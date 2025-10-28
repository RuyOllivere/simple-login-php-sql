<?php

class Session {
    public static function start(){
        if(session_status() == PHP_SESSION_NONE){
            session_set_cookie_params([
                'lifetime' => 0,
                'path' => '/',
                'domain' => '',
                'secure' => true,
                'httponly' => true,
                'samesite' => 'Strict'
            ]);
            // testing
            // test
            session_start();

        }
    }

    public static function destroy(){
        if(session_status() != PHP_SESSION_NONE){
            $_SESSION = [];
            if(ini_get("session.use_cookies")){
                $params = session_get_cookie_params();
                setcookie(session_name(), '', time() - 42000,
                    $params["path"], $params["domain"],
                    $params["secure"], $params["httponly"]
                );
            }
            session_destroy();
        }
    }

    public static function regenerate(){
        if(session_status() != PHP_SESSION_NONE){
            session_regenerate_id(true);
        }
    }

    public static function getFlash($key){
        if(session_status() != PHP_SESSION_NONE && isset($_SESSION['flash'][$key])){
            $value = $_SESSION['flash'][$key];
            unset($_SESSION['flash'][$key]);
            return $value;
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

        
    public static function setFlash($key, $message){
        if(session_status() != PHP_SESSION_NONE){
            $_SESSION['flash'][$key] = $message;
        }
    }

}

?>