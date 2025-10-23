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
            session_start();

        }
    }
}

?>