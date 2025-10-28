<?php

class User{
    private $pdo;

    public function __construct($pdo)
    {
        $this -> pdo = $pdo;
    }

    public function findByEmail($email) {
        $sql = "SELECT id, nome, email, senha_hash, ativo, data_cadastro, ultimo_login, FROM usuarios WHERE email =?";

        $stmt = $this->pdo->prepare($sql);
        $stmt->execute([$email]);

        return $stmt->fetch();
    }

    public function findById($user_id){

        $sql = "SELECT id, nome, email, senha_hash, ativo, data_cadastro, ultimo_login, FROM usuarios WHERE id = ? AND ativo = 1";

        $stmt = $this->pdo->prepare($sql);
        $stmt->execute([$user_id]);

        return $stmt->fetch();

        

    }

}

?>