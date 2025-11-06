<?php

class User{
    private $pdo;

    public function __construct($pdo)
    {
        $this -> pdo = $pdo;
    }

    public function findByEmail($email) {
        $sql = "SELECT id, nome, email, senha_hash, ativo, data_cadastro, ultimo_login FROM usuarios WHERE email =?";

        $stmt = $this->pdo->prepare($sql);
        $stmt->execute([$email]);

        return $stmt->fetch();
    }

    public function findById($user_id){

        $sql = "SELECT id, nome, email, senha_hash, ativo, data_cadastro, ultimo_login FROM usuarios WHERE id = ? AND ativo = 1";

        $stmt = $this->pdo->prepare($sql);
        $stmt->execute([$user_id]);

        return $stmt->fetch();
    }

    public function create($nome, $email, $senha_hash){
        $sql = "INSERT INTO usuarios (nome, email, senha_hash) VALUES (?, ?, ?)";

        $stmt = $this->pdo->prepare($sql);
        return $stmt->execute([$nome, $email, $senha_hash]);
    }

    public function updateLastLogin($user_id){
        $sql = "UPDATE usuarios SET ultimo_login = NOW() WHERE id = ?";

        $stmt = $this->pdo->prepare($sql);
        return $stmt->execute([$user_id]);
    }

    public function emailExists($email){

        $sql = "SELECT id FROM usuarios WHERE email = ?";
        $stmt = $this->pdo->prepare($sql);
        $stmt->execute([$email]);
        return $stmt->fetch() !== false;

    }

    public function getLoginHistory($user_id, $limit = 10){
        $sql = "SELECT acao, data_acesso, ip_address, sucesso FROM logs_acesso WHERE usuario_id = ? ORDER BY data_acesso DESC LIMIT ?";

        $stmt = $this->pdo->prepare($sql);
        $stmt->execute([$user_id, $limit]);
        return $stmt->fetchAll();
    }

    public function createResetToken($user_id) {
        $token = bin2hex(random_bytes(32));
        $expires_at = date('Y-m-d H:i:s', strtotime('+1 hour'));

        $sql = "INSERT INTO password_reset_tokens (user_id, token, expires_at) VALUES (?, ?, ?)";
        $stmt = $this->pdo->prepare($sql);
        $stmt->execute([$user_id, $token, $expires_at]);

        return $token;
    }

    public function findResetToken($token) {
        $sql = "SELECT id, user_id, expires_at, used FROM password_reset_tokens WHERE token = ? AND used = 0 AND expires_at > NOW()";
        $stmt = $this->pdo->prepare($sql);
        $stmt->execute([$token]);
        return $stmt->fetch();
    }

    public function useResetToken($token) {
        $sql = "UPDATE password_reset_tokens SET used = 1 WHERE token = ?";
        $stmt = $this->pdo->prepare($sql);
        return $stmt->execute([$token]);
    }

    public function updatePassword($user_id, $new_password_hash) {
        $sql = "UPDATE usuarios SET senha_hash = ? WHERE id = ?";
        $stmt = $this->pdo->prepare($sql);
        return $stmt->execute([$new_password_hash, $user_id]);
    }

}

?>
