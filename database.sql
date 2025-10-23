-- Create database
CREATE DATABASE IF NOT EXISTS sistema_login_prod CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci;
USE sistema_login_prod;

-- Create users table
CREATE TABLE IF NOT EXISTS usuarios (
    id INT AUTO_INCREMENT PRIMARY KEY,
    nome VARCHAR(100) NOT NULL,
    email VARCHAR(255) NOT NULL UNIQUE,
    senha_hash VARCHAR(255) NOT NULL,
    data_cadastro TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    ultimo_login TIMESTAMP NULL,
    ativo TINYINT(1) DEFAULT 1,
    INDEX idx_email(email),
    INDEX idx_ativo(ativo)
) ENGINE = InnoDB;

-- Security Logs table
CREATE TABLE IF NOT EXISTS logs_acesso(
    id INT AUTO_INCREMENT PRIMARY KEY,
    usuario_id INT,
    ip_address VARCHAR(45) NOT NULL,
    user_agent TEXT,
    data_acesso TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    acao VARCHAR(50) NOT NULL,
    sucesso TINYINT(1) NOT NULL,
    FOREIGN KEY (usuario_id) REFERENCES usuarios(id) ON DELETE SET NULL
) ENGINE = InnoDB;

-- Insert example user with password: '12345'

-- INSERT INTO usuarios(nome, email, senha_hash) VALUES
-- ('User test', 'teste@gmail.com', '5994471ABB01112AFCC18159F6CC74B4F511B99806DA59B3CAF5A9C173CACFC5');