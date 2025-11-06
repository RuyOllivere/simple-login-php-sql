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

-- Password Reset Tokens table
CREATE TABLE IF NOT EXISTS password_reset_tokens (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NOT NULL,
    token VARCHAR(255) NOT NULL UNIQUE,
    expires_at TIMESTAMP NOT NULL,
    used TINYINT(1) DEFAULT 0,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES usuarios(id) ON DELETE CASCADE,
    INDEX idx_token(token),
    INDEX idx_expires_at(expires_at)
) ENGINE = InnoDB;

-- Table must be

CREATE TABLE tokens_reset (
    id INT AUTO_INCREMENT PRIMARY KEY,
    usuario_id INT NOT NULL,
    token VARCHAR(64) NOT NULL,
    expira_em TIMESTAMP NOT NULL,
    usado TINYINT(1) DEFAULT 0,
    FOREIGN KEY (usuario_id) REFERENCES usuarios(id),
    INDEX idx_token (token),
    INDEX idx_expira (expira_em)
);

ALTER TABLE usuarios ADD COLUMN email_verificado TINYINT(1) DEFAULT 0;

-- Insert example user with password: '12345'

-- INSERT INTO usuarios(nome, email, senha_hash) VALUES
-- ('User test', 'exemplo@email.com', '123456');