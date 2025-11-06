# 🔐 Sistema de Login Seguro em PHP (MVC + PDO + Bootstrap)

> Repositório base para um sistema de autenticação em **PHP puro**, estruturado com **boas práticas de segurança** (CSRF, XSS, hashing de senhas, sessões seguras) e arquitetura organizada (MVC simplificado).  
> Ideal como base para aplicações internas ou aprendizado de segurança em PHP.

---

## 🧭 Índice

- [Descrição](#descrição)  
- [Tecnologias](#tecnologias)  
- [Estrutura do Repositório](#estrutura-do-repositório)  
- [Banco de Dados (SQL)](#banco-de-dados-sql)  
- [Configuração (`config.php`)](#configuração-configphp)  
- [Classe `Session.php`](#classe-sessionphp)  
- [Fluxo de Autenticação](#fluxo-de-autenticação)  
- [Como Executar Localmente](#como-executar-localmente)  
- [Guia Rápido para Novatos na Empresa](#guia-rápido-para-novatos-na-empresa)  
- [Boas Práticas de Segurança](#boas-práticas-de-segurança)  
- [Debug e Troubleshooting](#debug-e-troubleshooting)  
- [Contato / Manutenção](#contato--manutenção)

---

## 📘 Descrição

O sistema implementa as seguintes funcionalidades:

- Cadastro e login de usuários com `password_hash()` e `password_verify()`.  
- Sessões seguras (HTTPOnly, SameSite, Secure).  
- Recuperação e redefinição de senha via token temporário.  
- Atualização de perfil.  
- Registro de logs de acesso.  
- Proteções CSRF e XSS básicas.  

Front-end simples com **Bootstrap 5** + **CSS customizado**.

---

## ⚙️ Tecnologias

- **PHP 8+**  
- **MySQL / MariaDB**  
- **PDO** (prepared statements)  
- **Bootstrap 5**  
- **HTML5 / CSS3**  
- **Sessions & Cookies Seguros**

---

## 🗂️ Estrutura do Repositório

├── logs/
│ └── errors.log
├── public/
│ ├── assets/CSS/style.css
│ ├── cadastro.php
│ ├── dashboard.php
│ ├── index.php
│ ├── login.php
│ ├── logout.php
│ ├── recuperar_senha.php
│ └── reset.php
├── src/
│ ├── config/
│ │ └── config.php
│ ├── controllers/
│ │ ├── AuthController.php
│ │ └── UserController.php
│ ├── models/
│ │ └── User.php
│ └── utils/
│ ├── Security.php
│ └── Session.php
├── database.sql
└── README.md


---

## 🧩 Banco de Dados (SQL)

Crie o banco com o seguinte script (`database.sql`):

```sql
CREATE TABLE usuarios (
  id INT AUTO_INCREMENT PRIMARY KEY,
  nome VARCHAR(100) NOT NULL,
  email VARCHAR(255) UNIQUE NOT NULL,
  senha_hash VARCHAR(255) NOT NULL,
  ativo TINYINT(1) DEFAULT 1,
  data_cadastro DATETIME DEFAULT CURRENT_TIMESTAMP,
  ultimo_login DATETIME DEFAULT NULL
);

CREATE TABLE password_reset_tokens (
  id INT AUTO_INCREMENT PRIMARY KEY,
  user_id INT NOT NULL,
  token VARCHAR(255) NOT NULL,
  expires_at DATETIME NOT NULL,
  used TINYINT(1) DEFAULT 0,
  FOREIGN KEY (user_id) REFERENCES usuarios(id) ON DELETE CASCADE
);

CREATE TABLE logs_acesso (
  id INT AUTO_INCREMENT PRIMARY KEY,
  usuario_id INT,
  ip_address VARCHAR(45),
  user_agent TEXT,
  acao VARCHAR(50),
  sucesso TINYINT(1),
  data_acesso DATETIME DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (usuario_id) REFERENCES usuarios(id) ON DELETE SET NULL
);

```
## ⚙️ Configuração (config.php)

Crie o arquivo src/config/config.php com o conteúdo abaixo e ajuste suas credenciais:

```php
<?php
// Environment configuration
define('ENVIRONMENT', 'production');

// Database configurations
$host = 'localhost';
$user = 'root';
$pass = '';
$dbName = 'sistema_login_prod';
$charset = 'utf8mb4';

// Include utilities
require_once __DIR__ . '/../utils/Security.php';
require_once __DIR__ . '/../utils/Session.php';

// Initialize secure session
Session::start();

// PDO connection
try {
    $pdo = new PDO("mysql:host=$host;dbname=$dbName;charset=$charset;", $user, $pass, [
        PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
        PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
        PDO::ATTR_EMULATE_PREPARES => false
    ]);
} catch (PDOException $e) {
    error_log('Connection error: ' . $e->getMessage());
    die('System error. Try again later.');
}

// Auth helper functions
function isLoggedIn() {
    return isset($_SESSION['user_id']) && !empty($_SESSION['user_id']);
}

function requireLogin() {
    if(!isLoggedIn()){
        $_SESSION['error'] = 'Por favor, faça login para acessar esta página.';
        header('Location: ../public/login.php');
        exit();
    }
}

// Debug helper
function debug($data) {
    if (defined('ENVIRONMENT') && ENVIRONMENT === 'development') {
        echo '<pre>';
        print_r($data);
        echo '</pre>';
    }
}
?>
```
---

## 🛡️ Classe `Session.php`
A classe `Session.php` em `src/utils/Session.php` gerencia sessões seguras com configurações apropriadas para cookies:

```php
<?php
class Session {
    public static function start() {
        if (session_status() == PHP_SESSION_NONE) {
            session_set_cookie_params([
                'lifetime' => 0,
                'path' => '/',
                'domain' => '',
                'secure' => true,
                'httponly' => true,
                'samesite' => 'Strict'
            ]);
            session_start();
        }
    }

    public static function destroy() {
        $_SESSION = [];
        if (session_status() !== PHP_SESSION_NONE) {
            session_destroy();
        }
        setcookie(session_name(), '', time() - 3600, '/');
    }

    public static function setFlash($type, $message) {
        $_SESSION['flash'][$type] = $message;
    }

    public static function getFlash($type) {
        if (isset($_SESSION['flash'][$type])) {
            $message = $_SESSION['flash'][$type];
            unset($_SESSION['flash'][$type]);
            return $message;
        }
        return null;
    }

    public static function setUser($user) {
        $_SESSION['user_id'] = $user['id'];
        $_SESSION['user_nome'] = $user['nome'];
        $_SESSION['user_email'] = $user['email'];
        $_SESSION['loged_in'] = true;
    }

    public static function getUser() {
        return [
            'id'    => $_SESSION['user_id'] ?? null,
            'nome'  => $_SESSION['user_nome'] ?? null,
            'email' => $_SESSION['user_email'] ?? null,
        ];
    }
}
?>
```

## 🔄 Fluxo de Autenticação

Cadastro:

 - Recebe POST com nome, email, senha, confirmar_senha.

 - Valida dados, cria hash (password_hash()), insere no banco.

 - Redireciona para login.

Login:

 - Valida email e senha com password_verify().

 - Cria sessão e atualiza ultimo_login.

Recuperação de Senha:

 - Gera token com validade (1h), armazena em password_reset_tokens.

 - Link enviado: reset.php?token=....

Redefinição:

 - Valida token, cria novo hash, marca token como used.

Logout:

 - Finaliza sessão e redireciona para login.

 ## 🚀 Como Executar Localmente
1. Clone o repositório:  
    `git clone https://github.com/RuyOllivere/simple-login-php-sql.git`
    `cd sistema-login-php`

2. Configure o banco de dados:
    - `mysql -u root -p -e "CREATE DATABASE sistema_login_prod CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci;"`
    - `mysql -u root -p sistema_login_prod < database.sql`

---

# 1. Clonar o repositório
git clone https://github.com/RuyOllivere/simple-login-php-sql.git
cd sistema-login-php

# 2. Criar banco de dados
mysql -u root -p -e "CREATE DATABASE sistema_login_prod;"

# 3. Importar estrutura
mysql -u root -p sistema_login_prod < database.sql

# 4. Configurar credenciais
nano src/config/config.php

# 5. Rodar localmente
php -S localhost:8000 -t public


