<?php
require_once '../config/config.php';
require_once '../models/User.php';

if($_SERVER['REQUEST_METHOD'] === 'POST'){
    $action = $_GET['action'] ?? '';

    if($action === 'register'){
        handleRegister($pdo);
    } elseif($action === 'login'){
        handleLogin($pdo);
    } elseif($action === 'reset'){
        handleReset($pdo);
    } elseif($action === 'reset_password'){
        handleResetPassword($pdo);
    }
}

function handleRegister($pdo){
    // Verify CSRF TOKEN
    if(!security::verifyCSRFToken($_POST['csrf_token']) ?? ''){
        Session::setFlash('error', "Token de segurança inválido");
        header('Location: ../../public/cadastro.php');
        exit();
    }

    $nome = Security::sanitizeInput($_POST['nome'] ?? '');
    $email = filter_var($_POST['email'] ?? '', FILTER_SANITIZE_EMAIL);
    $senha = $_POST['senha'] ?? '';
    $confirmar_senha = $_POST['confirmar_senha'] ?? '';
    
    // Validation
    $errors = [];

    if(!Security::validateName($nome)){
        $errors[] = "Nome deve ter entre 2 e 100.";
    }

    if(!Security::validateEmail(($email))){
        $errors[] = "Email inválido";
    }

    if(!Security::validatePassword($senha)){
        $errors[] = "Senha deve conter pelo menos 8 caracteres.";
    }

    if($senha !== $confirmar_senha){
        $errors[] = "Senhas não coincidem.";
    }

    if(empty($errors)) {
        try{
            $userModel = new User($pdo);

            // Verify if email already exists.
            if($userModel->emailExists($email)){
                $errors[] = "Email já cadastrado.";
            } else {
                $senha_hash = password_hash($senha, PASSWORD_DEFAULT);

                // Insert user
                if($userModel->create($nome, $email, $senha_hash)){
                    Session::setFlash('success', 'Cadastro realizado.');

                    header('Location: ../../public/login.php');
                    exit();
                }

                else{
                    $errors[] = "Erro durante a criação da conta.";
                }

            }
        } catch(Exception $e){
            error_log("Register error: " . $e->getMessage() . '\n', 3, "../logs/errors.log");
            $errors[] = "Erro dentro do sistema, realize o cadastro novamente mais tarde." . $e;
        }

        }
        if(!empty($errors)){
            Session::setFlash('error', implode('<br>', $errors));
            header('Location: ../../public/cadastro.php');
        }
}


function handleLogin($pdo){

    if(!security::verifyCSRFToken($_POST['csrf_token']) ?? ''){
        Session::setFlash('error', "Token de segurança inválido");
        header('Location: ../../public/login.php');
        exit();
    }

    $email = filter_var($_POST['email'] ?? '', FILTER_SANITIZE_EMAIL);
    $senha = $_POST['senha'] ?? '';

    // Validation
    $errors = [];

    if (!Security::validateEmail($email)){
        $errors[] = "Email incorreto.";
    }

    if(empty($senha)){
        $errors[]="Senha não pode ser vazia.";
    }

    if(empty($errors)){
        try{
            $userModel = new User($pdo);

            $usuario = $userModel->findByEmail($email);
            
            if($usuario && password_verify($senha, $usuario['senha_hash'])){
                if($usuario['ativo'] == 1){
                    // Success Login
                    Session::setUser($usuario);

                    // Update last login
                    $userModel->updateLastLogin($usuario['id']);
                    
                    // Register success login
                    Security::logAccess($pdo, $usuario['id'], 'login', true);

                    header('Location: ../../public/dashboard.php');
                    exit();
                } else{
                    $errors[] = "Conta desativada";
                } 
                
            }else{
                $errors[] = "Usuário ou senha incorretos";

                // Register failed attempt to enter the account
                if($usuario) {
                    Security::logAccess($pdo, $usuario['id'], 'login_failed', false);
                }
            }
        }catch(PDOException $e){
            error_log("Erro no login: " . $e->getMessage(), 3, "../logs/errors.log");
            $errors[] = "Erro dentro do sistema, realize o login novamente mais tarde." . $e;

        }

        
    }

    if(!empty($errors)){
        Session::setFlash('error', implode('<br>', $errors));
        header('Location: ../../public/login.php');
        exit();

        // pode dar erro

    }

}

function handleReset($pdo){
    if(!Security::verifyCSRFToken($_POST['csrf_token']) ?? ''){
        Session::setFlash('error', "Token de segurança inválido");
        header('Location: ../../public/recuperar_senha.php');
        exit();
    }

    $email = filter_var($_POST['email'] ?? '', FILTER_SANITIZE_EMAIL);

    $errors = [];

    if(!Security::validateEmail($email)){
        $errors[] = "Email inválido.";
    }

    if(empty($errors)){
        try{
            $userModel = new User($pdo);
            $usuario = $userModel->findByEmail($email);

            if($usuario){
                $token = $userModel->createResetToken($usuario['id']);
                $reset_link = "http://localhost/projetoNovoLoginPhp/public/reset.php?token=" . $token;

                // Simulate email sending
                $subject = "Recuperação de Senha";
                $message = "Clique no link para redefinir sua senha: " . $reset_link . "\n\nEste link é válido por 1 hora.";
                $headers = "From: noreply@seudominio.com";

                // Simulate successful email sending
                $email_sent = true;

                if($email_sent){
                    // Store simulated email content for display
                    Session::setFlash('email_simulation', "Email simulado enviado para: " . $usuario['email'] . "\n\nAssunto: " . $subject . "\n\nMensagem:\n" . $message);
                    Session::setFlash('success', 'Link de recuperação enviado para seu email.');
                } else {
                    $errors[] = "Erro ao enviar email.";
                }
            } else {
                // Don't reveal if email exists or not for security
                Session::setFlash('success', 'Se o email estiver cadastrado, você receberá um link de recuperação.');
            }
        } catch(Exception $e){
            error_log("Reset error: " . $e->getMessage(), 3, "../logs/errors.log");
            $errors[] = "Erro dentro do sistema.";
        }
    }

    if(!empty($errors)){
        Session::setFlash('error', implode('<br>', $errors));
    }

    header('Location: ../../public/recuperar_senha.php');
    exit();
}

function handleResetPassword($pdo){
    $token = $_POST['token'] ?? '';
    $nova_senha = $_POST['nova_senha'] ?? '';
    $confirmar_senha = $_POST['confirmar_senha'] ?? '';

    $errors = [];

    if(empty($token)){
        $errors[] = "Token inválido.";
    }

    if(!Security::validatePassword($nova_senha)){
        $errors[] = "Senha deve conter pelo menos 8 caracteres.";
    }

    if($nova_senha !== $confirmar_senha){
        $errors[] = "Senhas não coincidem.";
    }

    if(empty($errors)){
        try{
            $userModel = new User($pdo);
            $token_data = $userModel->findResetToken($token);

            if($token_data){
                $nova_senha_hash = password_hash($nova_senha, PASSWORD_DEFAULT);
                if($userModel->updatePassword($token_data['user_id'], $nova_senha_hash)){
                    $userModel->useResetToken($token);
                    Session::setFlash('success', 'Senha redefinida com sucesso.');
                    header('Location: ../../public/login.php');
                    exit();
                } else {
                    $errors[] = "Erro ao atualizar senha.";
                }
            } else {
                $errors[] = "Token inválido ou expirado.";
            }
        } catch(Exception $e){
            error_log("Reset password error: " . $e->getMessage(), 3, "../logs/errors.log");
            $errors[] = "Erro dentro do sistema.";
        }
    }

    if(!empty($errors)){
        Session::setFlash('error', implode('<br>', $errors));
    }

    header('Location: ../../public/reset.php?token=' . urlencode($token));
    exit();
}

?>
