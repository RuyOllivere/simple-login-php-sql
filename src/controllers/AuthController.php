<?php
require_once '../config/config.php';
require_once '../models/User.php';

if($_SERVER['REQUEST_METHOD'] === 'POST'){
    $action = $_GET['action'] ?? '';

    if($action === 'register'){
        handleRegister($pdo);
    } elseif($action === 'login'){
        handleLogin($pdo);
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
            error_log("Register error: " . $e->getMessage());
            $errors[] = "Erro dentro do sistema, realize o cadastro novamente mais tarde.";
        }

        

    }
}

function handleLogin($pdo){

}

?>