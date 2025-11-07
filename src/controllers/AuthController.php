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
    } elseif($action === 'update_profile'){
        handleUpdateProfile($pdo);
    } elseif($action === 'upload_profile_picture'){
        handleUploadProfilePicture($pdo);
    } elseif($action === 'withdraw'){
        handleWithdraw($pdo);
    } elseif($action === 'update_coins'){
        handleUpdateCoins($pdo);
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
                $reset_link = "http://localhost/simple-login-php-sql/public/reset.php?token=" . $token;

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

function handleUpdateProfile($pdo){
    if(!Security::verifyCSRFToken($_POST['csrf_token']) ?? ''){
        Session::setFlash('error', "Token de segurança inválido");
        header('Location: ../../public/dashboard.php');
        exit();
    }

    $nome = Security::sanitizeInput($_POST['nome'] ?? '');

    $errors = [];

    if(!Security::validateName($nome)){
        $errors[] = "Nome deve ter entre 2 e 100 caracteres.";
    }

    if(empty($errors)){
        try{
            $userModel = new User($pdo);
            if($userModel->updateProfile($_SESSION['user_id'], $nome)){
                Session::setFlash('success', 'Perfil atualizado com sucesso.');
            } else {
                $errors[] = "Erro ao atualizar perfil.";
            }
        } catch(Exception $e){
            error_log("Update profile error: " . $e->getMessage(), 3, "../logs/errors.log");
            $errors[] = "Erro dentro do sistema.";
        }
    }

    if(!empty($errors)){
        Session::setFlash('error', implode('<br>', $errors));
    }

    header('Location: ../../public/dashboard.php');
    exit();
}

function handleUploadProfilePicture($pdo){
    if(!Security::verifyCSRFToken($_POST['csrf_token']) ?? ''){
        Session::setFlash('error', "Token de segurança inválido");
        header('Location: ../../public/dashboard.php');
        exit();
    }

    $errors = [];

    if(!isset($_FILES['profile_picture']) || $_FILES['profile_picture']['error'] !== UPLOAD_ERR_OK){
        $errors[] = "Erro no upload da imagem.";
    } else {
        $file = $_FILES['profile_picture'];
        $allowed_types = ['image/jpeg', 'image/png', 'image/gif'];
        $max_size = 2 * 1024 * 1024; // 2MB

        if(!in_array($file['type'], $allowed_types)){
            $errors[] = "Tipo de arquivo não permitido. Use apenas JPG, PNG ou GIF.";
        }

        if($file['size'] > $max_size){
            $errors[] = "Arquivo muito grande. Máximo 2MB.";
        }

        if(empty($errors)){
            $upload_dir = '../../public/uploads/profile_pictures/';
            if(!is_dir($upload_dir)){
                mkdir($upload_dir, 0755, true);
            }

            $file_extension = pathinfo($file['name'], PATHINFO_EXTENSION);
            $new_filename = 'profile_' . $_SESSION['user_id'] . '_' . time() . '.' . $file_extension;
            $file_path = $upload_dir . $new_filename;

            if(move_uploaded_file($file['tmp_name'], $file_path)){
                try{
                    $userModel = new User($pdo);
                    $relative_path = 'uploads/profile_pictures/' . $new_filename;
                    if($userModel->updateProfilePicture($_SESSION['user_id'], $relative_path)){
                        Session::setFlash('success', 'Foto de perfil atualizada com sucesso.');
                    } else {
                        $errors[] = "Erro ao salvar caminho da imagem.";
                    }
                } catch(Exception $e){
                    error_log("Upload profile picture error: " . $e->getMessage(), 3, "../logs/errors.log");
                    $errors[] = "Erro dentro do sistema.";
                }
            } else {
                $errors[] = "Erro ao mover arquivo.";
            }
        }
    }

    if(!empty($errors)){
        Session::setFlash('error', implode('<br>', $errors));
    }

    header('Location: ../../public/dashboard.php');
    exit();
}

function handleWithdraw($pdo){
    if(!Security::verifyCSRFToken($_POST['csrf_token']) ?? ''){
        Session::setFlash('error', "Token de segurança inválido");
        header('Location: ../../public/withdraw.php');
        exit();
    }

    $withdraw_amount = (int)($_POST['withdraw_amount'] ?? 0);
    $card_number = Security::sanitizeInput($_POST['card_number'] ?? '');
    $expiry_date = Security::sanitizeInput($_POST['expiry_date'] ?? '');
    $cvv = Security::sanitizeInput($_POST['cvv'] ?? '');
    $cardholder_name = Security::sanitizeInput($_POST['cardholder_name'] ?? '');

    $errors = [];

    if($withdraw_amount < 10 || $withdraw_amount > 1000){
        $errors[] = "Valor de saque deve ser entre 10 e 1000 moedas.";
    }

    // Basic card validation
    if(empty($card_number) || !preg_match('/^\d{4}\s\d{4}\s\d{4}\s\d{4}$/', $card_number)){
        $errors[] = "Número do cartão inválido.";
    }

    if(empty($expiry_date) || !preg_match('/^\d{2}\/\d{2}$/', $expiry_date)){
        $errors[] = "Data de expiração inválida.";
    }

    if(empty($cvv) || !preg_match('/^\d{3,4}$/', $cvv)){
        $errors[] = "CVV inválido.";
    }

    if(empty($cardholder_name) || strlen($cardholder_name) < 2){
        $errors[] = "Nome no cartão é obrigatório.";
    }

    if(empty($errors)){
        try{
            // Save card information (in a real app, this would be encrypted)
            $stmt = $pdo->prepare("INSERT INTO credit_cards (user_id, card_number, expiry_date, cvv, cardholder_name) VALUES (?, ?, ?, ?, ?)");
            $stmt->execute([$_SESSION['user_id'], $card_number, $expiry_date, $cvv, $cardholder_name]);

            // Simulate withdrawal processing
            Session::setFlash('success', "Saque de {$withdraw_amount} moedas solicitado com sucesso! O valor será depositado em sua conta em até 3 dias úteis.");
        } catch(Exception $e){
            error_log("Withdraw error: " . $e->getMessage(), 3, "../logs/errors.log");
            $errors[] = "Erro ao processar saque.";
        }
    }

    if(!empty($errors)){
        Session::setFlash('error', implode('<br>', $errors));
    }

    header('Location: ../../public/withdraw.php');
    exit();
}

function handleUpdateCoins($pdo){
    if(!Security::verifyCSRFToken($_POST['csrf_token']) ?? ''){
        Session::setFlash('error', "Token de segurança inválido");
        header('Location: ../../public/casinoPlane.php');
        exit();
    }

    $new_balance = (int)($_POST['balance'] ?? 0);

    $errors = [];

    if($new_balance < 0){
        $errors[] = "Saldo não pode ser negativo.";
    }

    if(empty($errors)){
        try{
            $userModel = new User($pdo);
            if($userModel->updateCoins($_SESSION['user_id'], $new_balance)){
                // Success - balance updated
                echo json_encode(['success' => true]);
                exit();
            } else {
                $errors[] = "Erro ao atualizar saldo.";
            }
        } catch(Exception $e){
            error_log("Update coins error: " . $e->getMessage(), 3, "../logs/errors.log");
            $errors[] = "Erro dentro do sistema.";
        }
    }

    if(!empty($errors)){
        echo json_encode(['success' => false, 'error' => implode('<br>', $errors)]);
        exit();
    }
}

?>
