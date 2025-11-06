<?php

require_once '../src/config/config.php';
require_once '../src/models/User.php';

$token = $_GET['token'] ?? '';

if(empty($token)){
    Session::setFlash('error', 'Token inválido.');
    header('Location: login.php');
    exit();
}

$userModel = new User($pdo);
$token_data = $userModel->findResetToken($token);

if(!$token_data){
    Session::setFlash('error', 'Token inválido ou expirado.');
    header('Location: login.php');
    exit();
}

$csrf_token = Security::generateCSFRToken();

?>

<!DOCTYPE html>
<html lang="pt-BR">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Redefinir Senha</title>

    <!-- Bootstrap CSS -->
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.8/dist/css/bootstrap.min.css" rel="stylesheet">

    <!-- Estilo opcional -->
    <style>
        body {
            background: linear-gradient(135deg, #007bff 0%, #00b4d8 100%);
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
        }

        .card {
            border: none;
            border-radius: 15px;
            overflow: hidden;
            box-shadow: 0 10px 25px rgba(0,0,0,0.15);
        }

        .card-header {
            background: linear-gradient(90deg, #007bff, #00b4d8);
            color: white;
            font-weight: 600;
            letter-spacing: 0.5px;
        }

        .btn-primary {
            background: linear-gradient(90deg, #007bff, #00b4d8);
            border: none;
        }

        .btn-primary:hover {
            background: linear-gradient(90deg, #0069d9, #0096c7);
        }

        .alert {
            border-radius: 8px;
        }

        label {
            font-weight: 500;
        }
    </style>
</head>
<body>

    <div class="container">
        <div class="row justify-content-center">
            <div class="col-md-8 col-lg-5">
                <div class="card">
                    <div class="card-header text-center py-4">
                        <h2 class="mb-0">Redefinir Senha</h2>
                    </div>
                    <div class="card-body p-4">

                        <?php
                            $success = Session::getFlash('success');
                            $error = Session::getFlash('error');

                            if($success): ?>
                                <div class="alert alert-success text-center mb-3">
                                    <?php echo $success; ?>
                                </div>
                            <?php endif;

                            if($error): ?>
                                <div class="alert alert-danger text-center mb-3">
                                    <?php echo $error; ?>
                                </div>
                            <?php endif;
                        ?>

                        <form action="../src/controllers/AuthController.php?action=reset_password" method="POST">
                            <input type="hidden" name="csrf_token" value="<?php echo $csrf_token; ?>">
                            <input type="hidden" name="token" value="<?php echo htmlspecialchars($token); ?>">

                            <div class="mb-3">
                                <label for="nova_senha" class="form-label">Nova Senha</label>
                                <input type="password" name="nova_senha" id="nova_senha" class="form-control" required minlength="8" placeholder="Digite uma nova senha" autocomplete="new-password">
                            </div>

                            <div class="mb-3">
                                <label for="confirmar_senha" class="form-label">Confirmar Senha</label>
                                <input type="password" name="confirmar_senha" id="confirmar_senha" class="form-control" required minlength="8" placeholder="Confirme a nova senha" autocomplete="new-password">
                            </div>

                            <div class="d-grid mt-4">
                                <button type="submit" class="btn btn-primary btn-lg">
                                     Redefinir Senha
                                </button>
                            </div>
                        </form>

                        <div class="text-center mt-4">
                            <a href="login.php" class="text-decoration-none text-secondary">Voltar ao Login</a>
                        </div>

                    </div>
                </div>
            </div>
