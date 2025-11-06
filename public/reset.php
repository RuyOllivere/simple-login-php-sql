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
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.8/dist/css/bootstrap.min.css" rel="stylesheet" integrity="sha384-sRIl4kxILFvY47J16cr9ZwB07vP4J8+LH7qKQnuqIAvNWLzeN8tE5YBujZqJLB" crossorigin="anonymous">
    <link rel="stylesheet" href="./assets/CSS/style.css">
</head>
<body class="bg-light">
    <div class="container mt-5">
        <div class="row justify-content-center">
            <div class="col-md-8 col-lg-6">
                <div class="card shadow-lg animate-fade-in">
                    <div class="card-header bg-gradient-primary text-white text-center">
                        <h1 class="mb-0">Redefinir Senha</h1>
                    </div>
                    <div class="card-body">
                        <?php
                            $success = Session::getFlash('success');
                            $error = Session::getFlash('error');

                            if($success): ?>
                            <div class="alert alert-success animate-slide-down">
                                <?php echo $success; ?>
                            </div>
                        <?php endif;

                        if($error): ?>
                            <div class="alert alert-danger animate-slide-down">
                                <?php echo $error; ?>
                            </div>
                        <?php endif; ?>

                        <form action="../src/controllers/AuthController.php?action=reset_password" method="POST">
                            <input type="hidden" name="csrf_token" value="<?php echo $csrf_token; ?>">
                            <input type="hidden" name="token" value="<?php echo htmlspecialchars($token); ?>">

                            <div class="mb-3">
                                <label for="nova_senha" class="form-label">Nova Senha:</label>
                                <input type="password" name="nova_senha" id="nova_senha" class="form-control" required minlength="8" placeholder="8 caracteres" autocomplete="new-password">
                            </div>

                            <div class="mb-3">
                                <label for="confirmar_senha" class="form-label">Confirmar Nova Senha:</label>
                                <input type="password" name="confirmar_senha" id="confirmar_senha" class="form-control" required minlength="8" placeholder="8 caracteres" autocomplete="new-password">
                            </div>

                            <div class="d-grid">
                                <button type="submit" class="btn btn-primary btn-lg animate-bounce">Redefinir Senha</button>
                            </div>
                        </form>

                        <div class="text-center mt-3">
                            <a href="login.php" class="btn btn-link">Voltar ao Login</a>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </div>

    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.8/dist/js/bootstrap.bundle.min.js" integrity="sha384-w76AqPfDkMBDXo30jS1Sgez6pr3x5MlQ1ZAGC+nuZB+EYdgRZgiwxhTBTkF7CXvN" crossorigin="anonymous"></script>
</body>
</html>
