<?php

date_default_timezone_set('America/Sao_Paulo');

require_once '../src/config/config.php';
require_once '../src/models/User.php';

// Check if temp_user is set
if(!isset($_SESSION['temp_user'])){
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
    <title>Verificar 2FA - Sistema Seguro</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.8/dist/css/bootstrap.min.css" rel="stylesheet" integrity="sha384-sRIl4kxILFvY47J16cr9ZwB07vP4J8+LH7qKQnuqkuIAvNWLzeN8tE5YBujZqJLB" crossorigin="anonymous">
    <link rel="stylesheet" href="./assets/CSS/style.css">
</head>
<body class="bg-light">
    <div class="container mt-5">
        <div class="row justify-content-center">
            <div class="col-md-6">
                <div class="card shadow-lg animate-fade-in">
                    <div class="card-header bg-gradient-primary text-white text-center">
                        <h1 class="mb-0">Verificar 2FA</h1>
                    </div>
                    <div class="card-body">
                        <?php
                        $error = Session::getFlash('error');

                        if($error): ?>
                            <div class="alert alert-danger animate-slide-down">
                                <?php echo $error; ?>
                            </div>
                        <?php endif; ?>

                        <p class="text-center">Insira o código de 6 dígitos gerado pelo seu app autenticador.</p>

                        <form action="../src/controllers/AuthController.php?action=verify_2fa" method="POST">
                            <input type="hidden" name="csrf_token" value="<?php echo $csrf_token; ?>">
                            <div class="mb-3">
                                <label for="code" class="form-label">Código 2FA:</label>
                                <input type="text" name="code" id="code" class="form-control text-center" required maxlength="6" pattern="[0-9]{6}" placeholder="000000" style="font-size: 1.5rem; letter-spacing: 0.5rem;">
                            </div>
                            <div class="d-grid">
                                <button type="submit" class="btn btn-primary animate-bounce">Verificar</button>
                            </div>
                        </form>

                        <div class="text-center mt-3">
                            <a href="login.php" class="btn btn-secondary btn-sm">Voltar ao Login</a>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </div>

    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.8/dist/js/bootstrap.bundle.min.js" integrity="sha384-w76AqPfDkMBDXo30jS1Sgez6pr3x5MlQ1ZAGC+nuZB+EYdgRZgiwxhTBTkF7CXvN" crossorigin="anonymous"></script>
</body>
</html>
