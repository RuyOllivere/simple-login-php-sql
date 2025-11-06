<?php

require_once '../src/config/config.php';

// Redirect to dashboard if logged

// if(isLoggedIn()){
//     header('Location: dashboard.php');
//     exit();
// }

?>

<!DOCTYPE html>
<html lang="pt-BR">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">

    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.8/dist/css/bootstrap.min.css" rel="stylesheet" integrity="sha384-sRIl4kxILFvY47J16cr9ZwB07vP4J8+LH7qKQnuqkuIAvNWLzeN8tE5YBujZqJLB" crossorigin="anonymous">
    <link rel="stylesheet" href="./assets/CSS/style.css">

    <title>Sistema Seguro - Login</title>
</head>
<body class="bg-light">
    <div class="container mt-5">
        <div class="row justify-content-center">
            <div class="col-md-8 col-lg-6">
                <div class="card shadow-lg animate-fade-in">
                    <div class="card-header bg-gradient-primary text-white text-center">
                        <h1 class="mb-1">Sistema Seguro</h1>
                        <p class="mb-0">Versão Produção</p>
                    </div>
                    <div class="card-body">
                        <?php
                            $success = Session::getFlash('success');
                            $error = Session::getFlash('error');
                            if($success): ?>
                            <div class="alert alert-success animate-slide-down">
                                <?php echo $success; ?>
                            </div>
                        <?php endif;?>

                        <?php if($error):?>
                            <div class="alert alert-danger animate-slide-down">
                                <?php echo $error; ?>
                            </div>
                        <?php endif;?>

                        <div class="d-flex justify-content-around mb-4">
                            <a href="cadastro.php" class="btn btn-primary btn-lg animate-bounce">Cadastrar</a>
                            <a href="login.php" class="btn btn-outline-primary btn-lg animate-bounce">Login</a>
                        </div>

                        <div class="mb-4">
                            <h3 class="text-center mb-3">Sistema em Modo de Produção</h3>
                            <ul class="list-group list-group-flush">
                                <li class="list-group-item">Senhas criptografadas</li>
                                <li class="list-group-item">Proteção CSRF em todos os formulários</li>
                                <li class="list-group-item">Sessões seguras com httpOnly</li>
                                <li class="list-group-item">Validações de entrada do servidor</li>
                                <li class="list-group-item">Logs de auditoria</li>
                            </ul>
                        </div>

                        <div class="alert alert-info animate-fade-in">
                            <p class="mb-1"><strong>Usuário de Demonstração:</strong></p>
                            <p class="mb-1">Email: exemplo@email.com</p>
                            <p class="mb-0">Senha: 123456</p>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </div>

    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.8/dist/js/bootstrap.bundle.min.js" integrity="sha384-w76AqPfDkMBDXo30jS1Sgez6pr3x5MlQ1ZAGC+nuZB+EYdgRZgiwxhTBTkF7CXvN" crossorigin="anonymous"></script>
</body>
</html>