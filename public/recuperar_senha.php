<?php

require_once '../src/config/config.php';

if(isLoggedIn()){
    header('Location: dashboard.php');
    exit();
}

$csrf_token = Security::generateCSFRToken();

?>

<!DOCTYPE html>
<html lang="pt-BR">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Recuperar Senha</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.8/dist/css/bootstrap.min.css" rel="stylesheet" integrity="sha384-sRIl4kxILFvY47J16cr9ZwB07vP4J8+LH7qKQnuqkuIAvNWLzeN8tE5YBujZqJLB" crossorigin="anonymous">
    <link rel="stylesheet" href="./assets/CSS/style.css">
</head>
<body class="bg-light">
    <div class="container mt-5">
        <div class="row justify-content-center">
            <div class="col-md-8 col-lg-6">
                <div class="card shadow-lg animate-fade-in">
                    <div class="card-header bg-gradient-primary text-white text-center">
                        <h1 class="mb-0">Recuperar Senha</h1>
                    </div>
                    <div class="card-body">
                        <?php
                            $success = Session::getFlash('success');
                            $error = Session::getFlash('error');
                            $email_simulation = Session::getFlash('email_simulation');

                            if($success): ?>
                            <div class="alert alert-success animate-slide-down">
                                <?php echo $success; ?>
                            </div>
                        <?php endif;

                        if($error): ?>
                            <div class="alert alert-danger animate-slide-down">
                                <?php echo $error; ?>
                            </div>
                        <?php endif;

                        if($email_simulation): ?>
                            <div class="alert alert-info animate-slide-down">
                                <strong>Email Simulado:</strong><br>
                                <pre><?php echo htmlspecialchars($email_simulation); ?></pre>
                            </div>
                        <?php endif; ?>

                        <form action="../src/controllers/AuthController.php?action=reset" method="POST">
                            <input type="hidden" name="csrf_token" value="<?php echo $csrf_token; ?>">

                            <div class="mb-3">
                                <label for="email" class="form-label">Digite seu email:</label>
                                <input type="email" name="email" id="email" class="form-control" required value="<?php echo $_POST['email'] ?? '';?>" placeholder="Seu email">
                            </div>

                            <div class="d-grid">
                                <button type="submit" class="btn btn-primary btn-lg animate-bounce">Enviar Link de Recuperação</button>
                            </div>
                        </form>

                        <div class="text-center mt-3">
                            <a href="login.php" class="btn btn-link">Voltar ao Login</a>
                            <a href="cadastro.php" class="btn btn-link">Se não possuir conta, realize seu registro</a>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </div>

    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.8/dist/js/bootstrap.bundle.min.js" integrity="sha384-w76AqPfDkMBDXo30jS1Sgez6pr3x5MlQ1ZAGC+nuZB+EYdgRZgiwxhTBTkF7CXvN" crossorigin="anonymous"></script>
</body>
</html>
