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
    <title>Login</title>
    <link rel="stylesheet" href="./assets/CSS/style.css">
</head>
<body>
    
    <div class="container">
        <div class="card">
            <h1>Login</h1>

            <?php
                $success = Session::getFlash('success');
                $error = Session::getFlash('error');

                if($success): ?>

                    <div class="alert alert-success">
                        <?php echo $success; ?>
                    </div>
                <?php endif;

                if($error): ?>
                    <div class="alert alert-error">
                        <?php echo $error; ?>
                    </div>
                <?php endif; ?>

                <form action="../src/controllers/AuthController.php?action=login" method="POST" class="form">

                    <input type="hidden" name="csrf_token" value="<?php echo $csrf_token; ?>">
            
                    <div class="form-group">
                        <label for="email">Digite seu email: </label>
                        <input type="email" name="email" id="email" required value="<?php echo $_POST['email'] ?? '';?>" placeholder="Seu email">
                    </div>
                    
                    <div class="form-group">
                        <label for="senha">Digite sua senha: </label>
                        <input type="password" name="senha" id="senha" required minlength="8" placeholder="8 caracteres" autocomplete="new-password">
                    </div>  

                    <button type="submit" class="btn btn-primary btn-block">
                        Login
                    </button>

                </form>

                <div class="demo-credentials">
                   <p><strong>Credenciais de teste:</strong></p>
                   <p>Email: examplo@email.com</p>
                   <p>Senha: 123456</p>
                </div>

                <div class="links">
                    <a href="index.php">Home</a>
                    <a href="cadastro.php">Se não possuir conta, realize seu registro</a>
                </div>

        </div>
    </div>

</body>
</html>