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
    <title>Document</title>
    <style rel="stylesheet" href='./assets/CSS/style.css'></style>
</head>
<body>
    <div class="container">
        <div class="card">
            <div class="header">
                <h1>Sistema seguro</h1>
                <p>Versão produção</p>
            </div>
            <?php
                $success = Session::getFlash('success');
                $error = Session::getFlash('error');
                if($success): ?>
                <div class="alert alert-sucess">
                    <?php echo $success?>
                </div>
            <?php endif;?>

            <?php if($error):?>
                <div class="alert alert-sucess">
                    <?php echo $success?>
                </div>
            <?php endif;?>

             <div class="actions">
                <a href="cadastro.php" class="btn btn-primary">Cadastrar</a>
                <a href="login.php" class="btn btn-primary">Login</a>
             </div>
             <div class="security-info">
                <h3>Sistema de modo de produção</h3>
                <ul>
                    <li>Senhas criptografadas</li>
                    <li>Proteção CSRF em todos os formulários</li>
                    <li>Sessões seguras com httpOnly</li>
                    <li>Validações de entrada do servidor</li>
                    <li>Logs de auditoria</li>
                </ul>
             </div>
             
             <div class="demo-info">
                <p><strong>Usuário de demonstração:</strong></p>
                <p>Email: examplo@email.com</p>
                <p>Senha: 123456</p>
             </div>

        </div>
    </div>
</body>
</html>