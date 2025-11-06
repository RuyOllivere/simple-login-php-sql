<?php


require_once '../src/config/config.php';

if (isLoggedIn()){
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
    <title>Cadastro</title>
    <link rel='stylesheet' href='./assets/CSS/style.css'>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.8/dist/css/bootstrap.min.css" rel="stylesheet" integrity="sha384-sRIl4kxILFvY47J16cr9ZwB07vP4J8+LH7qKQnuqkuIAvNWLzeN8tE5YBujZqJLB" crossorigin="anonymous">


</head>
<body>
    <div class="container">
        <div class="card">
            <h1>Cadastro</h1>
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
                    <?php echo $error?>
                </div>
            <?php endif?>

            <form action="../src/controllers/AuthController.php?action=register" method="POST" class="form">
                <input type="hidden" name="csrf_token" value="<?php echo $csrf_token; ?>">

                <div class="form-group">
                    <label for="nome">Nome completo: </label>
                    <input type="text" name="nome" id="nome" required value="<?php echo $_POST['nome'] ?? '';?>" minlength="2" maxlength="100" placeholder="Seu nome completo">
                </div>

                <div class="form-group">
                    <label for="email">Digite seu email: </label>
                    <input type="email" name="email" id="email" required value="<?php echo $_POST['email'] ?? '';?>" placeholder="Seu email">
                </div>

                <div class="form-group">
                    <label for="senha">Digite sua senha: </label>
                    <input type="password" name="senha" id="senha" required minlength="8" placeholder="8 caracteres" autocomplete="new-password">
                </div>  
    
                <div class="form-group">
                    <label for="confirmar_senha">Confirmar senha: </label>
                    <input type="password" name="confirmar_senha" id="confirmar_senha" required minlength="8" placeholder="8 caracteres" autocomplete="new-password">
                </div>

                <button type="submit" class="btn btn-primary btn-block">
                    Cadastrar
                </button>

            </form>

            <div class="links">
                <a href="index.php">Home</a>
                <a href="login.php">Se já tiver conta, realize seu login</a>
            </div>
                
        </div>
    </div>
</body>
</html>