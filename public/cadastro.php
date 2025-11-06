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
            <div class="card-body">
                <h1 class="card-title">Cadastro</h1>
            <?php
            $success = Session::getFlash('success');
            $error = Session::getFlash('error');

            if($success): ?>
                <div class="alert alert-success">
                    <?php echo $success; ?>
                </div>
            <?php endif;

            if($error): ?>
                <div class="alert alert-danger">
                    <?php echo $error?>
                </div>
            <?php endif?>

            <form action="../src/controllers/AuthController.php?action=register" method="POST" class="form">
                <input type="hidden" name="csrf_token" value="<?php echo $csrf_token; ?>">

                <div class="form-group mb-3">
                    <label for="nome" class="form-label">Nome completo: </label>
                    <input type="text" name="nome" id="nome" class="form-control" required value="<?php echo $_POST['nome'] ?? '';?>" minlength="2" maxlength="100" placeholder="Seu nome completo">
                </div>

                <div class="form-group mb-3">
                    <label for="email" class="form-label">Digite seu email: </label>
                    <input type="email" name="email" id="email" class="form-control" required value="<?php echo $_POST['email'] ?? '';?>" placeholder="Seu email">
                </div>

                <div class="form-group mb-3">
                    <label for="senha" class="form-label">Digite sua senha: </label>
                    <input type="password" name="senha" id="senha" class="form-control" required minlength="8" placeholder="8 caracteres" autocomplete="new-password">
                </div>

                <div class="form-group mb-3">
                    <label for="confirmar_senha" class="form-label">Confirmar senha: </label>
                    <input type="password" name="confirmar_senha" id="confirmar_senha" class="form-control" required minlength="8" placeholder="8 caracteres" autocomplete="new-password">
                </div>

                <button type="submit" class="btn btn-primary w-100">
                    Cadastrar
                </button>

            </form>

            <div class="links mt-3 text-center">
                <a href="index.php" class="d-block">Home</a>
                <a href="login.php" class="d-block">Se já tiver conta, realize seu login</a>
            </div>
            </div>
        </div>
    </div>
</body>
</html>