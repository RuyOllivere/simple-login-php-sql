<?php

date_default_timezone_set('America/Sao_Paulo');

require_once '../src/config/config.php';
require_once '../src/models/User.php';
requireLogin();

try{
    // Search user data
    $userModel = new User($pdo);
    $usuario = $userModel->findById($_SESSION['user_id']);

    if(!$usuario){
        session_destroy();
        header('Location: login.php');
        exit();
    }

    // Login history
    $loginHistory = $userModel->getLoginHistory($_SESSION['user_id'], 5);

} catch(PDOException $e){
    error_log("Erro ao iniciar a conta: " . $e->getMessage(), 3, "../logs/errors.log");
    die("Error to load the page.");
}

$csrf_token = Security::generateCSFRToken();
?>

<!DOCTYPE html>
<html lang="pt-BR">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Dashboard - Sistema Seguro</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.8/dist/css/bootstrap.min.css" rel="stylesheet" integrity="sha384-sRIl4kxILFvY47J16cr9ZwB07vP4J8+LH7qKQnuqkuIAvNWLzeN8tE5YBujZqJLB" crossorigin="anonymous">
    <link rel="stylesheet" href="./assets/CSS/style.css">
</head>
<body class="bg-light">
    <div class="container mt-5">
        <div class="row justify-content-center">
            <div class="col-lg-10">
                <div class="card shadow-lg animate-fade-in">
                    <div class="card-header bg-gradient-primary text-white d-flex justify-content-between align-items-center">
                        <h1 class="mb-0">Welcome, <?php echo htmlspecialchars($usuario['nome'], ENT_QUOTES, 'UTF-8'); ?>!</h1>
                        <a href="logout.php" class="btn btn-outline-light animate-bounce">Logout</a>
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

                        <div class="row">
                            <div class="col-md-6 mb-4">
                                <div class="card h-100">
                                    <div class="card-header">
                                        <h5 class="mb-0">Perfil</h5>
                                    </div>
                                    <div class="card-body text-center">
                                        <?php if($usuario['profile_picture']): ?>
                                            <img src="<?php echo htmlspecialchars($usuario['profile_picture']); ?>" alt="Foto de Perfil" class="rounded-circle mb-3" style="width: 100px; height: 100px; object-fit: cover;">
                                        <?php else: ?>
                                            <div class="bg-secondary rounded-circle d-inline-flex align-items-center justify-content-center mb-3" style="width: 100px; height: 100px;">
                                                <span class="text-white fs-1"><?php echo strtoupper(substr($usuario['nome'], 0, 1)); ?></span>
                                            </div>
                                        <?php endif; ?>
                                        <h6><?php echo htmlspecialchars($usuario['nome']);?></h6>
                                        <p class="text-muted"><?php echo htmlspecialchars($usuario['email']);?></p>
                                        <form action="../src/controllers/AuthController.php?action=upload_profile_picture" method="POST" enctype="multipart/form-data" class="mt-3">
                                            <input type="hidden" name="csrf_token" value="<?php echo $csrf_token; ?>">
                                            <div class="mb-3">
                                                <input type="file" name="profile_picture" id="profile_picture" class="form-control" accept="image/*" required>
                                            </div>
                                            <button type="submit" class="btn btn-primary btn-sm">Alterar Foto</button>
                                        </form>
                                    </div>
                                </div>
                            </div>

                            <div class="col-md-6 mb-4">
                                <div class="card h-100">
                                    <div class="card-header">
                                        <h5 class="mb-0">Informações da Conta</h5>
                                    </div>
                                    <div class="card-body">
                                        <p><strong>ID:</strong> <?php echo $usuario['id'];?></p>
                                        <p><strong>DATA CADASTRO:</strong> <?php echo date('d/m/Y H:i', strtotime($usuario['data_cadastro']));?></p>
                                        <p><strong>ÚLTIMO LOGIN:</strong> <?php echo $usuario['ultimo_login'] ? date('d/m/Y H:i', strtotime($usuario['ultimo_login'])) : 'Primeiro login';?></p>
                                    </div>
                                </div>
                            </div>
                        </div>

                        <div class="row">
                            <div class="col-md-6 mb-4">
                                <div class="card h-100">
                                    <div class="card-header">
                                        <h5 class="mb-0">Segurança</h5>
                                    </div>
                                    <div class="card-body">
                                        <p>☑️ Sessão segura</p>
                                        <p>☑️ Autenticação validada</p>
                                        <p>☑️ Conexão criptografada</p>
                                        <p>Sessão iniciada: <?php echo date('H:i:s');?></p>
                                    </div>
                                </div>
                            </div>
                        </div>

                        <div class="row">
                            <div class="col-md-6 mb-4">
                                <div class="card h-100">
                                    <div class="card-header">
                                        <h5 class="mb-0">Atualizar Perfil</h5>
                                    </div>
                                    <div class="card-body">
                                        <form action="../src/controllers/AuthController.php?action=update_profile" method="POST">
                                            <input type="hidden" name="csrf_token" value="<?php echo $csrf_token; ?>">
                                            <div class="mb-3">
                                                <label for="nome" class="form-label">Nome completo:</label>
                                                <input type="text" name="nome" id="nome" class="form-control" required value="<?php echo htmlspecialchars($usuario['nome']); ?>" minlength="2" maxlength="100">
                                            </div>
                                            <div class="d-grid">
                                                <button type="submit" class="btn btn-secondary animate-bounce">Atualizar</button>
                                            </div>
                                        </form>
                                    </div>
                                </div>
                            </div>

                            <?php if(!empty($loginHistory)): ?>
                            <div class="col-md-6 mb-4">
                                <div class="card h-100">
                                    <div class="card-header">
                                        <h5 class="mb-0">Histórico de Login</h5>
                                    </div>
                                    <div class="card-body">
                                        <div class="list-group">
                                            <?php foreach ($loginHistory as $log): ?>
                                                <div class="list-group-item d-flex justify-content-between align-items-center <?php echo $log['sucesso'] ? 'list-group-item-success' : 'list-group-item-danger'; ?>">
                                                    <div>
                                                        <strong><?php echo $log['acao']; ?></strong><br>
                                                        <small><?php echo date('d/M/Y H:i', strtotime($log['data_acesso'])); ?> - <?php echo $log['ip_address']; ?></small>
                                                    </div>
                                                    <span><?php echo $log['sucesso'] ? '☑️' : 'X'; ?></span>
                                                </div>
                                            <?php endforeach; ?>
                                        </div>
                                    </div>
                                </div>
                            </div>
                            <?php endif; ?>
                        </div>

                        <div class="text-center mt-4">
                            <a href="index.php" class="btn btn-secondary me-2 animate-bounce">Página Inicial</a>
                            <a href="logout.php" class="btn btn-danger animate-bounce">Logout</a>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </div>

    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.8/dist/js/bootstrap.bundle.min.js" integrity="sha384-w76AqPfDkMBDXo30jS1Sgez6pr3x5MlQ1ZAGC+nuZB+EYdgRZgiwxhTBTkF7CXvN" crossorigin="anonymous"></script>
</body>
</html>